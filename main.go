package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

// Structure pour les templates d'email
type EmailTemplate struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Subject   string   `json:"subject"`
	HTML      string   `json:"html"`
	Params    []string `json:"params"`
	FromEmail string   `json:"from_email,omitempty"`
}

// Structure pour l'API Resend
type ResendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
}

// Structure pour la session admin
type AdminSession struct {
	Token   string
	Expires time.Time
}

// Gestionnaire des templates
type TemplateManager struct {
	templates map[string]EmailTemplate
	mutex     sync.RWMutex
}

func NewTemplateManager() *TemplateManager {
	tm := &TemplateManager{
		templates: make(map[string]EmailTemplate),
	}
	
	// Template par défaut pour welcome
	tm.templates["welcome"] = EmailTemplate{
		ID:      "welcome",
		Name:    "Welcome Email",
		Subject: "Bienvenue {{.first_name}}!",
		HTML:    `<h1>Bienvenue {{.first_name}}!</h1><p>Nous sommes ravis de vous avoir parmi nous.</p>`,
		Params:  []string{"first_name"},
	}
	
	return tm
}

func (tm *TemplateManager) GetTemplate(id string) (EmailTemplate, bool) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	tpl, exists := tm.templates[id]
	return tpl, exists
}

func (tm *TemplateManager) AddTemplate(template EmailTemplate) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.templates[template.ID] = template
}

func (tm *TemplateManager) GetAllTemplates() []EmailTemplate {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	
	var templates []EmailTemplate
	for _, tpl := range tm.templates {
		templates = append(templates, tpl)
	}
	return templates
}

func (tm *TemplateManager) DeleteTemplate(id string) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	delete(tm.templates, id)
}

// Variables globales
var (
	templateManager *TemplateManager
	resendAPIKey    string
	fromEmail       string
	adminPassword   string
	apiKey          string
	adminSessions   map[string]AdminSession
	sessionMutex    sync.RWMutex
)

// Générer une clé API aléatoirement
func generateAPIKey() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		log.Printf("Erreur génération API key: %v", err)
		return "fallback-api-key"
	}
	return hex.EncodeToString(bytes)
}

// Middleware pour vérifier l'API key
func apiKeyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providedKey := r.Header.Get("X-API-Key")
		if providedKey != apiKey {
			http.Error(w, "API key invalide", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// Middleware pour vérifier la session admin
func adminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("admin_session")
		if err != nil {
			http.Error(w, "Non autorisé", http.StatusUnauthorized)
			return
		}

		sessionMutex.RLock()
		session, exists := adminSessions[cookie.Value]
		sessionMutex.RUnlock()

		if !exists || time.Now().After(session.Expires) {
			// Nettoyer la session expirée
			if exists {
				sessionMutex.Lock()
				delete(adminSessions, cookie.Value)
				sessionMutex.Unlock()
			}
			http.Error(w, "Session expirée", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// Fonction pour envoyer un email via Resend
func sendEmailViaResend(to, subject, html, from string) error {
	reqBody := ResendRequest{
		From:    from,
		To:      []string{to},
		Subject: subject,
		HTML:    html,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("erreur marshalling JSON: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("erreur création requête: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+resendAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("erreur requête HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("erreur Resend: code %d", resp.StatusCode)
	}

	return nil
}

// Handler pour envoyer un email
func sendEmailHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateID := vars["template"]

	// Décoder le body JSON en map générique
	var requestBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}

	// Extraire l'email destinataire
	to, ok := requestBody["to"].(string)
	if !ok {
		http.Error(w, "Champ 'to' requis", http.StatusBadRequest)
		return
	}

	// Validation de l'email
	if to == "" {
		http.Error(w, "Email destinataire vide", http.StatusBadRequest)
		return
	}

	// Supprimer 'to' des paramètres
	delete(requestBody, "to")

	// Les autres champs deviennent les paramètres du template
	params := requestBody

	// Récupérer le template
	emailTemplate, exists := templateManager.GetTemplate(templateID)
	if !exists {
		http.Error(w, "Template non trouvé", http.StatusNotFound)
		return
	}

	// Traiter le subject
	subjectTmpl, err := template.New("subject").Parse(emailTemplate.Subject)
	if err != nil {
		log.Printf("Erreur parsing template subject: %v", err)
		http.Error(w, "Erreur template subject", http.StatusInternalServerError)
		return
	}

	var subjectBuf bytes.Buffer
	if err := subjectTmpl.Execute(&subjectBuf, params); err != nil {
		log.Printf("Erreur exécution template subject: %v", err)
		http.Error(w, "Erreur exécution template subject", http.StatusInternalServerError)
		return
	}

	// Traiter le HTML
	htmlTmpl, err := template.New("html").Parse(emailTemplate.HTML)
	if err != nil {
		log.Printf("Erreur parsing template HTML: %v", err)
		http.Error(w, "Erreur template HTML", http.StatusInternalServerError)
		return
	}

	var htmlBuf bytes.Buffer
	if err := htmlTmpl.Execute(&htmlBuf, params); err != nil {
		log.Printf("Erreur exécution template HTML: %v", err)
		http.Error(w, "Erreur exécution template HTML", http.StatusInternalServerError)
		return
	}

	// Déterminer l'email d'envoi
	emailFrom := emailTemplate.FromEmail
	if emailFrom == "" {
		emailFrom = fromEmail // Fallback sur l'email par défaut
	}
	
	if err := sendEmailViaResend(to, subjectBuf.String(), htmlBuf.String(), emailFrom); err != nil {
		log.Printf("Erreur envoi email: %v", err)
		http.Error(w, "Erreur envoi email", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// Handler pour la page de login admin
func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root {
            --background: 222.2 84% 4.9%;
            --foreground: 210 40% 98%;
            --card: 222.2 84% 4.9%;
            --card-foreground: 210 40% 98%;
            --popover: 222.2 84% 4.9%;
            --popover-foreground: 210 40% 98%;
            --primary: 210 40% 98%;
            --primary-foreground: 222.2 84% 4.9%;
            --secondary: 217.2 32.6% 17.5%;
            --secondary-foreground: 210 40% 98%;
            --muted: 217.2 32.6% 17.5%;
            --muted-foreground: 215 20.2% 65.1%;
            --accent: 217.2 32.6% 17.5%;
            --accent-foreground: 210 40% 98%;
            --destructive: 0 62.8% 30.6%;
            --destructive-foreground: 210 40% 98%;
            --border: 217.2 32.6% 17.5%;
            --input: 217.2 32.6% 17.5%;
            --ring: 212.7 26.8% 83.9%;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: hsl(var(--background));
            color: hsl(var(--foreground));
            line-height: 1.5;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .login-container {
            width: 100%;
            max-width: 400px;
            padding: 2rem;
            background: hsl(var(--card));
            border: 1px solid hsl(var(--border));
            border-radius: 0.75rem;
            box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -2px rgb(0 0 0 / 0.05);
        }

        .logo {
            text-align: center;
            margin-bottom: 2rem;
        }

        .logo h1 {
            font-size: 1.875rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .logo p {
            color: hsl(var(--muted-foreground));
            font-size: 0.875rem;
        }

        .form-group {
            margin-bottom: 1rem;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
            font-weight: 500;
        }

        input {
            width: 100%;
            padding: 0.75rem;
            background: hsl(var(--input));
            border: 1px solid hsl(var(--border));
            border-radius: 0.375rem;
            color: hsl(var(--foreground));
            font-size: 0.875rem;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        input:focus {
            outline: none;
            border-color: hsl(var(--ring));
            box-shadow: 0 0 0 2px hsl(var(--ring) / 0.2);
        }

        button {
            width: 100%;
            padding: 0.75rem;
            background: hsl(var(--primary));
            color: hsl(var(--primary-foreground));
            border: none;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        button:hover {
            background: hsl(var(--primary) / 0.9);
        }

        button:disabled {
            background: hsl(var(--muted));
            color: hsl(var(--muted-foreground));
            cursor: not-allowed;
        }

        .error {
            color: hsl(var(--destructive));
            font-size: 0.875rem;
            margin-top: 0.5rem;
            text-align: center;
        }

        .spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid hsl(var(--primary-foreground) / 0.3);
            border-radius: 50%;
            border-top-color: hsl(var(--primary-foreground));
            animation: spin 0.8s ease-in-out infinite;
            margin-right: 0.5rem;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .hidden {
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>Email Manager</h1>
            <p>Connectez-vous à votre tableau de bord</p>
        </div>
        
        <form onsubmit="login(event)">
            <div class="form-group">
                <label for="password">Mot de passe</label>
                <input type="password" id="password" placeholder="Entrez votre mot de passe" required>
            </div>
            
            <button type="submit" id="loginBtn">
                <span id="loginSpinner" class="spinner hidden"></span>
                <span id="loginText">Se connecter</span>
            </button>
            
            <div id="error" class="error"></div>
        </form>
    </div>

    <script>
        async function login(event) {
            event.preventDefault();
            const password = document.getElementById('password').value;
            const loginBtn = document.getElementById('loginBtn');
            const loginText = document.getElementById('loginText');
            const loginSpinner = document.getElementById('loginSpinner');
            const errorDiv = document.getElementById('error');
            
            // Reset error
            errorDiv.textContent = '';
            
            // Show loading state
            loginBtn.disabled = true;
            loginSpinner.classList.remove('hidden');
            loginText.textContent = 'Connexion...';
            
            try {
                const response = await fetch('/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: password })
                });
                
                if (response.ok) {
                    loginText.textContent = 'Succès !';
                    window.location.href = '/admin';
                } else {
                    throw new Error('Mot de passe incorrect');
                }
            } catch (error) {
                errorDiv.textContent = error.message || 'Erreur de connexion';
            } finally {
                // Hide loading state
                loginBtn.disabled = false;
                loginSpinner.classList.add('hidden');
                loginText.textContent = 'Se connecter';
            }
        }
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Handler pour traiter le login admin
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginReq struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}

	if loginReq.Password != adminPassword {
		http.Error(w, "Mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	// Créer une session
	sessionToken := generateAPIKey()
	expires := time.Now().Add(24 * time.Hour)

	sessionMutex.Lock()
	adminSessions[sessionToken] = AdminSession{
		Token:   sessionToken,
		Expires: expires,
	}
	sessionMutex.Unlock()

	// Définir le cookie
	cookie := &http.Cookie{
		Name:     "admin_session",
		Value:    sessionToken,
		Expires:  expires,
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// Handler pour la déconnexion admin
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("admin_session")
	if err == nil {
		sessionMutex.Lock()
		delete(adminSessions, cookie.Value)
		sessionMutex.Unlock()
	}

	// Supprimer le cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// Handler pour l'interface web admin (sécurisée)
func adminHandler(w http.ResponseWriter, r *http.Request) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Email Template Manager</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 40px; 
            background-color: #f5f5f5;
        }
        .container { 
            max-width: 1000px; 
            margin: 0 auto; 
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 30px; 
            border-bottom: 2px solid #eee;
            padding-bottom: 20px;
        }
        .template { 
            border: 1px solid #ddd; 
            padding: 20px; 
            margin: 10px 0; 
            border-radius: 5px; 
            background: #fafafa;
        }
        input, textarea, select { 
            width: 100%; 
            padding: 8px; 
            margin: 5px 0; 
            box-sizing: border-box; 
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button { 
            padding: 10px 15px; 
            margin: 5px; 
            cursor: pointer; 
            border: none;
            border-radius: 4px;
            font-weight: 500;
        }
        .btn-primary { background: #007bff; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        .form-group { 
            margin: 15px 0; 
            padding: 20px;
            border: 1px solid #eee;
            border-radius: 5px;
            background: #f9f9f9;
        }
        pre { 
            background: #f8f9fa; 
            padding: 10px; 
            border-radius: 3px; 
            overflow-x: auto; 
            border: 1px solid #e9ecef;
        }
        .api-key-section { 
            background: #e9ecef; 
            padding: 15px; 
            border-radius: 5px; 
            margin: 20px 0; 
        }
        .api-key { 
            font-family: monospace; 
            background: white; 
            padding: 10px; 
            border: 1px solid #ccc; 
            border-radius: 3px; 
            word-break: break-all;
        }
        .form-group h2 {
            margin-top: 0;
            color: #333;
        }
        .template h3 {
            color: #007bff;
            margin-top: 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Email Template Manager</h1>
            <button class="btn-secondary" onclick="logout()">Déconnexion</button>
        </div>

        <div class="api-key-section">
            <h3>Clé API</h3>
            <p>Utilisez cette clé API dans le header <code>X-API-Key</code> pour envoyer des emails :</p>
            <div class="api-key" id="apiKey">%s</div>
            <button class="btn-secondary" onclick="copyApiKey()">Copier</button>
        </div>
        
        <div class="form-group">
            <h2>Ajouter un nouveau template</h2>
            <input type="text" id="templateId" placeholder="ID du template (ex: welcome)">
            <input type="text" id="templateName" placeholder="Nom du template">
            <input type="text" id="templateSubject" placeholder="Sujet (ex: Bienvenue {{.first_name}}!)">
            <textarea id="templateHTML" rows="5" placeholder="HTML du template (ex: <h1>Bonjour {{.first_name}}!</h1>)"></textarea>
            <input type="text" id="templateParams" placeholder="Paramètres séparés par des virgules (ex: first_name,last_name)">
            <input type="email" id="templateFromEmail" placeholder="Email expéditeur (optionnel)">
            <button class="btn-primary" onclick="addTemplate()">Ajouter Template</button>
        </div>

        <div class="form-group">
            <h2>Tester un email</h2>
            <select id="testTemplateId">
                <option value="">Sélectionner un template</option>
            </select>
            <input type="email" id="testEmail" placeholder="Email destinataire">
            <div id="paramInputs"></div>
            <button class="btn-success" onclick="testEmail()">Envoyer Test</button>
        </div>

        <div id="templates">
            <h2>Templates existants</h2>
        </div>
    </div>

    <script>
        let currentTemplates = [];

        function loadTemplates() {
            fetch('/api/templates')
                .then(response => response.json())
                .then(templates => {
                    currentTemplates = templates;
                    const container = document.getElementById('templates');
                    const select = document.getElementById('testTemplateId');
                    
                    container.innerHTML = '<h2>Templates existants</h2>';
                    select.innerHTML = '<option value="">Sélectionner un template</option>';
                    
                    templates.forEach(template => {
                        // Ajouter à la liste
                        const div = document.createElement('div');
                        div.className = 'template';
                        
                        const exampleParams = template.params.map(param => 
                            '"' + param + '": "valeur"'
                        ).join(',\\n    ');
                        
                        div.innerHTML = `
                            <h3>${template.name} (${template.id})</h3>
                            <p><strong>Sujet:</strong> ${template.subject}</p>
                            <p><strong>Paramètres:</strong> ${template.params.join(', ')}</p>
                            ${template.from_email ? '<p><strong>Email expéditeur:</strong> ' + template.from_email + '</p>' : ''}
                            <pre>${template.html}</pre>
                            <p><strong>Exemple d'appel API:</strong></p>
                            <pre>curl -X POST https://your-app.railway.app/email/${template.id} \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -d '{
    "to": "user@example.com",
    ${exampleParams}
  }'</pre>
                            <button class="btn-danger" onclick="deleteTemplate('${template.id}')">Supprimer</button>
                        `;
                        container.appendChild(div);
                        
                        // Ajouter au select
                        const option = document.createElement('option');
                        option.value = template.id;
                        option.textContent = template.name;
                        select.appendChild(option);
                    });
                })
                .catch(error => {
                    console.error('Erreur chargement templates:', error);
                });
        }

        function updateParamInputs() {
            const templateId = document.getElementById('testTemplateId').value;
            const paramInputsDiv = document.getElementById('paramInputs');
            
            if (!templateId) {
                paramInputsDiv.innerHTML = '';
                return;
            }
            
            const template = currentTemplates.find(t => t.id === templateId);
            if (!template) return;
            
            paramInputsDiv.innerHTML = '';
            template.params.forEach(param => {
                const input = document.createElement('input');
                input.type = 'text';
                input.placeholder = param;
                input.id = 'param_' + param;
                input.setAttribute('data-param', param);
                paramInputsDiv.appendChild(input);
            });
        }

        document.getElementById('testTemplateId').addEventListener('change', updateParamInputs);

        function copyApiKey() {
            const apiKey = document.getElementById('apiKey').textContent;
            navigator.clipboard.writeText(apiKey).then(() => {
                alert('Clé API copiée !');
            });
        }

        function logout() {
            fetch('/admin/logout', { method: 'POST' })
                .then(() => {
                    window.location.href = '/admin/login';
                })
                .catch(error => {
                    console.error('Erreur logout:', error);
                    window.location.href = '/admin/login';
                });
        }

        function addTemplate() {
            const fromEmail = document.getElementById('templateFromEmail').value;
            const template = {
                id: document.getElementById('templateId').value,
                name: document.getElementById('templateName').value,
                subject: document.getElementById('templateSubject').value,
                html: document.getElementById('templateHTML').value,
                params: document.getElementById('templateParams').value.split(',').map(p => p.trim()).filter(p => p)
            };

            if (fromEmail) {
                template.from_email = fromEmail;
            }

            if (!template.id || !template.name) {
                alert('ID et nom du template sont requis');
                return;
            }

            fetch('/api/templates', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(template)
            })
            .then(response => {
                if (response.ok) {
                    alert('Template ajouté!');
                    loadTemplates();
                    // Clear form
                    document.getElementById('templateId').value = '';
                    document.getElementById('templateName').value = '';
                    document.getElementById('templateSubject').value = '';
                    document.getElementById('templateHTML').value = '';
                    document.getElementById('templateParams').value = '';
                    document.getElementById('templateFromEmail').value = '';
                } else {
                    alert('Erreur lors de l\'ajout');
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
                alert('Erreur lors de l\'ajout');
            });
        }

        function deleteTemplate(id) {
            if (confirm('Supprimer ce template?')) {
                fetch('/api/templates/' + id, { method: 'DELETE' })
                .then(response => {
                    if (response.ok) {
                        alert('Template supprimé!');
                        loadTemplates();
                    } else {
                        alert('Erreur lors de la suppression');
                    }
                })
                .catch(error => {
                    console.error('Erreur:', error);
                    alert('Erreur lors de la suppression');
                });
            }
        }

        function testEmail() {
            const templateId = document.getElementById('testTemplateId').value;
            const email = document.getElementById('testEmail').value;
            
            if (!templateId || !email) {
                alert('Veuillez sélectionner un template et saisir un email');
                return;
            }
            
            // Construire l'objet avec les paramètres
            const emailData = { to: email };
            
            // Ajouter tous les paramètres du template
            const paramInputs = document.querySelectorAll('#paramInputs input');
            paramInputs.forEach(input => {
                const paramName = input.getAttribute('data-param');
                emailData[paramName] = input.value;
            });
            
            fetch('/email/' + templateId, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-API-Key': '%s'
                },
                body: JSON.stringify(emailData)
            })
            .then(response => {
                if (response.ok) {
                    alert('Email envoyé!');
                } else {
                    alert('Erreur lors de l\'envoi');
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
                alert('Erreur lors de l\'envoi');
            });
        }

        // Charger les templates au démarrage
        loadTemplates();
    </script>
</body>
</html>`, apiKey, apiKey)