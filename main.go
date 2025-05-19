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
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Subject  string   `json:"subject"`
	HTML     string   `json:"html"`
	Params   []string `json:"params"`
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
	rand.Read(bytes)
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
			http.Error(w, "Session expirée", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// Fonction pour envoyer un email via Resend
func sendEmailViaResend(to, subject, html string) error {
	reqBody := ResendRequest{
		From:    fromEmail,
		To:      []string{to},
		Subject: subject,
		HTML:    html,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+resendAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("erreur Resend: %d", resp.StatusCode)
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
		http.Error(w, "Erreur template subject", http.StatusInternalServerError)
		return
	}

	var subjectBuf bytes.Buffer
	if err := subjectTmpl.Execute(&subjectBuf, params); err != nil {
		http.Error(w, "Erreur exécution template subject", http.StatusInternalServerError)
		return
	}

	// Traiter le HTML
	htmlTmpl, err := template.New("html").Parse(emailTemplate.HTML)
	if err != nil {
		http.Error(w, "Erreur template HTML", http.StatusInternalServerError)
		return
	}

	var htmlBuf bytes.Buffer
	if err := htmlTmpl.Execute(&htmlBuf, params); err != nil {
		http.Error(w, "Erreur exécution template HTML", http.StatusInternalServerError)
		return
	}

	// Envoyer l'email
	if err := sendEmailViaResend(to, subjectBuf.String(), htmlBuf.String()); err != nil {
		log.Printf("Erreur envoi email: %v", err)
		http.Error(w, "Erreur envoi email", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// Handler pour la page de login admin
func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .login-container { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { color: red; margin-top: 10px; }
        h1 { text-align: center; color: #333; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Admin Login</h1>
        <form onsubmit="login(event)">
            <input type="password" id="password" placeholder="Mot de passe admin" required>
            <button type="submit">Se connecter</button>
            <div id="error" class="error"></div>
        </form>
    </div>

    <script>
        async function login(event) {
            event.preventDefault();
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: password })
                });
                
                if (response.ok) {
                    window.location.href = '/admin';
                } else {
                    document.getElementById('error').textContent = 'Mot de passe incorrect';
                }
            } catch (error) {
                document.getElementById('error').textContent = 'Erreur de connexion';
            }
        }
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
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
	}
	http.SetCookie(w, cookie)

	w.WriteHeader(http.StatusOK)
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
	})

	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// Handler pour l'interface web admin (sécurisée)
func adminHandler(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Email Template Manager</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .template { border: 1px solid #ddd; padding: 20px; margin: 10px 0; border-radius: 5px; }
        input, textarea, select { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
        button { padding: 10px 15px; margin: 5px; cursor: pointer; }
        .btn-primary { background: #007bff; color: white; border: none; }
        .btn-danger { background: #dc3545; color: white; border: none; }
        .btn-success { background: #28a745; color: white; border: none; }
        .btn-secondary { background: #6c757d; color: white; border: none; }
        .form-group { margin: 15px 0; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .api-key-section { background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .api-key { font-family: monospace; background: white; padding: 10px; border: 1px solid #ccc; border-radius: 3px; }
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
            <div class="api-key" id="apiKey">` + apiKey + `</div>
            <button class="btn-secondary" onclick="copyApiKey()">Copier</button>
        </div>
        
        <div class="form-group">
            <h2>Ajouter un nouveau template</h2>
            <input type="text" id="templateId" placeholder="ID du template (ex: welcome)">
            <input type="text" id="templateName" placeholder="Nom du template">
            <input type="text" id="templateSubject" placeholder="Sujet (ex: Bienvenue {{.first_name}}!)">
            <textarea id="templateHTML" rows="5" placeholder="HTML du template (ex: <h1>Bonjour {{.first_name}}!</h1>)"></textarea>
            <input type="text" id="templateParams" placeholder="Paramètres séparés par des virgules (ex: first_name,last_name)">
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
                        div.innerHTML = ` + "`" + `
                            <h3>${template.name} (${template.id})</h3>
                            <p><strong>Sujet:</strong> ${template.subject}</p>
                            <p><strong>Paramètres:</strong> ${template.params.join(', ')}</p>
                            <pre>${template.html}</pre>
                            <p><strong>Exemple d'appel API:</strong></p>
                            <pre>curl -X POST https://your-app.railway.app/email/${template.id} \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -d '{
    "to": "user@example.com",
    ` + "${template.params.map(param => `\"${param}\": \"valeur\"`).join(',\\n    ')}" + `
  }'</pre>
                            <button class="btn-danger" onclick="deleteTemplate('${template.id}')">Supprimer</button>
                        ` + "`" + `;
                        container.appendChild(div);
                        
                        // Ajouter au select
                        const option = document.createElement('option');
                        option.value = template.id;
                        option.textContent = template.name;
                        select.appendChild(option);
                    });
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
                });
        }

        function addTemplate() {
            const template = {
                id: document.getElementById('templateId').value,
                name: document.getElementById('templateName').value,
                subject: document.getElementById('templateSubject').value,
                html: document.getElementById('templateHTML').value,
                params: document.getElementById('templateParams').value.split(',').map(p => p.trim()).filter(p => p)
            };

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
                } else {
                    alert('Erreur lors de l\'ajout');
                }
            });
        }

        function deleteTemplate(id) {
            if (confirm('Supprimer ce template?')) {
                fetch(` + "`" + `/api/templates/${id}` + "`" + `, { method: 'DELETE' })
                .then(response => {
                    if (response.ok) {
                        alert('Template supprimé!');
                        loadTemplates();
                    } else {
                        alert('Erreur lors de la suppression');
                    }
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
            
            fetch(` + "`" + `/email/${templateId}` + "`" + `, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-API-Key': '` + apiKey + `'
                },
                body: JSON.stringify(emailData)
            })
            .then(response => {
                if (response.ok) {
                    alert('Email envoyé!');
                } else {
                    alert('Erreur lors de l\'envoi');
                }
            });
        }

        // Charger les templates au démarrage
        loadTemplates();
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// API Handlers pour la gestion des templates (sécurisés)
func getTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	templates := templateManager.GetAllTemplates()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

func addTemplateHandler(w http.ResponseWriter, r *http.Request) {
	var template EmailTemplate
	if err := json.NewDecoder(r.Body).Decode(&template); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}

	if template.ID == "" || template.Name == "" {
		http.Error(w, "ID et nom requis", http.StatusBadRequest)
		return
	}

	templateManager.AddTemplate(template)
	w.WriteHeader(http.StatusCreated)
}

func deleteTemplateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateID := vars["id"]
	
	templateManager.DeleteTemplate(templateID)
	w.WriteHeader(http.StatusOK)
}

func main() {
	// Initialiser les variables d'environnement
	resendAPIKey = os.Getenv("RESEND_API_KEY")
	fromEmail = os.Getenv("FROM_EMAIL")
	adminPassword = os.Getenv("ADMIN_PASSWORD")
	
	if resendAPIKey == "" {
		log.Fatal("RESEND_API_KEY requis")
	}
	if fromEmail == "" {
		fromEmail = "noreply@example.com"
	}
	if adminPassword == "" {
		adminPassword = "admin123" // Mot de passe par défaut (à changer !)
		log.Println("ATTENTION: Utilisation du mot de passe admin par défaut. Définissez ADMIN_PASSWORD.")
	}

	// Générer une clé API unique
	apiKey = generateAPIKey()
	log.Printf("Clé API générée: %s", apiKey)

	// Initialiser les sessions admin
	adminSessions = make(map[string]AdminSession)

	// Initialiser le gestionnaire de templates
	templateManager = NewTemplateManager()

	// Configurer les routes
	r := mux.NewRouter()
	
	// Routes publiques pour l'envoi d'emails (protégées par API key)
	r.HandleFunc("/email/{template}", apiKeyMiddleware(sendEmailHandler)).Methods("POST")
	
	// Routes pour l'authentification admin
	r.HandleFunc("/admin/login", loginPageHandler).Methods("GET")
	r.HandleFunc("/admin/login", loginHandler).Methods("POST")
	r.HandleFunc("/admin/logout", logoutHandler).Methods("POST")
	
	// Routes pour l'interface d'administration (protégées par session)
	r.HandleFunc("/admin", adminAuthMiddleware(adminHandler)).Methods("GET")
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	}).Methods("GET")
	
	// API pour la gestion des templates (protégée par session admin)
	r.HandleFunc("/api/templates", adminAuthMiddleware(getTemplatesHandler)).Methods("GET")
	r.HandleFunc("/api/templates", adminAuthMiddleware(addTemplateHandler)).Methods("POST")
	r.HandleFunc("/api/templates/{id}", adminAuthMiddleware(deleteTemplateHandler)).Methods("DELETE")

	// Configuration CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	handler := c.Handler(r)

	// Démarrer le serveur
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Serveur démarré sur le port %s", port)
	log.Printf("Interface admin: http://localhost:%s/admin/login", port)
	log.Printf("Mot de passe admin: %s", adminPassword)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}