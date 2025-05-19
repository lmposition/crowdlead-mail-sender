package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

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

// Structure pour la requête d'envoi d'email
type SendEmailRequest struct {
	To     string                 `json:"to"`
	Params map[string]interface{} `json:"params"`
}

// Structure pour l'API Resend
type ResendRequest struct {
	From    string `json:"from"`
	To      []string `json:"to"`
	Subject string `json:"subject"`
	HTML    string `json:"html"`
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
)

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

	var req SendEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}

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
	if err := subjectTmpl.Execute(&subjectBuf, req.Params); err != nil {
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
	if err := htmlTmpl.Execute(&htmlBuf, req.Params); err != nil {
		http.Error(w, "Erreur exécution template HTML", http.StatusInternalServerError)
		return
	}

	// Envoyer l'email
	if err := sendEmailViaResend(req.To, subjectBuf.String(), htmlBuf.String()); err != nil {
		log.Printf("Erreur envoi email: %v", err)
		http.Error(w, "Erreur envoi email", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// Handler pour l'interface web
func adminHandler(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Email Template Manager</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .template { border: 1px solid #ddd; padding: 20px; margin: 10px 0; border-radius: 5px; }
        input, textarea, select { width: 100%; padding: 8px; margin: 5px 0; }
        button { padding: 10px 15px; margin: 5px; cursor: pointer; }
        .btn-primary { background: #007bff; color: white; border: none; }
        .btn-danger { background: #dc3545; color: white; border: none; }
        .btn-success { background: #28a745; color: white; border: none; }
        .form-group { margin: 15px 0; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Email Template Manager</h1>
        
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
            <textarea id="testParams" rows="3" placeholder='Paramètres JSON (ex: {"first_name": "John", "last_name": "Doe"})'></textarea>
            <button class="btn-success" onclick="testEmail()">Envoyer Test</button>
        </div>

        <div id="templates">
            <h2>Templates existants</h2>
        </div>
    </div>

    <script>
        function loadTemplates() {
            fetch('/api/templates')
                .then(response => response.json())
                .then(templates => {
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
            const paramsText = document.getElementById('testParams').value;
            
            if (!templateId || !email) {
                alert('Veuillez sélectionner un template et saisir un email');
                return;
            }
            
            let params = {};
            if (paramsText) {
                try {
                    params = JSON.parse(paramsText);
                } catch (e) {
                    alert('JSON des paramètres invalide');
                    return;
                }
            }
            
            fetch(` + "`" + `/email/${templateId}` + "`" + `, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ to: email, params: params })
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

// API Handlers pour la gestion des templates
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
	
	if resendAPIKey == "" {
		log.Fatal("RESEND_API_KEY requis")
	}
	if fromEmail == "" {
		fromEmail = "noreply@example.com" // Email par défaut
	}

	// Initialiser le gestionnaire de templates
	templateManager = NewTemplateManager()

	// Configurer les routes
	r := mux.NewRouter()
	
	// Routes pour l'envoi d'emails
	r.HandleFunc("/email/{template}", sendEmailHandler).Methods("POST")
	
	// Routes pour l'interface d'administration
	r.HandleFunc("/admin", adminHandler).Methods("GET")
	r.HandleFunc("/", adminHandler).Methods("GET")
	
	// API pour la gestion des templates
	r.HandleFunc("/api/templates", getTemplatesHandler).Methods("GET")
	r.HandleFunc("/api/templates", addTemplateHandler).Methods("POST")
	r.HandleFunc("/api/templates/{id}", deleteTemplateHandler).Methods("DELETE")

	// Configuration CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

	handler := c.Handler(r)

	// Démarrer le serveur
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Serveur démarré sur le port %s", port)
	log.Printf("Interface admin: http://localhost:%s/admin", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}