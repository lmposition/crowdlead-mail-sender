package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	_ "github.com/lib/pq"           // PostgreSQL driver
	_ "github.com/mattn/go-sqlite3" // SQLite driver
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

// Gestionnaire des templates avec base de données
type TemplateManager struct {
	db    *sql.DB
	mutex sync.RWMutex
}

// Gestionnaire des sessions avec base de données
type SessionManager struct {
	db    *sql.DB
	mutex sync.RWMutex
}

func NewTemplateManager(database *sql.DB) *TemplateManager {
	return &TemplateManager{db: database}
}

func NewSessionManager(database *sql.DB) *SessionManager {
	return &SessionManager{db: database}
}

func (tm *TemplateManager) GetTemplate(id string) (EmailTemplate, bool) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	var template EmailTemplate
	var paramsStr string
	
	query := `SELECT id, name, subject, html, params, from_email FROM email_templates WHERE id = $1`
	err := tm.db.QueryRow(query, id).Scan(
		&template.ID, &template.Name, &template.Subject, 
		&template.HTML, &paramsStr, &template.FromEmail,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return template, false
		}
		log.Printf("Erreur récupération template: %v", err)
		return template, false
	}
	
	// Parser les paramètres
	if paramsStr != "" {
		template.Params = strings.Split(paramsStr, ",")
	}
	
	return template, true
}

func (tm *TemplateManager) AddTemplate(template EmailTemplate) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	paramsStr := strings.Join(template.Params, ",")
	
	query := `INSERT INTO email_templates (id, name, subject, html, params, from_email, created_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7)
			  ON CONFLICT (id) DO UPDATE SET 
			  name = $2, subject = $3, html = $4, params = $5, from_email = $6, updated_at = $7`
	
	now := time.Now()
	_, err := tm.db.Exec(query, template.ID, template.Name, template.Subject, 
						template.HTML, paramsStr, template.FromEmail, now)
	
	if err != nil {
		log.Printf("Erreur ajout template: %v", err)
		return fmt.Errorf("erreur ajout template: %w", err)
	}
	
	return nil
}

func (tm *TemplateManager) GetAllTemplates() ([]EmailTemplate, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	query := `SELECT id, name, subject, html, params, from_email FROM email_templates ORDER BY name`
	rows, err := tm.db.Query(query)
	if err != nil {
		log.Printf("Erreur récupération templates: %v", err)
		return nil, fmt.Errorf("erreur récupération templates: %w", err)
	}
	defer rows.Close()

	var templates []EmailTemplate
	for rows.Next() {
		var template EmailTemplate
		var paramsStr string
		
		err := rows.Scan(&template.ID, &template.Name, &template.Subject, 
						&template.HTML, &paramsStr, &template.FromEmail)
		if err != nil {
			log.Printf("Erreur scan template: %v", err)
			continue
		}
		
		// Parser les paramètres
		if paramsStr != "" {
			template.Params = strings.Split(paramsStr, ",")
		}
		
		templates = append(templates, template)
	}
	
	return templates, nil
}

func (tm *TemplateManager) DeleteTemplate(id string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	query := `DELETE FROM email_templates WHERE id = $1`
	result, err := tm.db.Exec(query, id)
	if err != nil {
		log.Printf("Erreur suppression template: %v", err)
		return fmt.Errorf("erreur suppression template: %w", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("erreur vérification suppression: %w", err)
	}
	
	if rowsAffected == 0 {
		return fmt.Errorf("template non trouvé")
	}
	
	return nil
}

func (sm *SessionManager) CreateSession(token string, expires time.Time) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	query := `INSERT INTO admin_sessions (token, expires_at) VALUES ($1, $2)
			  ON CONFLICT (token) DO UPDATE SET expires_at = $2`
	_, err := sm.db.Exec(query, token, expires)
	if err != nil {
		log.Printf("Erreur création session: %v", err)
		return fmt.Errorf("erreur création session: %w", err)
	}
	return nil
}

func (sm *SessionManager) GetSession(token string) (AdminSession, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	var session AdminSession
	query := `SELECT token, expires_at FROM admin_sessions WHERE token = $1 AND expires_at > $2`
	err := sm.db.QueryRow(query, token, time.Now()).Scan(&session.Token, &session.Expires)
	
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Erreur récupération session: %v", err)
		}
		return session, false
	}
	
	return session, true
}

func (sm *SessionManager) DeleteSession(token string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	query := `DELETE FROM admin_sessions WHERE token = $1`
	_, err := sm.db.Exec(query, token)
	if err != nil {
		log.Printf("Erreur suppression session: %v", err)
		return fmt.Errorf("erreur suppression session: %w", err)
	}
	return nil
}

func (sm *SessionManager) CleanupExpiredSessions() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	query := `DELETE FROM admin_sessions WHERE expires_at <= $1`
	result, err := sm.db.Exec(query, time.Now())
	if err != nil {
		log.Printf("Erreur nettoyage sessions: %v", err)
		return
	}
	
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("Nettoyé %d sessions expirées", rowsAffected)
	}
}

// Variables globales
var (
	db              *sql.DB
	templateManager *TemplateManager
	sessionManager  *SessionManager
	resendAPIKey    string
	fromEmail       string
	adminPassword   string
	apiKey          string
)

// Initialiser la base de données
func initDatabase() error {
	databaseURL := os.Getenv("DATABASE_URL")
	
	if databaseURL == "" {
		// Fallback vers SQLite si pas de DATABASE_URL
		databaseURL = "sqlite3://./email_manager.db"
		log.Println("⚠️  DATABASE_URL non défini, utilisation de SQLite par défaut")
	}

	var err error
	var driverName string
	var dataSourceName string

	// Parser l'URL de la base de données
	u, err := url.Parse(databaseURL)
	if err != nil {
		return fmt.Errorf("erreur parsing DATABASE_URL: %w", err)
	}

	switch u.Scheme {
	case "postgres", "postgresql":
		driverName = "postgres"
		dataSourceName = databaseURL
	case "sqlite3", "sqlite":
		driverName = "sqlite3"
		// Extraire le chemin du fichier SQLite
		if u.Path != "" {
			dataSourceName = u.Path
		} else if u.Host != "" {
			dataSourceName = u.Host + u.Path
		} else {
			dataSourceName = "./email_manager.db"
		}
	default:
		return fmt.Errorf("driver de base de données non supporté: %s", u.Scheme)
	}

	// Ouvrir la connexion à la base de données
	db, err = sql.Open(driverName, dataSourceName)
	if err != nil {
		return fmt.Errorf("erreur ouverture base de données: %w", err)
	}

	// Tester la connexion
	if err = db.Ping(); err != nil {
		return fmt.Errorf("erreur connexion base de données: %w", err)
	}

	// Créer les tables
	if err = createTables(driverName); err != nil {
		return fmt.Errorf("erreur création tables: %w", err)
	}

	log.Printf("✅ Base de données initialisée (%s)", driverName)
	return nil
}

func createTables(driverName string) error {
	// SQL compatible SQLite et PostgreSQL
	var createTemplatesTable string
	var createSessionsTable string

	if driverName == "postgres" {
		createTemplatesTable = `
		CREATE TABLE IF NOT EXISTS email_templates (
			id VARCHAR(255) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			subject TEXT NOT NULL,
			html TEXT NOT NULL,
			params TEXT,
			from_email VARCHAR(255),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`
		
		createSessionsTable = `
		CREATE TABLE IF NOT EXISTS admin_sessions (
			token VARCHAR(255) PRIMARY KEY,
			expires_at TIMESTAMP NOT NULL
		)`
	} else {
		// SQLite
		createTemplatesTable = `
		CREATE TABLE IF NOT EXISTS email_templates (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			subject TEXT NOT NULL,
			html TEXT NOT NULL,
			params TEXT,
			from_email TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`
		
		createSessionsTable = `
		CREATE TABLE IF NOT EXISTS admin_sessions (
			token TEXT PRIMARY KEY,
			expires_at DATETIME NOT NULL
		)`
	}

	// Créer la table des templates
	if _, err := db.Exec(createTemplatesTable); err != nil {
		return fmt.Errorf("erreur création table email_templates: %w", err)
	}

	// Créer la table des sessions
	if _, err := db.Exec(createSessionsTable); err != nil {
		return fmt.Errorf("erreur création table admin_sessions: %w", err)
	}

	log.Println("✅ Tables créées avec succès")
	return nil
}

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

		session, exists := sessionManager.GetSession(cookie.Value)
		if !exists || time.Now().After(session.Expires) {
			// Nettoyer la session expirée
			if exists {
				sessionManager.DeleteSession(cookie.Value)
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

	if err := sessionManager.CreateSession(sessionToken, expires); err != nil {
		log.Printf("Erreur création session: %v", err)
		http.Error(w, "Erreur serveur", http.StatusInternalServerError)
		return
	}

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
		sessionManager.DeleteSession(cookie.Value)
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
	html := `<!DOCTYPE html>
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
        .error-message {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            margin: 10px 0;
        }
        .success-message {
            background: #d4edda;
            color: #155724;
            padding: 10px;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            margin: 10px 0;
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
            <div class="api-key" id="apiKey">` + apiKey + `</div>
            <button class="btn-secondary" onclick="copyApiKey()">Copier</button>
        </div>
        
        <div class="form-group">
            <h2>Ajouter un nouveau template</h2>
            <input type="text" id="templateId" placeholder="ID du template (ex: welcome)" required>
            <input type="text" id="templateName" placeholder="Nom du template" required>
            <input type="text" id="templateSubject" placeholder="Sujet (ex: Bienvenue {{.first_name}}!)" required>
            <textarea id="templateHTML" rows="5" placeholder="HTML du template (ex: <h1>Bonjour {{.first_name}}!</h1>)" required></textarea>
            <input type="text" id="templateParams" placeholder="Paramètres séparés par des virgules (ex: first_name,last_name)">
            <input type="email" id="templateFromEmail" placeholder="Email expéditeur (optionnel)">
            <button class="btn-primary" onclick="addTemplate(event)">Ajouter Template</button>
            <div id="addTemplateMessage"></div>
        </div>

        <div class="form-group">
            <h2>Tester un email</h2>
            <select id="testTemplateId">
                <option value="">Sélectionner un template</option>
            </select>
            <input type="email" id="testEmail" placeholder="Email destinataire" required>
            <div id="paramInputs"></div>
            <button class="btn-success" onclick="testEmail()">Envoyer Test</button>
            <div id="testEmailMessage"></div>
        </div>

        <div id="templates">
            <h2>Templates existants</h2>
            <div id="templatesLoading">Chargement...</div>
        </div>
    </div>

    <script>
        let currentTemplates = [];

        function showMessage(elementId, message, isError = false) {
            const element = document.getElementById(elementId);
            element.textContent = message;
            element.className = isError ? 'error-message' : 'success-message';
            element.style.display = 'block';
            setTimeout(() => {
                element.style.display = 'none';
            }, 5000);
        }

        function loadTemplates() {
            const loadingDiv = document.getElementById('templatesLoading');
            loadingDiv.style.display = 'block';
            
            fetch('/api/templates')
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Erreur de chargement: ' + response.status);
                    }
                    return response.json();
                })
                .then(templates => {
                    currentTemplates = templates;
                    displayTemplates(templates);
                    updateTemplateSelect(templates);
                    loadingDiv.style.display = 'none';
                })
                .catch(error => {
                    console.error('Erreur chargement templates:', error);
                    document.getElementById('templates').innerHTML = 
                        '<h2>Templates existants</h2><div class="error-message">Erreur de chargement: ' + error.message + '</div>';
                    loadingDiv.style.display = 'none';
                });
        }

        function displayTemplates(templates) {
            const container = document.getElementById('templates');
            container.innerHTML = '<h2>Templates existants</h2>';
            
            if (templates.length === 0) {
                container.innerHTML += '<p>Aucun template trouvé. Créez votre premier template ci-dessus!</p>';
                return;
            }
            
            templates.forEach(template => {
                const div = document.createElement('div');
                div.className = 'template';
                
                const exampleParams = template.params.map(param => 
                    '"' + param + '": "valeur"'
                ).join(',\\n    ');
                
                const curlExample = 'curl -X POST ' + window.location.origin + '/email/' + template.id + ' \\\\\\n' +
                    '  -H "Content-Type: application/json" \\\\\\n' +
                    '  -H "X-API-Key: ' + document.getElementById('apiKey').textContent + '" \\\\\\n' +
                    '  -d \\'{\\n' +
                    '    "to": "user@example.com"' + (exampleParams ? ',\\n' + '    ' + exampleParams : '') + '\\n' +
                    '  }\\'';
                
                div.innerHTML = 
                    '<h3>' + template.name + ' (' + template.id + ')</h3>' +
                    '<p><strong>Sujet:</strong> ' + template.subject + '</p>' +
                    '<p><strong>Paramètres:</strong> ' + template.params.join(', ') + '</p>' +
                    (template.from_email ? '<p><strong>Email expéditeur:</strong> ' + template.from_email + '</p>' : '') +
                    '<p><strong>HTML:</strong></p>' +
                    '<pre>' + template.html + '</pre>' +
                    '<p><strong>Exemple d\\'appel API:</strong></p>' +
                    '<pre>' + curlExample + '</pre>' +
                    '<button class="btn-danger" onclick="deleteTemplate(\\'' + template.id + '\\')">Supprimer</button>';
                container.appendChild(div);
            });
        }

        function updateTemplateSelect(templates) {
            const select = document.getElementById('testTemplateId');
            select.innerHTML = '<option value="">Sélectionner un template</option>';
            
            templates.forEach(template => {
                const option = document.createElement('option');
                option.value = template.id;
                option.textContent = template.name;
                select.appendChild(option);
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
                input.required = true;
                paramInputsDiv.appendChild(input);
            });
        }

        document.getElementById('testTemplateId').addEventListener('change', updateParamInputs);

        function copyApiKey() {
            const apiKey = document.getElementById('apiKey').textContent;
            navigator.clipboard.writeText(apiKey).then(() => {
                alert('Clé API copiée !');
            }).catch(err => {
                console.error('Erreur copie:', err);
                prompt('Copiez cette clé API:', apiKey);
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

        function addTemplate(event) {
            // Empêcher le comportement par défaut si c'est un événement de formulaire
            if (event && event.preventDefault) {
                event.preventDefault();
            }

            const templateId = document.getElementById('templateId').value.trim();
            const templateName = document.getElementById('templateName').value.trim();
            const templateSubject = document.getElementById('templateSubject').value.trim();
            const templateHTML = document.getElementById('templateHTML').value.trim();
            const templateParams = document.getElementById('templateParams').value.trim();
            const templateFromEmail = document.getElementById('templateFromEmail').value.trim();

            // Validation côté client
            if (!templateId || !templateName || !templateSubject || !templateHTML) {
                showMessage('addTemplateMessage', 'Tous les champs marqués comme requis doivent être remplis', true);
                return;
            }

            // Vérifier que l'ID contient seulement des caractères valides
            if (!/^[a-zA-Z0-9_-]+$/.test(templateId)) {
                showMessage('addTemplateMessage', 'L\\'ID ne peut contenir que des lettres, chiffres, tirets et underscores', true);
                return;
            }

            const template = {
                id: templateId,
                name: templateName,
                subject: templateSubject,
                html: templateHTML,
                params: templateParams ? templateParams.split(',').map(p => p.trim()).filter(p => p) : []
            };

            if (templateFromEmail) {
                template.from_email = templateFromEmail;
            }

            // Trouver le bouton qui a déclenché l'action
            const button = event && event.target ? event.target : document.querySelector('.btn-primary');
            const originalText = button.textContent;
            button.disabled = true;
            button.textContent = 'Ajout...';

            fetch('/api/templates', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(template)
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text || 'Erreur serveur');
                    });
                }
                return response.json();
            })
            .then(data => {
                showMessage('addTemplateMessage', 'Template ajouté avec succès!', false);
                loadTemplates();
                // Vider le formulaire
                document.getElementById('templateId').value = '';
                document.getElementById('templateName').value = '';
                document.getElementById('templateSubject').value = '';
                document.getElementById('templateHTML').value = '';
                document.getElementById('templateParams').value = '';
                document.getElementById('templateFromEmail').value = '';
            })
            .catch(error => {
                console.error('Erreur ajout template:', error);
                showMessage('addTemplateMessage', 'Erreur: ' + error.message, true);
            })
            .finally(() => {
                button.disabled = false;
                button.textContent = originalText;
            });
        }

        function deleteTemplate(id) {
            if (!confirm('Êtes-vous sûr de vouloir supprimer ce template?')) {
                return;
            }

            fetch('/api/templates/' + encodeURIComponent(id), { 
                method: 'DELETE' 
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text || 'Erreur serveur');
                    });
                }
                return response.json();
            })
            .then(data => {
                loadTemplates();
                alert('Template supprimé avec succès!');
            })
            .catch(error => {
                console.error('Erreur suppression template:', error);
                alert('Erreur: ' + error.message);
            });
        }

        function testEmail(event) {
            // Empêcher le comportement par défaut si c'est un événement de formulaire
            if (event && event.preventDefault) {
                event.preventDefault();
            }

            const templateId = document.getElementById('testTemplateId').value;
            const email = document.getElementById('testEmail').value.trim();
            
            if (!templateId || !email) {
                showMessage('testEmailMessage', 'Veuillez sélectionner un template et saisir un email', true);
                return;
            }
            
            try {
                // Construire l'objet avec les paramètres
                const emailData = { to: email };
                
                // Ajouter tous les paramètres du template
                const paramInputs = document.querySelectorAll('#paramInputs input');
                paramInputs.forEach(input => {
                    const paramName = input.getAttribute('data-param');
                    const paramValue = input.value.trim();
                    if (!paramValue) {
                        throw new Error('Le paramètre ' + paramName + ' est requis');
                    }
                    emailData[paramName] = paramValue;
                });
                
                // Trouver le bouton qui a déclenché l'action
                const button = event && event.target ? event.target : document.querySelector('.btn-success');
                const originalText = button.textContent;
                button.disabled = true;
                button.textContent = 'Envoi...';

                fetch('/email/' + encodeURIComponent(templateId), {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-API-Key': document.getElementById('apiKey').textContent
                    },
                    body: JSON.stringify(emailData)
                })
                .then(response => {
                    if (!response.ok) {
                        return response.text().then(text => {
                            throw new Error(text || 'Erreur serveur');
                        });
                    }
                    return response.json();
                })
                .then(data => {
                    showMessage('testEmailMessage', 'Email envoyé avec succès à ' + email + '!', false);
                    // Vider les champs de test
                    document.getElementById('testEmail').value = '';
                    document.querySelectorAll('#paramInputs input').forEach(input => {
                        input.value = '';
                    });
                })
                .catch(error => {
                    console.error('Erreur envoi email:', error);
                    showMessage('testEmailMessage', 'Erreur: ' + error.message, true);
                })
                .finally(() => {
                    button.disabled = false;
                    button.textContent = originalText;
                });
            } catch (error) {
                showMessage('testEmailMessage', 'Erreur: ' + error.message, true);
            }
        }

        // Charger les templates au démarrage
        document.addEventListener('DOMContentLoaded', function() {
            loadTemplates();
        });
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

// API Handlers pour la gestion des templates (sécurisés)
func getTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	templates, err := templateManager.GetAllTemplates()
	if err != nil {
		log.Printf("Erreur récupération templates: %v", err)
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(templates); err != nil {
		log.Printf("Erreur encoding templates: %v", err)
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
	}
}

func addTemplateHandler(w http.ResponseWriter, r *http.Request) {
	var template EmailTemplate
	if err := json.NewDecoder(r.Body).Decode(&template); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}

	// Validation des champs requis
	if template.ID == "" || template.Name == "" || template.Subject == "" || template.HTML == "" {
		http.Error(w, "ID, nom, sujet et HTML sont requis", http.StatusBadRequest)
		return
	}

	// Validation de l'ID (caractères autorisés)
	for _, char := range template.ID {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || char == '_' || char == '-') {
			http.Error(w, "L'ID ne peut contenir que des lettres, chiffres, tirets et underscores", http.StatusBadRequest)
			return
		}
	}

	// Ajouter le template en base
	if err := templateManager.AddTemplate(template); err != nil {
		log.Printf("Erreur ajout template: %v", err)
		http.Error(w, "Erreur ajout template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"message": "Template créé avec succès",
	})
}

func deleteTemplateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateID := vars["id"]
	
	if templateID == "" {
		http.Error(w, "ID requis", http.StatusBadRequest)
		return
	}
	
	// Supprimer le template
	if err := templateManager.DeleteTemplate(templateID); err != nil {
		log.Printf("Erreur suppression template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"message": "Template supprimé avec succès",
	})
}

func main() {
	// Initialiser les variables d'environnement
	resendAPIKey = os.Getenv("RESEND_API_KEY")
	fromEmail = os.Getenv("FROM_EMAIL")
	adminPassword = os.Getenv("ADMIN_PASSWORD")
	
	if resendAPIKey == "" {
		log.Fatal("❌ RESEND_API_KEY est requis")
	}
	if fromEmail == "" {
		fromEmail = "noreply@example.com"
		log.Printf("⚠️  FROM_EMAIL non défini, utilisation de: %s", fromEmail)
	}
	if adminPassword == "" {
		adminPassword = "admin123"
		log.Println("⚠️  ATTENTION: Utilisation du mot de passe admin par défaut. Définissez ADMIN_PASSWORD.")
	}

	// Initialiser la base de données
	if err := initDatabase(); err != nil {
		log.Fatal("❌ Erreur initialisation base de données:", err)
	}
	defer db.Close()

	// Générer une clé API unique
	apiKey = generateAPIKey()
	log.Printf("🔑 Clé API générée: %s", apiKey)

	// Initialiser les gestionnaires
	templateManager = NewTemplateManager(db)
	sessionManager = NewSessionManager(db)

	// Vérifier qu'il y a au moins un template par défaut
	templates, err := templateManager.GetAllTemplates()
	if err != nil {
		log.Printf("⚠️  Erreur vérification templates: %v", err)
	} else if len(templates) == 0 {
		log.Println("📝 Aucun template trouvé, création du template par défaut...")
		defaultTemplate := EmailTemplate{
			ID:      "welcome",
			Name:    "Welcome Email",
			Subject: "Bienvenue {{.first_name}}!",
			HTML:    "<h1>Bienvenue {{.first_name}}!</h1><p>Nous sommes ravis de vous avoir parmi nous.</p>",
			Params:  []string{"first_name"},
		}
		if err := templateManager.AddTemplate(defaultTemplate); err != nil {
			log.Printf("⚠️  Erreur création template par défaut: %v", err)
		} else {
			log.Println("✅ Template par défaut créé")
		}
	}

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

	// Handler pour le health check
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "healthy",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}).Methods("GET")

	// Configuration CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	handler := c.Handler(r)

	// Lancer le nettoyage des sessions expirées toutes les heures
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			sessionManager.CleanupExpiredSessions()
		}
	}()

	// Démarrer le serveur
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🚀 Serveur démarré sur le port %s", port)
	log.Printf("🔗 Interface admin: http://localhost:%s/admin/login", port)
	log.Printf("👤 Mot de passe admin: %s", adminPassword)
	log.Printf("📧 FROM_EMAIL: %s", fromEmail)
	log.Printf("🔑 API Key: %s", apiKey)
	
	// Serveur avec configuration optimisée
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	log.Fatal(server.ListenAndServe())
}