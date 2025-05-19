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

// Structure pour les statistiques d'email
type EmailStats struct {
	TotalSent    int       `json:"total_sent"`
	TotalSuccess int       `json:"total_success"`
	TotalFailed  int       `json:"total_failed"`
	LastSentAt   time.Time `json:"last_sent_at"`
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

// Gestionnaire des logs d'email
type EmailLogManager struct {
	db    *sql.DB
	mutex sync.RWMutex
}

func NewTemplateManager(database *sql.DB) *TemplateManager {
	return &TemplateManager{db: database}
}

func NewSessionManager(database *sql.DB) *SessionManager {
	return &SessionManager{db: database}
}

func NewEmailLogManager(database *sql.DB) *EmailLogManager {
	return &EmailLogManager{db: database}
}

func (tm *TemplateManager) GetTemplate(id string) (EmailTemplate, bool) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	var template EmailTemplate
	var fromEmail sql.NullString

	query := `SELECT id, name, subject, html, from_email FROM email_templates WHERE id = $1`
	err := tm.db.QueryRow(query, id).Scan(
		&template.ID, &template.Name, &template.Subject,
		&template.HTML, &fromEmail,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return template, false
		}
		log.Printf("Erreur récupération template: %v", err)
		return template, false
	}

	if fromEmail.Valid {
		template.FromEmail = fromEmail.String
	}

	// Récupérer les paramètres séparément
	paramQuery := `SELECT param_name FROM template_params WHERE template_id = $1`
	rows, err := tm.db.Query(paramQuery, id)
	if err != nil {
		log.Printf("Erreur récupération paramètres: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var param string
			if err := rows.Scan(&param); err == nil {
				template.Params = append(template.Params, param)
			}
		}
	}

	return template, true
}

func (tm *TemplateManager) AddTemplate(template EmailTemplate) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Commencer une transaction
	tx, err := tm.db.Begin()
	if err != nil {
		return fmt.Errorf("erreur début transaction: %w", err)
	}
	defer tx.Rollback()

	// Insérer ou mettre à jour le template
	query := `INSERT INTO email_templates (id, name, subject, html, from_email) 
			  VALUES ($1, $2, $3, $4, $5)
			  ON CONFLICT (id) DO UPDATE SET 
			  name = $2, subject = $3, html = $4, from_email = $5, updated_at = CURRENT_TIMESTAMP`

	var fromEmail interface{}
	if template.FromEmail != "" {
		fromEmail = template.FromEmail
	}

	_, err = tx.Exec(query, template.ID, template.Name, template.Subject,
		template.HTML, fromEmail)
	if err != nil {
		return fmt.Errorf("erreur ajout template: %w", err)
	}

	// Supprimer les anciens paramètres
	_, err = tx.Exec("DELETE FROM template_params WHERE template_id = $1", template.ID)
	if err != nil {
		return fmt.Errorf("erreur suppression anciens paramètres: %w", err)
	}

	// Ajouter les nouveaux paramètres
	for _, param := range template.Params {
		_, err = tx.Exec("INSERT INTO template_params (template_id, param_name) VALUES ($1, $2)",
			template.ID, param)
		if err != nil {
			return fmt.Errorf("erreur ajout paramètre %s: %w", param, err)
		}
	}

	return tx.Commit()
}

func (tm *TemplateManager) GetAllTemplates() ([]EmailTemplate, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	query := `SELECT id, name, subject, html, from_email FROM email_templates ORDER BY name`
	rows, err := tm.db.Query(query)
	if err != nil {
		log.Printf("Erreur récupération templates: %v", err)
		return nil, fmt.Errorf("erreur récupération templates: %w", err)
	}
	defer rows.Close()

	var templates []EmailTemplate
	for rows.Next() {
		var template EmailTemplate
		var fromEmail sql.NullString

		err := rows.Scan(&template.ID, &template.Name, &template.Subject,
			&template.HTML, &fromEmail)
		if err != nil {
			log.Printf("Erreur scan template: %v", err)
			continue
		}

		if fromEmail.Valid {
			template.FromEmail = fromEmail.String
		}

		// Récupérer les paramètres
		paramQuery := `SELECT param_name FROM template_params WHERE template_id = $1`
		paramRows, err := tm.db.Query(paramQuery, template.ID)
		if err == nil {
			for paramRows.Next() {
				var param string
				if err := paramRows.Scan(&param); err == nil {
					template.Params = append(template.Params, param)
				}
			}
			paramRows.Close()
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

func (elm *EmailLogManager) LogEmail(templateID, recipientEmail, subject, status, errorMessage string) error {
	elm.mutex.Lock()
	defer elm.mutex.Unlock()

	query := `INSERT INTO email_logs (template_id, recipient_email, subject, status, error_message) 
			  VALUES ($1, $2, $3, $4, $5)`

	var errMsg interface{}
	if errorMessage != "" {
		errMsg = errorMessage
	}

	_, err := elm.db.Exec(query, templateID, recipientEmail, subject, status, errMsg)
	if err != nil {
		log.Printf("Erreur log email: %v", err)
		return fmt.Errorf("erreur log email: %w", err)
	}

	// Mettre à jour les statistiques
	elm.updateStats(templateID, status == "success")

	return nil
}

func (elm *EmailLogManager) updateStats(templateID string, success bool) {
	query := `INSERT INTO email_stats (template_id, total_sent, total_success, total_failed, last_sent_at)
			  VALUES ($1, 1, $2, $3, CURRENT_TIMESTAMP)
			  ON CONFLICT (template_id) DO UPDATE SET
			  total_sent = email_stats.total_sent + 1,
			  total_success = email_stats.total_success + $2,
			  total_failed = email_stats.total_failed + $3,
			  last_sent_at = CURRENT_TIMESTAMP`

	successCount := 0
	failedCount := 1
	if success {
		successCount = 1
		failedCount = 0
	}

	_, err := elm.db.Exec(query, templateID, successCount, failedCount)
	if err != nil {
		log.Printf("Erreur mise à jour stats: %v", err)
	}
}

func (elm *EmailLogManager) GetStats(templateID string) (EmailStats, error) {
	elm.mutex.RLock()
	defer elm.mutex.RUnlock()

	var stats EmailStats
	var lastSentAt sql.NullTime

	query := `SELECT total_sent, total_success, total_failed, last_sent_at 
			  FROM email_stats WHERE template_id = $1`

	err := elm.db.QueryRow(query, templateID).Scan(
		&stats.TotalSent, &stats.TotalSuccess, &stats.TotalFailed, &lastSentAt)

	if err != nil {
		if err == sql.ErrNoRows {
			// Pas de stats encore, retourner des zéros
			return EmailStats{}, nil
		}
		log.Printf("Erreur récupération stats: %v", err)
		return stats, fmt.Errorf("erreur récupération stats: %w", err)
	}

	if lastSentAt.Valid {
		stats.LastSentAt = lastSentAt.Time
	}

	return stats, nil
}

// Variables globales
var (
	db               *sql.DB
	templateManager  *TemplateManager
	sessionManager   *SessionManager
	emailLogManager  *EmailLogManager
	resendAPIKey     string
	fromEmail        string
	adminPassword    string
	apiKey           string
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
	var createTemplatesTable string
	var createParamsTable string
	var createSessionsTable string
	var createLogsTable string
	var createStatsTable string

	if driverName == "postgres" {
		createTemplatesTable = `
		CREATE TABLE IF NOT EXISTS email_templates (
			id VARCHAR(100) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			subject TEXT NOT NULL,
			html TEXT NOT NULL,
			from_email VARCHAR(255) DEFAULT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`

		createParamsTable = `
		CREATE TABLE IF NOT EXISTS template_params (
			id SERIAL PRIMARY KEY,
			template_id VARCHAR(100) NOT NULL,
			param_name VARCHAR(100) NOT NULL,
			FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE,
			UNIQUE (template_id, param_name)
		)`

		createSessionsTable = `
		CREATE TABLE IF NOT EXISTS admin_sessions (
			token VARCHAR(255) PRIMARY KEY,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`

		createLogsTable = `
		CREATE TABLE IF NOT EXISTS email_logs (
			id SERIAL PRIMARY KEY,
			template_id VARCHAR(100) NOT NULL,
			recipient_email VARCHAR(255) NOT NULL,
			subject TEXT NOT NULL,
			status VARCHAR(20) NOT NULL CHECK (status IN ('success', 'failed')),
			error_message TEXT DEFAULT NULL,
			sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE
		)`

		createStatsTable = `
		CREATE TABLE IF NOT EXISTS email_stats (
			id SERIAL PRIMARY KEY,
			template_id VARCHAR(100) NOT NULL,
			total_sent INTEGER DEFAULT 0,
			total_success INTEGER DEFAULT 0,
			total_failed INTEGER DEFAULT 0,
			last_sent_at TIMESTAMP NULL,
			FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE,
			UNIQUE (template_id)
		)`
	} else {
		// SQLite
		createTemplatesTable = `
		CREATE TABLE IF NOT EXISTS email_templates (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			subject TEXT NOT NULL,
			html TEXT NOT NULL,
			from_email TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`

		createParamsTable = `
		CREATE TABLE IF NOT EXISTS template_params (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			template_id TEXT NOT NULL,
			param_name TEXT NOT NULL,
			FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE,
			UNIQUE (template_id, param_name)
		)`

		createSessionsTable = `
		CREATE TABLE IF NOT EXISTS admin_sessions (
			token TEXT PRIMARY KEY,
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`

		createLogsTable = `
		CREATE TABLE IF NOT EXISTS email_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			template_id TEXT NOT NULL,
			recipient_email TEXT NOT NULL,
			subject TEXT NOT NULL,
			status TEXT NOT NULL CHECK (status IN ('success', 'failed')),
			error_message TEXT,
			sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE
		)`

		createStatsTable = `
		CREATE TABLE IF NOT EXISTS email_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			template_id TEXT NOT NULL,
			total_sent INTEGER DEFAULT 0,
			total_success INTEGER DEFAULT 0,
			total_failed INTEGER DEFAULT 0,
			last_sent_at DATETIME,
			FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE,
			UNIQUE (template_id)
		)`
	}

	// Créer toutes les tables
	tables := []string{
		createTemplatesTable,
		createParamsTable,
		createSessionsTable,
		createLogsTable,
		createStatsTable,
	}

	for _, tableSQL := range tables {
		if _, err := db.Exec(tableSQL); err != nil {
			return fmt.Errorf("erreur création table: %w", err)
		}
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
		emailLogManager.LogEmail(templateID, to, emailTemplate.Subject, "failed", "Erreur parsing subject")
		http.Error(w, "Erreur template subject", http.StatusInternalServerError)
		return
	}

	var subjectBuf bytes.Buffer
	if err := subjectTmpl.Execute(&subjectBuf, params); err != nil {
		log.Printf("Erreur exécution template subject: %v", err)
		emailLogManager.LogEmail(templateID, to, emailTemplate.Subject, "failed", "Erreur exécution subject")
		http.Error(w, "Erreur exécution template subject", http.StatusInternalServerError)
		return
	}

	// Traiter le HTML
	htmlTmpl, err := template.New("html").Parse(emailTemplate.HTML)
	if err != nil {
		log.Printf("Erreur parsing template HTML: %v", err)
		emailLogManager.LogEmail(templateID, to, subjectBuf.String(), "failed", "Erreur parsing HTML")
		http.Error(w, "Erreur template HTML", http.StatusInternalServerError)
		return
	}

	var htmlBuf bytes.Buffer
	if err := htmlTmpl.Execute(&htmlBuf, params); err != nil {
		log.Printf("Erreur exécution template HTML: %v", err)
		emailLogManager.LogEmail(templateID, to, subjectBuf.String(), "failed", "Erreur exécution HTML")
		http.Error(w, "Erreur exécution template HTML", http.StatusInternalServerError)
		return
	}

	// Déterminer l'email d'envoi
	emailFrom := emailTemplate.FromEmail
	if emailFrom == "" {
		emailFrom = fromEmail // Fallback sur l'email par défaut
	}

	// Envoyer l'email
	if err := sendEmailViaResend(to, subjectBuf.String(), htmlBuf.String(), emailFrom); err != nil {
		log.Printf("Erreur envoi email: %v", err)
		emailLogManager.LogEmail(templateID, to, subjectBuf.String(), "failed", err.Error())
		http.Error(w, "Erreur envoi email", http.StatusInternalServerError)
		return
	}

	// Logger le succès
	emailLogManager.LogEmail(templateID, to, subjectBuf.String(), "success", "")

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
            max-width: 1200px; 
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
            position: relative;
        }
        .template-stats {
            position: absolute;
            top: 10px;
            right: 10px;
            background: #e9ecef;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 12px;
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
        .btn-info { background: #17a2b8; color: white; }
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
        .tabs {
            display: flex;
            border-bottom: 1px solid #ddd;
            margin-bottom: 20px;
        }
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border: none;
            background: #f8f9fa;
            margin-right: 5px;
            border-radius: 5px 5px 0 0;
        }
        .tab.active {
            background: #007bff;
            color: white;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stats-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #dee2e6;
        }
        .stats-number {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }
        .stats-label {
            color: #6c757d;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Email Template Manager</h1>
            <button class="btn-secondary" onclick="logout()">Déconnexion</button>
        </div>

        <div class="tabs">
            <button class="tab active" onclick="showTab('templates')">Templates</button>
            <button class="tab" onclick="showTab('stats')">Statistiques</button>
        </div>

        <div id="templatesTab" class="tab-content active">
            <div class="api-key-section">
                <h3>Clé API</h3>
                <p>Utilisez cette clé API dans le header <code>X-API-Key</code> pour envoyer des emails :</p>
                <div class="api-key" id="apiKey">` + apiKey + `</div>
                <button class="btn-secondary" onclick="copyApiKey()">Copier</button>
            </div>
            
            <div class="form-group">
                <h2>Ajouter un nouveau template</h2>
                <form onsubmit="addTemplate(event); return false;">
                    <input type="text" id="templateId" placeholder="ID du template (ex: welcome)" required>
                    <input type="text" id="templateName" placeholder="Nom du template" required>
                    <input type="text" id="templateSubject" placeholder="Sujet (ex: Bienvenue {{.first_name}}!)" required>
                    <textarea id="templateHTML" rows="5" placeholder="HTML du template (ex: <h1>Bonjour {{.first_name}}!</h1>)" required></textarea>
                    <input type="text" id="templateParams" placeholder="Paramètres séparés par des virgules (ex: first_name,last_name)">
                    <input type="email" id="templateFromEmail" placeholder="Email expéditeur (optionnel)">
                    <button type="submit" class="btn-primary">Ajouter Template</button>
                </form>
                <div id="addTemplateMessage"></div>
            </div>

            <div class="form-group">
                <h2>Tester un email</h2>
                <form onsubmit="testEmail(event); return false;">
                    <select id="testTemplateId" required>
                        <option value="">Sélectionner un template</option>
                    </select>
                    <input type="email" id="testEmail" placeholder="Email destinataire" required>
                    <div id="paramInputs"></div>
                    <button type="submit" class="btn-success">Envoyer Test</button>
                </form>
                <div id="testEmailMessage"></div>
            </div>

            <div id="templates">
                <h2>Templates existants</h2>
                <div id="templatesLoading">Chargement...</div>
            </div>
        </div>

        <div id="statsTab" class="tab-content">
            <h2>Statistiques d'envoi</h2>
            <div id="statsLoading">Chargement des statistiques...</div>
            <div id="statsContent"></div>
        </div>
    </div>

    <script>
        let currentTemplates = [];

        function showTab(tabName) {
            // Supprimer la classe active de tous les onglets
            document.querySelectorAll('.tab-content').forEach(function(tab) {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(function(tab) {
                tab.classList.remove('active');
            });

            // Ajouter la classe active à l'onglet sélectionné
            document.getElementById(tabName + 'Tab').classList.add('active');
            
            // Trouver le bon bouton tab et l'activer
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(function(tab) {
                if (tab.textContent.toLowerCase().includes(tabName.toLowerCase()) || 
                    (tabName === 'templates' && tab.textContent === 'Templates') ||
                    (tabName === 'stats' && tab.textContent === 'Statistiques')) {
                    tab.classList.add('active');
                }
            });

            if (tabName === 'stats') {
                loadStats();
            }
        }

        function showMessage(elementId, message, isError) {
            if (isError === undefined) isError = false;
            const element = document.getElementById(elementId);
            element.textContent = message;
            element.className = isError ? 'error-message' : 'success-message';
            element.style.display = 'block';
            setTimeout(function() {
                element.style.display = 'none';
            }, 5000);
        }

        function loadTemplates() {
            const loadingDiv = document.getElementById('templatesLoading');
            loadingDiv.style.display = 'block';
            
            fetch('/api/templates')
                .then(function(response) {
                    if (!response.ok) {
                        throw new Error('Erreur de chargement: ' + response.status);
                    }
                    return response.json();
                })
                .then(function(templates) {
                    currentTemplates = templates;
                    displayTemplates(templates);
                    updateTemplateSelect(templates);
                    loadingDiv.style.display = 'none';
                })
                .catch(function(error) {
                    console.error('Erreur chargement templates:', error);
                    document.getElementById('templates').innerHTML = 
                        '<h2>Templates existants</h2><div class="error-message">Erreur de chargement: ' + error.message + '</div>';
                    loadingDiv.style.display = 'none';
                });
        }

        function loadStats() {
            const loadingDiv = document.getElementById('statsLoading');
            const contentDiv = document.getElementById('statsContent');
            
            loadingDiv.style.display = 'block';
            contentDiv.innerHTML = '';
            
            currentTemplates.forEach(function(template) {
                fetch('/api/stats/' + encodeURIComponent(template.id))
                    .then(function(response) { return response.json(); })
                    .then(function(stats) {
                        displayTemplateStats(template, stats);
                    })
                    .catch(function(error) {
                        console.error('Erreur chargement stats pour', template.id, ':', error);
                    });
            });
            
            loadingDiv.style.display = 'none';
        }

        function displayTemplateStats(template, stats) {
            const contentDiv = document.getElementById('statsContent');
            
            const statsDiv = document.createElement('div');
            statsDiv.className = 'template';
            
            var successRate = stats.total_sent > 0 ? Math.round(stats.total_success / stats.total_sent * 100) : 0;
            var lastSentText = stats.last_sent_at ? 
                '<p><strong>Dernier envoi:</strong> ' + new Date(stats.last_sent_at).toLocaleString() + '</p>' : 
                '<p>Aucun envoi pour le moment</p>';
            
            statsDiv.innerHTML = 
                '<h3>' + template.name + ' (' + template.id + ')</h3>' +
                '<div class="stats-grid">' +
                    '<div class="stats-card">' +
                        '<div class="stats-number">' + stats.total_sent + '</div>' +
                        '<div class="stats-label">Total envoyés</div>' +
                    '</div>' +
                    '<div class="stats-card">' +
                        '<div class="stats-number">' + stats.total_success + '</div>' +
                        '<div class="stats-label">Succès</div>' +
                    '</div>' +
                    '<div class="stats-card">' +
                        '<div class="stats-number">' + stats.total_failed + '</div>' +
                        '<div class="stats-label">Échecs</div>' +
                    '</div>' +
                    '<div class="stats-card">' +
                        '<div class="stats-number">' + successRate + '%</div>' +
                        '<div class="stats-label">Taux de succès</div>' +
                    '</div>' +
                '</div>' +
                lastSentText;
            
            contentDiv.appendChild(statsDiv);
        }

        function displayTemplates(templates) {
            const container = document.getElementById('templates');
            container.innerHTML = '<h2>Templates existants</h2>';
            
            if (templates.length === 0) {
                container.innerHTML += '<p>Aucun template trouvé. Créez votre premier template ci-dessus!</p>';
                return;
            }
            
            templates.forEach(function(template) {
                const div = document.createElement('div');
                div.className = 'template';
                
                fetch('/api/stats/' + encodeURIComponent(template.id))
                    .then(function(response) { return response.json(); })
                    .then(function(stats) {
                        const statsSpan = div.querySelector('.template-stats');
                        if (statsSpan) {
                            statsSpan.innerHTML = stats.total_sent + ' envoyés (' + stats.total_success + ' succès)';
                        }
                    })
                    .catch(function(error) {
                        console.error('Erreur stats:', error);
                    });
                
                const exampleParams = template.params.map(function(param) {
                    return '"' + param + '": "valeur"';
                }).join(',\\n    ');
                
                const curlExample = 'curl -X POST ' + window.location.origin + '/email/' + template.id + ' \\\\\\n' +
                    '  -H "Content-Type: application/json" \\\\\\n' +
                    '  -H "X-API-Key: ' + document.getElementById('apiKey').textContent + '" \\\\\\n' +
                    '  -d \\'{\\n' +
                    '    "to": "user@example.com"' + (exampleParams ? ',\\n' + '    ' + exampleParams : '') + '\\n' +
                    '  }\\'';
                
                div.innerHTML = 
                    '<span class="template-stats">Chargement stats...</span>' +
                    '<h3>' + template.name + ' (' + template.id + ')</h3>' +
                    '<p><strong>Sujet:</strong> ' + template.subject + '</p>' +
                    '<p><strong>Paramètres:</strong> ' + template.params.join(', ') + '</p>' +
                    (template.from_email ? '<p><strong>Email expéditeur:</strong> ' + template.from_email + '</p>' : '') +
                    '<p><strong>HTML:</strong></p>' +
                    '<pre>' + template.html + '</pre>' +
                    '<p><strong>Exemple d\\'appel API:</strong></p>' +
                    '<pre>' + curlExample + '</pre>' +
                    '<button class="btn-info" onclick="showTemplateStats(\'' + template.id + '\')">Voir Stats</button>' +
                    '<button class="btn-danger" onclick="deleteTemplate(\'' + template.id + '\')">Supprimer</button>';
                container.appendChild(div);
            });
        }

        function showTemplateStats(templateId) {
            showTab('stats');
            setTimeout(function() {
                const statsElements = document.querySelectorAll('#statsContent .template h3');
                for (let element of statsElements) {
                    if (element.textContent.indexOf('(' + templateId + ')') !== -1) {
                        element.scrollIntoView({ behavior: 'smooth' });
                        element.parentElement.style.border = '2px solid #007bff';
                        setTimeout(function() {
                            element.parentElement.style.border = '1px solid #ddd';
                        }, 3000);
                        break;
                    }
                }
            }, 100);
        }

        function updateTemplateSelect(templates) {
            const select = document.getElementById('testTemplateId');
            select.innerHTML = '<option value="">Sélectionner un template</option>';
            
            templates.forEach(function(template) {
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
            
            const template = currentTemplates.find(function(t) { return t.id === templateId; });
            if (!template) return;
            
            paramInputsDiv.innerHTML = '';
            template.params.forEach(function(param) {
                const input = document.createElement('input');
                input.type = 'text';
                input.placeholder = param;
                input.id = 'param_' + param;
                input.setAttribute('data-param', param);
                input.required = true;
                paramInputsDiv.appendChild(input);
            });
        }

        document.addEventListener('DOMContentLoaded', function() {
            loadTemplates();
            
            // Attacher l'événement pour le select des templates  
            const templateSelect = document.getElementById('testTemplateId');
            if (templateSelect) {
                templateSelect.addEventListener('change', updateParamInputs);
            }
            
            // Attacher les événements pour les onglets
            document.querySelectorAll('.tab').forEach(function(tab, index) {
                tab.addEventListener('click', function() {
                    if (index === 0) {
                        showTab('templates');
                    } else if (index === 1) {
                        showTab('stats');
                    }
                });
            });
        });

        function copyApiKey() {
            const apiKey = document.getElementById('apiKey').textContent;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(apiKey).then(function() {
                    alert('Clé API copiée !');
                }).catch(function(err) {
                    console.error('Erreur copie:', err);
                    prompt('Copiez cette clé API:', apiKey);
                });
            } else {
                prompt('Copiez cette clé API:', apiKey);
            }
        }

        function logout() {
            fetch('/admin/logout', { method: 'POST' })
                .then(function() {
                    window.location.href = '/admin/login';
                })
                .catch(function(error) {
                    console.error('Erreur logout:', error);
                    window.location.href = '/admin/login';
                });
        }

        function addTemplate(event) {
            event.preventDefault();

            const templateId = document.getElementById('templateId').value.trim();
            const templateName = document.getElementById('templateName').value.trim();
            const templateSubject = document.getElementById('templateSubject').value.trim();
            const templateHTML = document.getElementById('templateHTML').value.trim();
            const templateParams = document.getElementById('templateParams').value.trim();
            const templateFromEmail = document.getElementById('templateFromEmail').value.trim();

            if (!templateId || !templateName || !templateSubject || !templateHTML) {
                showMessage('addTemplateMessage', 'Tous les champs marqués comme requis doivent être remplis', true);
                return;
            }

            if (!/^[a-zA-Z0-9_-]+$/.test(templateId)) {
                showMessage('addTemplateMessage', 'L\'ID ne peut contenir que des lettres, chiffres, tirets et underscores', true);
                return;
            }

            const template = {
                id: templateId,
                name: templateName,
                subject: templateSubject,
                html: templateHTML,
                params: templateParams ? templateParams.split(',').map(function(p) { return p.trim(); }).filter(function(p) { return p; }) : []
            };

            if (templateFromEmail) {
                template.from_email = templateFromEmail;
            }

            const button = event.target.querySelector('button[type="submit"]') || event.target;
            const originalText = button.textContent;
            button.disabled = true;
            button.textContent = 'Ajout...';

            fetch('/api/templates', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(template)
            })
            .then(function(response) {
                if (!response.ok) {
                    return response.text().then(function(text) {
                        throw new Error(text || 'Erreur serveur');
                    });
                }
                return response.json();
            })
            .then(function(data) {
                showMessage('addTemplateMessage', 'Template ajouté avec succès!', false);
                loadTemplates();
                document.getElementById('templateId').value = '';
                document.getElementById('templateName').value = '';
                document.getElementById('templateSubject').value = '';
                document.getElementById('templateHTML').value = '';
                document.getElementById('templateParams').value = '';
                document.getElementById('templateFromEmail').value = '';
            })
            .catch(function(error) {
                console.error('Erreur ajout template:', error);
                showMessage('addTemplateMessage', 'Erreur: ' + error.message, true);
            })
            .finally(function() {
                button.disabled = false;
                button.textContent = originalText;
            });
        }

        function deleteTemplate(id) {
            if (!confirm('Êtes-vous sûr de vouloir supprimer ce template? Cela supprimera aussi tous les logs et statistiques associés.')) {
                return;
            }

            fetch('/api/templates/' + encodeURIComponent(id), { 
                method: 'DELETE' 
            })
            .then(function(response) {
                if (!response.ok) {
                    return response.text().then(function(text) {
                        throw new Error(text || 'Erreur serveur');
                    });
                }
                return response.json();
            })
            .then(function(data) {
                loadTemplates();
                alert('Template supprimé avec succès!');
            })
            .catch(function(error) {
                console.error('Erreur suppression template:', error);
                alert('Erreur: ' + error.message);
            });
        }

        function testEmail(event) {
            event.preventDefault();

            const templateId = document.getElementById('testTemplateId').value;
            const email = document.getElementById('testEmail').value.trim();
            
            if (!templateId || !email) {
                showMessage('testEmailMessage', 'Veuillez sélectionner un template et saisir un email', true);
                return;
            }
            
            try {
                const emailData = { to: email };
                
                const paramInputs = document.querySelectorAll('#paramInputs input');
                paramInputs.forEach(function(input) {
                    const paramName = input.getAttribute('data-param');
                    const paramValue = input.value.trim();
                    if (!paramValue) {
                        throw new Error('Le paramètre ' + paramName + ' est requis');
                    }
                    emailData[paramName] = paramValue;
                });
                
                const button = event.target.querySelector('button[type="submit"]') || event.target;
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
                .then(function(response) {
                    if (!response.ok) {
                        return response.text().then(function(text) {
                            throw new Error(text || 'Erreur serveur');
                        });
                    }
                    return response.json();
                })
                .then(function(data) {
                    showMessage('testEmailMessage', 'Email envoyé avec succès à ' + email + '!', false);
                    document.getElementById('testEmail').value = '';
                    document.querySelectorAll('#paramInputs input').forEach(function(input) {
                        input.value = '';
                    });
                    setTimeout(function() {
                        loadTemplates();
                    }, 1000);
                })
                .catch(function(error) {
                    console.error('Erreur envoi email:', error);
                    showMessage('testEmailMessage', 'Erreur: ' + error.message, true);
                })
                .finally(function() {
                    button.disabled = false;
                    button.textContent = originalText;
                });
            } catch (error) {
                showMessage('testEmailMessage', 'Erreur: ' + error.message, true);
            }
        }

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

// Handler pour récupérer les statistiques d'un template
func getStatsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateID := vars["id"]
	
	if templateID == "" {
		http.Error(w, "ID requis", http.StatusBadRequest)
		return
	}
	
	stats, err := emailLogManager.GetStats(templateID)
	if err != nil {
		log.Printf("Erreur récupération stats: %v", err)
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
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
	emailLogManager = NewEmailLogManager(db)

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
	r.HandleFunc("/api/stats/{id}", adminAuthMiddleware(getStatsHandler)).Methods("GET")

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