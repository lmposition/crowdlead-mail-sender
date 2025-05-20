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
	http.ServeFile(w, r, "./static/login.html")
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
	// Lire le fichier template
	tmpl, err := os.ReadFile("./static/admin.html")
	if err != nil {
		log.Printf("Erreur lecture template admin: %v", err)
		http.Error(w, "Erreur interne", http.StatusInternalServerError)
		return
	}

	// Remplacer la clé API dans le template
	htmlContent := strings.Replace(string(tmpl), "{{.APIKey}}", apiKey, -1)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlContent))
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
	
	// Routes pour les fichiers statiques
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	
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