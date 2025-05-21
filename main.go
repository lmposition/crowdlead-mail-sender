package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/jwtauth/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/resend/resend-go"
	"golang.org/x/crypto/bcrypt"
)

// Configuration globale
type Config struct {
	Port             string
	AdminPassword    string
	SessionSecret    string
	EmailAPIKey      string
	ConfigAPIKey     string
	ResendAPIKey     string
	DefaultFromEmail string
	DbPath           string
	JWTSecret        []byte
	JWTExpiration    time.Duration
}

// Réponse API standard
type ApiResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}

// Modèles de données
type EmailTemplate struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Subject   string    `json:"subject"`
	HTML      string    `json:"html"`
	FromEmail string    `json:"fromEmail,omitempty"`
	Params    []string  `json:"params"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type EmailLog struct {
	ID             int64     `json:"id"`
	TemplateID     string    `json:"templateId"`
	TemplateName   string    `json:"templateName,omitempty"`
	RecipientEmail string    `json:"recipientEmail"`
	Subject        string    `json:"subject"`
	Status         string    `json:"status"`
	ErrorMessage   string    `json:"errorMessage,omitempty"`
	SentAt         time.Time `json:"sentAt"`
}

type EmailStats struct {
	TemplateID    string     `json:"templateId"`
	TemplateName  string     `json:"templateName"`
	TotalSent     int        `json:"totalSent"`
	TotalSuccess  int        `json:"totalSuccess"`
	TotalFailed   int        `json:"totalFailed"`
	LastSentAt    *time.Time `json:"lastSentAt,omitempty"`
	SuccessRate   float64    `json:"successRate"`
}

type DashboardStats struct {
	TotalTemplates   int          `json:"totalTemplates"`
	TotalEmailsSent  int          `json:"totalEmailsSent"`
	SuccessRate      float64      `json:"successRate"`
	RecentLogs       []EmailLog   `json:"recentLogs"`
	TemplatesStats   []EmailStats `json:"templatesStats"`
}

// Requêtes
type CreateTemplateRequest struct {
	Name      string `json:"name"`
	Subject   string `json:"subject"`
	HTML      string `json:"html"`
	FromEmail string `json:"fromEmail,omitempty"`
}

type UpdateTemplateRequest struct {
	Name      string `json:"name"`
	Subject   string `json:"subject"`
	HTML      string `json:"html"`
	FromEmail string `json:"fromEmail,omitempty"`
}

type SendEmailRequest map[string]interface{}

type LoginRequest struct {
	Password string `json:"password"`
}

// Base de données
type Database struct {
	DB *sql.DB
}

// Gestionnaire d'application
type App struct {
	Config  Config
	DB      *Database
	Resend  *resend.Client
	JWTAuth *jwtauth.JWTAuth
	Router  *chi.Mux
}

// Fonctions utilitaires
func generateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func extractTemplateParams(content string) []string {
	re := regexp.MustCompile(`\{\{(\w+)\}\}`)
	matches := re.FindAllStringSubmatch(content, -1)
	
	paramsMap := make(map[string]bool)
	var params []string
	
	for _, match := range matches {
		if len(match) > 1 && !paramsMap[match[1]] {
			paramsMap[match[1]] = true
			params = append(params, match[1])
		}
	}
	
	return params
}

func replaceTemplateParams(content string, params map[string]interface{}) string {
	result := content
	
	for key, value := range params {
		strValue := fmt.Sprintf("%v", value)
		placeholder := fmt.Sprintf("{{%s}}", key)
		result = strings.ReplaceAll(result, placeholder, strValue)
	}
	
	return result
}

// Initialisation de la base de données
func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	database := &Database{
		DB: db,
	}

	if err = database.InitTables(); err != nil {
		return nil, err
	}

	return database, nil
}

func (db *Database) InitTables() error {
	// Table des templates
	_, err := db.DB.Exec(`
	CREATE TABLE IF NOT EXISTS email_templates (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		subject TEXT NOT NULL,
		html TEXT NOT NULL,
		from_email TEXT,
		params TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return err
	}

	// Table des logs d'emails
	_, err = db.DB.Exec(`
	CREATE TABLE IF NOT EXISTS email_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		template_id TEXT NOT NULL,
		recipient_email TEXT NOT NULL,
		subject TEXT NOT NULL,
		status TEXT NOT NULL,
		error_message TEXT,
		sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE
	)`)
	if err != nil {
		return err
	}

	// Table des statistiques
	_, err = db.DB.Exec(`
	CREATE TABLE IF NOT EXISTS email_stats (
		template_id TEXT PRIMARY KEY,
		total_sent INTEGER DEFAULT 0,
		total_success INTEGER DEFAULT 0,
		total_failed INTEGER DEFAULT 0,
		last_sent_at DATETIME,
		FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE
	)`)
	if err != nil {
		return err
	}

	return nil
}

// Méthodes pour les templates
func (db *Database) GetTemplate(id string) (*EmailTemplate, error) {
	row := db.DB.QueryRow(`
	SELECT id, name, subject, html, from_email, params, created_at, updated_at 
	FROM email_templates 
	WHERE id = ?`, id)
	
	var template EmailTemplate
	var paramsJSON string
	
	err := row.Scan(
		&template.ID,
		&template.Name,
		&template.Subject,
		&template.HTML,
		&template.FromEmail,
		&paramsJSON,
		&template.CreatedAt,
		&template.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	
	err = json.Unmarshal([]byte(paramsJSON), &template.Params)
	if err != nil {
		template.Params = []string{}
	}
	
	return &template, nil
}

func (db *Database) GetAllTemplates() ([]EmailTemplate, error) {
	rows, err := db.DB.Query(`
	SELECT id, name, subject, html, from_email, params, created_at, updated_at 
	FROM email_templates 
	ORDER BY created_at DESC`)
	
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var templates []EmailTemplate
	
	for rows.Next() {
		var template EmailTemplate
		var paramsJSON string
		
		err := rows.Scan(
			&template.ID,
			&template.Name,
			&template.Subject,
			&template.HTML,
			&template.FromEmail,
			&paramsJSON,
			&template.CreatedAt,
			&template.UpdatedAt,
		)
		
		if err != nil {
			return nil, err
		}
		
		err = json.Unmarshal([]byte(paramsJSON), &template.Params)
		if err != nil {
			template.Params = []string{}
		}
		
		templates = append(templates, template)
	}
	
	if err = rows.Err(); err != nil {
		return nil, err
	}
	
	return templates, nil
}

func (db *Database) CreateTemplate(template *EmailTemplate) error {
	paramsJSON, err := json.Marshal(template.Params)
	if err != nil {
		return err
	}
	
	_, err = db.DB.Exec(`
	INSERT INTO email_templates (id, name, subject, html, from_email, params, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		template.ID,
		template.Name,
		template.Subject,
		template.HTML,
		template.FromEmail,
		string(paramsJSON),
		template.CreatedAt,
		template.UpdatedAt,
	)
	
	if err != nil {
		return err
	}
	
	// Initialiser les statistiques pour ce template
	_, err = db.DB.Exec(`
	INSERT INTO email_stats (template_id, total_sent, total_success, total_failed)
	VALUES (?, 0, 0, 0)`,
		template.ID,
	)
	
	return err
}

func (db *Database) UpdateTemplate(template *EmailTemplate) error {
	paramsJSON, err := json.Marshal(template.Params)
	if err != nil {
		return err
	}
	
	_, err = db.DB.Exec(`
	UPDATE email_templates 
	SET name = ?, subject = ?, html = ?, from_email = ?, params = ?, updated_at = ?
	WHERE id = ?`,
		template.Name,
		template.Subject,
		template.HTML,
		template.FromEmail,
		string(paramsJSON),
		template.UpdatedAt,
		template.ID,
	)
	
	return err
}

func (db *Database) DeleteTemplate(id string) error {
	_, err := db.DB.Exec("DELETE FROM email_templates WHERE id = ?", id)
	return err
}

// Méthodes pour les logs d'emails
func (db *Database) CreateEmailLog(log *EmailLog) error {
	_, err := db.DB.Exec(`
	INSERT INTO email_logs (template_id, recipient_email, subject, status, error_message)
	VALUES (?, ?, ?, ?, ?)`,
		log.TemplateID,
		log.RecipientEmail,
		log.Subject,
		log.Status,
		log.ErrorMessage,
	)
	
	if err != nil {
		return err
	}
	
	// Mettre à jour les statistiques
	return db.UpdateStats(log.TemplateID, log.Status)
}

func (db *Database) GetEmailLogs(templateID string, limit int) ([]EmailLog, error) {
	var query string
	var args []interface{}
	
	if templateID != "" {
		query = `
		SELECT l.id, l.template_id, t.name, l.recipient_email, l.subject, l.status, l.error_message, l.sent_at
		FROM email_logs l
		LEFT JOIN email_templates t ON l.template_id = t.id
		WHERE l.template_id = ?
		ORDER BY l.sent_at DESC
		LIMIT ?`
		args = []interface{}{templateID, limit}
	} else {
		query = `
		SELECT l.id, l.template_id, t.name, l.recipient_email, l.subject, l.status, l.error_message, l.sent_at
		FROM email_logs l
		LEFT JOIN email_templates t ON l.template_id = t.id
		ORDER BY l.sent_at DESC
		LIMIT ?`
		args = []interface{}{limit}
	}
	
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var logs []EmailLog
	
	for rows.Next() {
		var log EmailLog
		var templateName sql.NullString
		var errorMessage sql.NullString
		
		err := rows.Scan(
			&log.ID,
			&log.TemplateID,
			&templateName,
			&log.RecipientEmail,
			&log.Subject,
			&log.Status,
			&errorMessage,
			&log.SentAt,
		)
		
		if err != nil {
			return nil, err
		}
		
		if templateName.Valid {
			log.TemplateName = templateName.String
		}
		
		if errorMessage.Valid {
			log.ErrorMessage = errorMessage.String
		}
		
		logs = append(logs, log)
	}
	
	if err = rows.Err(); err != nil {
		return nil, err
	}
	
	return logs, nil
}

// Méthodes pour les statistiques
func (db *Database) UpdateStats(templateID, status string) error {
	var query string
	
	if status == "success" {
		query = `
		UPDATE email_stats 
		SET total_sent = total_sent + 1, 
			total_success = total_success + 1,
			last_sent_at = CURRENT_TIMESTAMP
		WHERE template_id = ?`
	} else {
		query = `
		UPDATE email_stats 
		SET total_sent = total_sent + 1, 
			total_failed = total_failed + 1,
			last_sent_at = CURRENT_TIMESTAMP
		WHERE template_id = ?`
	}
	
	_, err := db.DB.Exec(query, templateID)
	return err
}

func (db *Database) GetTemplateStats(templateID string) (*EmailStats, error) {
	query := `
	SELECT s.template_id, t.name, s.total_sent, s.total_success, s.total_failed, s.last_sent_at
	FROM email_stats s
	LEFT JOIN email_templates t ON s.template_id = t.id
	WHERE s.template_id = ?`
	
	row := db.DB.QueryRow(query, templateID)
	
	var stats EmailStats
	var templateName sql.NullString
	var lastSentAt sql.NullTime
	
	err := row.Scan(
		&stats.TemplateID,
		&templateName,
		&stats.TotalSent,
		&stats.TotalSuccess,
		&stats.TotalFailed,
		&lastSentAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	
	if templateName.Valid {
		stats.TemplateName = templateName.String
	}
	
	if lastSentAt.Valid {
		stats.LastSentAt = &lastSentAt.Time
	}
	
	if stats.TotalSent > 0 {
		stats.SuccessRate = float64(stats.TotalSuccess) / float64(stats.TotalSent) * 100
	}
	
	return &stats, nil
}

func (db *Database) GetAllStats() ([]EmailStats, error) {
	query := `
	SELECT s.template_id, t.name, s.total_sent, s.total_success, s.total_failed, s.last_sent_at
	FROM email_stats s
	LEFT JOIN email_templates t ON s.template_id = t.id
	ORDER BY s.total_sent DESC`
	
	rows, err := db.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var statsList []EmailStats
	
	for rows.Next() {
		var stats EmailStats
		var templateName sql.NullString
		var lastSentAt sql.NullTime
		
		err := rows.Scan(
			&stats.TemplateID,
			&templateName,
			&stats.TotalSent,
			&stats.TotalSuccess,
			&stats.TotalFailed,
			&lastSentAt,
		)
		
		if err != nil {
			return nil, err
		}
		
		if templateName.Valid {
			stats.TemplateName = templateName.String
		}
		
		if lastSentAt.Valid {
			stats.LastSentAt = &lastSentAt.Time
		}
		
		if stats.TotalSent > 0 {
			stats.SuccessRate = float64(stats.TotalSuccess) / float64(stats.TotalSent) * 100
		}
		
		statsList = append(statsList, stats)
	}
	
	if err = rows.Err(); err != nil {
		return nil, err
	}
	
	return statsList, nil
}

func (db *Database) GetDashboardStats() (*DashboardStats, error) {
	// Nombre total de templates
	var totalTemplates int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM email_templates").Scan(&totalTemplates)
	if err != nil {
		return nil, err
	}
	
	// Nombre total d'emails envoyés
	var totalEmailsSent int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM email_logs").Scan(&totalEmailsSent)
	if err != nil {
		return nil, err
	}
	
	// Taux de succès global
	var totalSuccess int
	var successRate float64
	err = db.DB.QueryRow("SELECT COUNT(*) FROM email_logs WHERE status = 'success'").Scan(&totalSuccess)
	if err != nil {
		return nil, err
	}
	
	if totalEmailsSent > 0 {
		successRate = float64(totalSuccess) / float64(totalEmailsSent) * 100
	}
	
	// Logs récents
	recentLogs, err := db.GetEmailLogs("", 10)
	if err != nil {
		return nil, err
	}
	
	// Statistiques des templates
	templatesStats, err := db.GetAllStats()
	if err != nil {
		return nil, err
	}
	
	dashboard := &DashboardStats{
		TotalTemplates:  totalTemplates,
		TotalEmailsSent: totalEmailsSent,
		SuccessRate:     successRate,
		RecentLogs:      recentLogs,
		TemplatesStats:  templatesStats,
	}
	
	return dashboard, nil
}

// Initialisation de l'application
func NewApp() (*App, error) {
	// Charger les variables d'environnement
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}
	
	// Configuration de base
	config := Config{
		Port:             os.Getenv("PORT"),
		AdminPassword:    os.Getenv("ADMIN_PASSWORD"),
		SessionSecret:    os.Getenv("SESSION_SECRET"),
		ResendAPIKey:     os.Getenv("RESEND_API_KEY"),
		DefaultFromEmail: os.Getenv("FROM_EMAIL"),
		DbPath:           os.Getenv("DB_PATH"),
		JWTExpiration:    24 * time.Hour,
	}
	
	// Valeurs par défaut
	if config.Port == "" {
		config.Port = "3000"
	}
	if config.DbPath == "" {
		config.DbPath = "./database.db"
	}
	
	// Générer des clés API si elles n'existent pas
	if os.Getenv("EMAIL_API_KEY") == "" {
		config.EmailAPIKey = generateSecureToken(16)
		os.Setenv("EMAIL_API_KEY", config.EmailAPIKey)
		log.Printf("Generated EMAIL_API_KEY: %s", config.EmailAPIKey)
	} else {
		config.EmailAPIKey = os.Getenv("EMAIL_API_KEY")
	}
	
	if os.Getenv("CONFIG_API_KEY") == "" {
		config.ConfigAPIKey = generateSecureToken(16)
		os.Setenv("CONFIG_API_KEY", config.ConfigAPIKey)
		log.Printf("Generated CONFIG_API_KEY: %s", config.ConfigAPIKey)
	} else {
		config.ConfigAPIKey = os.Getenv("CONFIG_API_KEY")
	}
	
	// Générer un secret JWT si nécessaire
	if config.SessionSecret == "" {
		config.SessionSecret = generateSecureToken(32)
		os.Setenv("SESSION_SECRET", config.SessionSecret)
	}
	config.JWTSecret = []byte(config.SessionSecret)
	
	// S'assurer que le mot de passe admin existe
	if config.AdminPassword == "" {
		adminPassword := generateSecureToken(8)
		config.AdminPassword = adminPassword
		os.Setenv("ADMIN_PASSWORD", adminPassword)
		log.Printf("Generated ADMIN_PASSWORD: %s", adminPassword)
	}
	
	// Initialiser la base de données
	db, err := NewDatabase(config.DbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	
	// Initialiser le client Resend
	resendClient := resend.NewClient(config.ResendAPIKey)
	
	// Initialiser JWT
	jwtAuth := jwtauth.New("HS256", config.JWTSecret, nil)
	
	// Configurer le routeur
	router := chi.NewRouter()
	
	// Créer l'application
	app := &App{
		Config:  config,
		DB:      db,
		Resend:  resendClient,
		JWTAuth: jwtAuth,
		Router:  router,
	}
	
	// Configurer les routes
	app.setupRoutes()
	
	return app, nil
}

// Configuration des routes
func (app *App) setupRoutes() {
	r := app.Router
	
	// Middleware globaux
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Timeout(30 * time.Second))
	
	// CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-API-Key"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	
	// Fichiers statiques
	fileServer := http.FileServer(http.Dir("./public"))
	r.Handle("/static/*", http.StripPrefix("/static", fileServer))
	
	// Middleware de base de données
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), "db", app.DB)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	
	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"status":    "OK",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})
	
	// Routes d'authentification
	r.Route("/admin", func(r chi.Router) {
		r.Post("/login", app.handleLogin)
		
		// Routes protégées par JWT
		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(app.JWTAuth))
			r.Use(app.authenticateJWT)
			
			r.Post("/logout", app.handleLogout)
			r.Get("/dashboard", app.handleGetDashboard)
			r.Get("/logs", app.handleGetLogs)
			r.Get("/stats", app.handleGetStats)
		})
	})
	
	// Routes pour les templates (protégées par API key)
	r.Route("/api/templates", func(r chi.Router) {
		r.Use(app.validateConfigAPIKey)
		
		r.Get("/", app.handleGetAllTemplates)
		r.Post("/", app.handleCreateTemplate)
		r.Get("/{id}", app.handleGetTemplate)
		r.Put("/{id}", app.handleUpdateTemplate)
		r.Delete("/{id}", app.handleDeleteTemplate)
		r.Get("/{id}/stats", app.handleGetTemplateStats)
		r.Get("/{id}/logs", app.handleGetTemplateLogs)
	})
	
	// Routes pour l'envoi d'emails (protégées par API key)
	r.Route("/email", func(r chi.Router) {
		r.Use(app.validateEmailAPIKey)
		
		r.Post("/{templateId}", app.handleSendEmail)
		r.Post("/{templateId}/test", app.handleSendTestEmail)
	})
	
	// Routes de l'interface utilisateur
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	
	r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./public/admin.html")
	})
	
	r.Get("/admin/login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./public/login.html")
	})
}

// Middleware d'authentification
func (app *App) authenticateJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _, err := jwtauth.FromContext(r.Context())
		
		if err != nil || token == nil || !token.Valid {
			respondWithError(w, http.StatusUnauthorized, "Token d'authentification invalide")
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (app *App) validateEmailAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		
		if apiKey == "" {
			respondWithError(w, http.StatusUnauthorized, "Clé API requise dans l'en-tête X-API-Key")
			return
		}
		
		if apiKey != app.Config.EmailAPIKey {
			respondWithError(w, http.StatusForbidden, "Clé API invalide")
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (app *App) validateConfigAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		
		if apiKey == "" {
			respondWithError(w, http.StatusUnauthorized, "Clé API requise dans l'en-tête X-API-Key")
			return
		}
		
		if apiKey != app.Config.ConfigAPIKey {
			respondWithError(w, http.StatusForbidden, "Clé API de configuration invalide")
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// Utilitaires de réponse
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success":false,"error":"Erreur interne du serveur"}`))
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, ApiResponse{
		Success: false,
		Error:   message,
	})
}

func respondWithSuccess(w http.ResponseWriter, code int, data interface{}, message string) {
	respondWithJSON(w, code, ApiResponse{
		Success: true,
		Data:    data,
		Message: message,
	})
}

// Gestionnaires d'authentification
func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Requête invalide")
		return
	}
	
	if req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Mot de passe requis")
		return
	}
	
	// En production, utiliser bcrypt
	passwordMatches := false
	if os.Getenv("APP_ENV") == "production" {
		err := bcrypt.CompareHashAndPassword([]byte(app.Config.AdminPassword), []byte(req.Password))
		passwordMatches = err == nil
	} else {
		// En développement, comparaison directe
		passwordMatches = req.Password == app.Config.AdminPassword
	}
	
	if !passwordMatches {
		respondWithError(w, http.StatusUnauthorized, "Mot de passe incorrect")
		return
	}
	
	// Créer le token JWT
	expiration := time.Now().Add(app.Config.JWTExpiration)
	claims := jwt.MapClaims{
		"exp": expiration.Unix(),
		"iat": time.Now().Unix(),
		"sub": "admin",
	}
	
	_, tokenString, err := app.JWTAuth.Encode(claims)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la création du token")
		return
	}
	
	respondWithSuccess(w, http.StatusOK, map[string]interface{}{
		"token":     tokenString,
		"expiresAt": expiration.Format(time.RFC3339),
	}, "Connexion réussie")
}

func (app *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	// JWT stateless, pas besoin de logique compliquée
	respondWithSuccess(w, http.StatusOK, nil, "Déconnexion réussie")
}

// Gestionnaires des templates
func (app *App) handleGetAllTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := app.DB.GetAllTemplates()
	if err != nil {
		log.Printf("Erreur lors de la récupération des templates: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération des templates")
		return
	}
	
	respondWithSuccess(w, http.StatusOK, templates, "")
}

func (app *App) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	
	template, err := app.DB.GetTemplate(id)
	if err != nil {
		log.Printf("Erreur lors de la récupération du template: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération du template")
		return
	}
	
	if template == nil {
		respondWithError(w, http.StatusNotFound, "Template non trouvé")
		return
	}
	
	respondWithSuccess(w, http.StatusOK, template, "")
}

func (app *App) handleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	var req CreateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Requête invalide")
		return
	}
	
	// Validation
	if req.Name == "" || req.Subject == "" || req.HTML == "" {
		respondWithError(w, http.StatusBadRequest, "Nom, sujet et contenu HTML sont requis")
		return
	}
	
	// Extraire les paramètres
	subjectParams := extractTemplateParams(req.Subject)
	htmlParams := extractTemplateParams(req.HTML)
	
	// Fusion des paramètres uniques
	paramsMap := make(map[string]bool)
	var params []string
	
	for _, param := range subjectParams {
		if !paramsMap[param] {
			paramsMap[param] = true
			params = append(params, param)
		}
	}
	
	for _, param := range htmlParams {
		if !paramsMap[param] {
			paramsMap[param] = true
			params = append(params, param)
		}
	}
	
	// Générer un ID unique
	templateID := fmt.Sprintf("tpl_%s", generateSecureToken(8))
	now := time.Now()
	
	template := &EmailTemplate{
		ID:        templateID,
		Name:      req.Name,
		Subject:   req.Subject,
		HTML:      req.HTML,
		FromEmail: req.FromEmail,
		Params:    params,
		CreatedAt: now,
		UpdatedAt: now,
	}
	
	if err := app.DB.CreateTemplate(template); err != nil {
		log.Printf("Erreur lors de la création du template: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la création du template")
		return
	}
	
	respondWithSuccess(w, http.StatusCreated, template, "Template créé avec succès")
}

func (app *App) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	
	existingTemplate, err := app.DB.GetTemplate(id)
	if err != nil {
		log.Printf("Erreur lors de la récupération du template: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération du template")
		return
	}
	
	if existingTemplate == nil {
		respondWithError(w, http.StatusNotFound, "Template non trouvé")
		return
	}
	
	var req UpdateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Requête invalide")
		return
	}
	
	// Validation
	if req.Name == "" || req.Subject == "" || req.HTML == "" {
		respondWithError(w, http.StatusBadRequest, "Nom, sujet et contenu HTML sont requis")
		return
	}
	
	// Extraire les paramètres
	subjectParams := extractTemplateParams(req.Subject)
	htmlParams := extractTemplateParams(req.HTML)
	
	// Fusion des paramètres uniques
	paramsMap := make(map[string]bool)
	var params []string
	
	for _, param := range subjectParams {
		if !paramsMap[param] {
			paramsMap[param] = true
			params = append(params, param)
		}
	}
	
	for _, param := range htmlParams {
		if !paramsMap[param] {
			paramsMap[param] = true
			params = append(params, param)
		}
	}
	
	// Mettre à jour le template
	existingTemplate.Name = req.Name
	existingTemplate.Subject = req.Subject
	existingTemplate.HTML = req.HTML
	existingTemplate.FromEmail = req.FromEmail
	existingTemplate.Params = params
	existingTemplate.UpdatedAt = time.Now()
	
	if err := app.DB.UpdateTemplate(existingTemplate); err != nil {
		log.Printf("Erreur lors de la mise à jour du template: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la mise à jour du template")
		return
	}
	
	respondWithSuccess(w, http.StatusOK, existingTemplate, "Template mis à jour avec succès")
}

func (app *App) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	
	// Vérifier que le template existe
	existingTemplate, err := app.DB.GetTemplate(id)
	if err != nil {
		log.Printf("Erreur lors de la récupération du template: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération du template")
		return
	}
	
	if existingTemplate == nil {
		respondWithError(w, http.StatusNotFound, "Template non trouvé")
		return
	}
	
	if err := app.DB.DeleteTemplate(id); err != nil {
		log.Printf("Erreur lors de la suppression du template: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la suppression du template")
		return
	}
	
	respondWithSuccess(w, http.StatusOK, nil, "Template supprimé avec succès")
}

// Gestionnaires des statistiques et logs
func (app *App) handleGetTemplateStats(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	
	// Vérifier que le template existe
	existingTemplate, err := app.DB.GetTemplate(id)
	if err != nil {
		log.Printf("Erreur lors de la récupération du template: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération du template")
		return
	}
	
	if existingTemplate == nil {
		respondWithError(w, http.StatusNotFound, "Template non trouvé")
		return
	}
	
	stats, err := app.DB.GetTemplateStats(id)
	if err != nil {
		log.Printf("Erreur lors de la récupération des statistiques: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération des statistiques")
		return
	}
	
	if stats == nil {
		stats = &EmailStats{
			TemplateID:   id,
			TemplateName: existingTemplate.Name,
			TotalSent:    0,
			TotalSuccess: 0,
			TotalFailed:  0,
			SuccessRate:  0,
		}
	}
	
	respondWithSuccess(w, http.StatusOK, stats, "")
}

func (app *App) handleGetTemplateLogs(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	
	// Vérifier que le template existe
	existingTemplate, err := app.DB.GetTemplate(id)
	if err != nil {
		log.Printf("Erreur lors de la récupération du template: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération du template")
		return
	}
	
	if existingTemplate == nil {
		respondWithError(w, http.StatusNotFound, "Template non trouvé")
		return
	}
	
	limit := 50
	if limitParam := r.URL.Query().Get("limit"); limitParam != "" {
		if parsedLimit, err := strconv.Atoi(limitParam); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}
	
	logs, err := app.DB.GetEmailLogs(id, limit)
	if err != nil {
		log.Printf("Erreur lors de la récupération des logs: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération des logs")
		return
	}
	
	respondWithSuccess(w, http.StatusOK, logs, "")
}

func (app *App) handleGetDashboard(w http.ResponseWriter, r *http.Request) {
	stats, err := app.DB.GetDashboardStats()
	if err != nil {
		log.Printf("Erreur lors de la récupération des statistiques du tableau de bord: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération des statistiques du tableau de bord")
		return
	}
	
	respondWithSuccess(w, http.StatusOK, stats, "")
}

func (app *App) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if limitParam := r.URL.Query().Get("limit"); limitParam != "" {
		if parsedLimit, err := strconv.Atoi(limitParam); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}
	
	logs, err := app.DB.GetEmailLogs("", limit)
	if err != nil {
		log.Printf("Erreur lors de la récupération des logs: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération des logs")
		return
	}
	
	respondWithSuccess(w, http.StatusOK, logs, "")
}

func (app *App) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := app.DB.GetAllStats()
	if err != nil {
		log.Printf("Erreur lors de la récupération des statistiques: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération des statistiques")
		return
	}
	
	respondWithSuccess(w, http.StatusOK, stats, "")
}

// Gestionnaires d'envoi d'emails
func (app *App) handleSendEmail(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "templateId")
	
	// Récupérer le template
	template, err := app.DB.GetTemplate(templateID)
	if err != nil {
		log.Printf("Erreur lors de la récupération du template: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération du template")
		return
	}
	
	if template == nil {
		respondWithError(w, http.StatusNotFound, "Template non trouvé")
		return
	}
	
	// Décoder la requête
	var req SendEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Requête invalide")
		return
	}
	
	// Vérifier le destinataire
	to, ok := req["to"]
	if !ok || to == "" {
		respondWithError(w, http.StatusBadRequest, "Destinataire requis")
		return
	}
	
	// Vérifier que tous les paramètres requis sont fournis
	var missingParams []string
	for _, param := range template.Params {
		if _, exists := req[param]; !exists {
			missingParams = append(missingParams, param)
		}
	}
	
	if len(missingParams) > 0 {
		respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Paramètres manquants: %s", strings.Join(missingParams, ", ")))
		return
	}
	
	// Extraire CC et BCC si présents
	var cc, bcc string
	if ccValue, exists := req["cc"]; exists {
		cc = fmt.Sprintf("%v", ccValue)
	}
	if bccValue, exists := req["bcc"]; exists {
		bcc = fmt.Sprintf("%v", bccValue)
	}
	
	// Créer un sous-ensemble des paramètres pour le remplacement (sans to, cc, bcc)
	templateParams := make(map[string]interface{})
	for k, v := range req {
		if k != "to" && k != "cc" && k != "bcc" {
			templateParams[k] = v
		}
	}
	
	// Remplacer les paramètres dans le sujet et le contenu
	subject := replaceTemplateParams(template.Subject, templateParams)
	html := replaceTemplateParams(template.HTML, templateParams)
	
	// Préparer l'email
	fromEmail := template.FromEmail
	if fromEmail == "" {
		fromEmail = app.Config.DefaultFromEmail
	}
	
	// Convertir to en tableau si c'est une chaîne
	var recipients []string
	switch v := to.(type) {
	case string:
		recipients = []string{v}
	case []string:
		recipients = v
	case []interface{}:
		for _, r := range v {
			if s, ok := r.(string); ok {
				recipients = append(recipients, s)
			}
		}
	default:
		recipients = []string{fmt.Sprintf("%v", to)}
	}
	
	// Envoyer l'email via Resend
	params := &resend.SendEmailRequest{
		From:    fromEmail,
		To:      recipients,
		Subject: subject,
		Html:    html,
	}
	
	if cc != "" {
		params.Cc = []string{cc}
	}
	if bcc != "" {
		params.Bcc = []string{bcc}
	}
	
	// Créer le log d'email (initialement en échec)
	emailLog := &EmailLog{
		TemplateID:     templateID,
		RecipientEmail: strings.Join(recipients, ", "),
		Subject:        subject,
		Status:         "failed",
		SentAt:         time.Now(),
	}
	
	resp, err := app.Resend.Emails.Send(params)
	if err != nil {
		// Enregistrer l'échec
		emailLog.ErrorMessage = err.Error()
		if dbErr := app.DB.CreateEmailLog(emailLog); dbErr != nil {
			log.Printf("Erreur lors de l'enregistrement du log d'email: %v", dbErr)
		}
		
		log.Printf("Erreur lors de l'envoi de l'email: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de l'envoi de l'email")
		return
	}
	
	// Mettre à jour le log pour indiquer le succès
	emailLog.Status = "success"
	if err := app.DB.CreateEmailLog(emailLog); err != nil {
		log.Printf("Erreur lors de l'enregistrement du log d'email: %v", err)
	}
	
	respondWithSuccess(w, http.StatusOK, map[string]interface{}{
		"emailId":    resp.ID,
		"templateId": templateID,
		"recipient":  to,
		"subject":    subject,
	}, "Email envoyé avec succès")
}

func (app *App) handleSendTestEmail(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "templateId")
	
	// Récupérer le template
	template, err := app.DB.GetTemplate(templateID)
	if err != nil {
		log.Printf("Erreur lors de la récupération du template: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de la récupération du template")
		return
	}
	
	if template == nil {
		respondWithError(w, http.StatusNotFound, "Template non trouvé")
		return
	}
	
	// Décoder la requête
	var req SendEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Requête invalide")
		return
	}
	
	// Vérifier le destinataire
	to, ok := req["to"]
	if !ok || to == "" {
		respondWithError(w, http.StatusBadRequest, "Destinataire requis pour le test")
		return
	}
	
	// Préparer des valeurs par défaut pour les paramètres manquants
	testParams := make(map[string]interface{})
	for _, param := range template.Params {
		if value, exists := req[param]; exists {
			testParams[param] = value
		} else {
			testParams[param] = fmt.Sprintf("[TEST_%s]", strings.ToUpper(param))
		}
	}
	
	// Remplacer les paramètres dans le sujet et le contenu
	subject := "[TEST] " + replaceTemplateParams(template.Subject, testParams)
	html := replaceTemplateParams(template.HTML, testParams)
	
	// Préparer l'email
	fromEmail := template.FromEmail
	if fromEmail == "" {
		fromEmail = app.Config.DefaultFromEmail
	}
	
	// Convertir to en tableau si c'est une chaîne
	var recipients []string
	switch v := to.(type) {
	case string:
		recipients = []string{v}
	case []string:
		recipients = v
	case []interface{}:
		for _, r := range v {
			if s, ok := r.(string); ok {
				recipients = append(recipients, s)
			}
		}
	default:
		recipients = []string{fmt.Sprintf("%v", to)}
	}
	
	// Envoyer l'email via Resend
	params := &resend.SendEmailRequest{
		From:    fromEmail,
		To:      recipients,
		Subject: subject,
		Html:    html,
	}
	
	resp, err := app.Resend.Emails.Send(params)
	if err != nil {
		log.Printf("Erreur lors de l'envoi de l'email de test: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Erreur lors de l'envoi de l'email de test")
		return
	}
	
	respondWithSuccess(w, http.StatusOK, map[string]interface{}{
		"emailId":    resp.ID,
		"templateId": templateID,
		"recipient":  to,
		"subject":    subject,
		"testParams": testParams,
	}, "Email de test envoyé avec succès")
}

// Fonction principale
func main() {
	// Créer l'application
	app, err := NewApp()
	if err != nil {
		log.Fatalf("Erreur lors de l'initialisation de l'application: %v", err)
	}
	
	// Afficher les informations importantes
	log.Printf("🚀 Email Manager API démarré sur le port %s", app.Config.Port)
	log.Printf("📧 API Email disponible avec la clé API: %s", app.Config.EmailAPIKey)
	log.Printf("⚙️ API Config disponible avec la clé API: %s", app.Config.ConfigAPIKey)
	log.Printf("💾 Base de données: %s", app.Config.DbPath)
	
	// Configurer le canal pour les signaux d'arrêt
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	
	// Démarrer le serveur dans une goroutine
	srv := &http.Server{
		Addr:    ":" + app.Config.Port,
		Handler: app.Router,
	}
	
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Erreur du serveur HTTP: %v", err)
		}
	}()
	
	<-stop
	
	log.Println("🛑 Arrêt du serveur...")
	
	// Création d'un contexte avec un timeout pour l'arrêt propre
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Erreur lors de l'arrêt du serveur: %v", err)
	}
	
	log.Println("✅ Serveur arrêté proprement")
}