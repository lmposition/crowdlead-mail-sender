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
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/resend/resend-go"
)

// Configuration globale
type Config struct {
	Port             string
	EmailAPIKey      string
	ConfigAPIKey     string
	ResendAPIKey     string
	DefaultFromEmail string
	DbPath           string
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

// Base de données
type Database struct {
	DB *sql.DB
}

// Gestionnaire d'application
type App struct {
	Config Config
	DB     *Database
	Resend *resend.Client
	Router *chi.Mux
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

	return err
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
	
	return err
}

// Initialisation de l'application
func NewApp() (*App, error) {
	// Charger les variables d'environnement
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}
	
	// Base de données : sur Railway, stockez-la dans /app/data
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/app/data/database.db"
		if _, err := os.Stat("/app/data"); os.IsNotExist(err) {
			// Si nous ne sommes pas sur Railway, utilisez un chemin local
			dbPath = "./database.db"
		}
	}
	
	// Configuration de base
	config := Config{
		Port:             os.Getenv("PORT"),
		ResendAPIKey:     os.Getenv("RESEND_API_KEY"),
		DefaultFromEmail: os.Getenv("FROM_EMAIL"),
		DbPath:           dbPath,
	}
	
	// Valeurs par défaut
	if config.Port == "" {
		config.Port = "8080" // Pour Railway
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
	
	// Initialiser la base de données
	db, err := NewDatabase(config.DbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	
	// Initialiser le client Resend
	resendClient := resend.NewClient(config.ResendAPIKey)
	
	// Configurer le routeur
	router := chi.NewRouter()
	
	// Créer l'application
	app := &App{
		Config:  config,
		DB:      db,
		Resend:  resendClient,
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
	
	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"status":    "OK",
			"timestamp": time.Now().Format(time.RFC3339),
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
	})
	
	// Routes pour l'envoi d'emails (protégées par API key)
	r.Route("/email", func(r chi.Router) {
		r.Use(app.validateEmailAPIKey)
		
		r.Post("/{templateId}", app.handleSendEmail)
		r.Post("/{templateId}/test", app.handleSendTestEmail)
	})
}

// Middleware d'authentification API
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
	
	// Obtenir le port depuis l'environnement Railway ou utiliser la valeur par défaut
	port := os.Getenv("PORT")
	if port == "" {
		port = app.Config.Port // Utiliser la valeur par défaut
	} else {
		app.Config.Port = port // Mettre à jour la config
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
} := template.FromEmail
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
	fromEmail