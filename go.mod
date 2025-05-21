// go.mod
module github.com/yourusername/email-manager

go 1.21

require (
	github.com/go-chi/chi/v5 v5.0.10
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/jwtauth/v5 v5.1.1
	github.com/golang-jwt/jwt/v5 v5.0.0
	github.com/joho/godotenv v1.5.1
	github.com/mattn/go-sqlite3 v1.14.17
	github.com/resend/resend-go v1.7.0
	golang.org/x/crypto v0.14.0
)

// Modifications à apporter au main.go pour Railway

// Au début de la fonction main(), ajoutez ces lignes pour obtenir le port depuis l'environnement Railway
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
	
	// Le reste du code reste identique...
}

// Dans la fonction NewApp(), modifiez la gestion de la configuration:
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
		AdminPassword:    os.Getenv("ADMIN_PASSWORD"),
		SessionSecret:    os.Getenv("SESSION_SECRET"),
		ResendAPIKey:     os.Getenv("RESEND_API_KEY"),
		DefaultFromEmail: os.Getenv("FROM_EMAIL"),
		DbPath:           dbPath,
		JWTExpiration:    24 * time.Hour,
	}
	
	// Valeurs par défaut
	if config.Port == "" {
		config.Port = "8080" // Modifié à 8080 pour Railway
	}
	
	// Le reste du code reste identique...
}