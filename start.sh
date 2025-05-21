#!/bin/bash
set -e

echo "🚀 Démarrage de l'application Email Manager..."

# Vérification des variables d'environnement
if [ -z "$DATABASE_URL" ]; then
  echo "❌ ERROR: DATABASE_URL n'est pas défini"
  exit 1
fi

if [ -z "$RESEND_API_KEY" ]; then
  echo "⚠️ WARNING: RESEND_API_KEY n'est pas défini"
fi

if [ -z "$FROM_EMAIL" ]; then
  echo "⚠️ WARNING: FROM_EMAIL n'est pas défini"
fi

# Génération des clés API si nécessaire
if [ -z "$EMAIL_API_KEY" ]; then
  export EMAIL_API_KEY=$(openssl rand -hex 16)
  echo "📧 EMAIL_API_KEY générée: $EMAIL_API_KEY"
fi

if [ -z "$CONFIG_API_KEY" ]; then
  export CONFIG_API_KEY=$(openssl rand -hex 16)
  echo "⚙️ CONFIG_API_KEY générée: $CONFIG_API_KEY"
fi

# Extraire les infos de connexion de DATABASE_URL
if [[ $DATABASE_URL == postgres://* ]]; then
  # Format attendu: postgres://username:password@hostname:port/database_name
  DB_USER=$(echo $DATABASE_URL | awk -F[:@] '{print $2}' | sed 's/\/\///')
  DB_PASS=$(echo $DATABASE_URL | awk -F[:@] '{print $3}')
  DB_HOST=$(echo $DATABASE_URL | awk -F[@:/] '{print $4}')
  DB_PORT=$(echo $DATABASE_URL | awk -F[@:/] '{print $5}')
  DB_NAME=$(echo $DATABASE_URL | awk -F[@:/] '{print $6}')
  
  echo "🛢️ Connexion à PostgreSQL: $DB_HOST:$DB_PORT/$DB_NAME"
  
  # Création des tables PostgreSQL si nécessaire
  echo "🛢️ Initialisation de la base de données..."
  
  export PGPASSWORD=$DB_PASS
  psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "
  CREATE TABLE IF NOT EXISTS email_templates (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      subject TEXT NOT NULL,
      html TEXT NOT NULL,
      from_email TEXT,
      params TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS email_logs (
      id SERIAL PRIMARY KEY,
      template_id TEXT NOT NULL,
      recipient_email TEXT NOT NULL,
      subject TEXT NOT NULL,
      status TEXT NOT NULL,
      error_message TEXT,
      sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE
  );"
else
  echo "⚠️ Format DATABASE_URL non reconnu. Les tables ne seront pas initialisées automatiquement."
fi

# Lancer l'application (elle doit déjà être compilée)
echo "🚀 Lancement de l'API Email Manager..."
echo "📊 API disponible sur le port ${PORT:-8080}"

# Vérifier si l'exécutable existe
if [ -f "./email-api" ]; then
  exec ./email-api
else
  echo "❌ ERROR: exécutable email-api non trouvé!"
  echo "📁 Contenu du répertoire:"
  ls -la
  exit 1
fi