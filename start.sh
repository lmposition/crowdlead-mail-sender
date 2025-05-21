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

# Création des tables PostgreSQL si nécessaire
echo "🛢️ Initialisation de la base de données..."
PGPASSWORD=${DATABASE_URL##*:} psql ${DATABASE_URL} -c "
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

# Lancer l'application
echo "🚀 Lancement de l'API Email Manager..."
exec ./email-api