CREATE TABLE IF NOT EXISTS email_templates (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    from_email VARCHAR(255) NOT NULL DEFAULT '',
    subject TEXT NOT NULL,
    html TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Ajouter la colonne from_email si elle n'existe pas (pour migration)
DO $ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                  WHERE table_name='email_templates' AND column_name='from_email') THEN
        ALTER TABLE email_templates ADD COLUMN from_email VARCHAR(255) NOT NULL DEFAULT '';
    END IF;
END $;

-- Index pour améliorer les performances des requêtes
CREATE INDEX IF NOT EXISTS idx_email_templates_created_at ON email_templates(created_at DESC);