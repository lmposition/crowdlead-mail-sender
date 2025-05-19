CREATE TABLE email_templates (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    subject TEXT NOT NULL,
    html TEXT NOT NULL,
    from_email VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table pour les paramètres des templates
CREATE TABLE template_params (
    id SERIAL PRIMARY KEY,
    template_id VARCHAR(100) NOT NULL,
    param_name VARCHAR(100) NOT NULL,
    FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE,
    UNIQUE (template_id, param_name)
);

-- Table pour les sessions admin
CREATE TABLE admin_sessions (
    token VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table pour les logs d'envoi d'emails (optionnel)
CREATE TABLE email_logs (
    id SERIAL PRIMARY KEY,
    template_id VARCHAR(100) NOT NULL,
    recipient_email VARCHAR(255) NOT NULL,
    subject TEXT NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('success', 'failed')),
    error_message TEXT DEFAULT NULL,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE
);

-- Table pour les statistiques d'envoi (optionnel)
CREATE TABLE email_stats (
    id SERIAL PRIMARY KEY,
    template_id VARCHAR(100) NOT NULL,
    total_sent INTEGER DEFAULT 0,
    total_success INTEGER DEFAULT 0,
    total_failed INTEGER DEFAULT 0,
    last_sent_at TIMESTAMP NULL,
    FOREIGN KEY (template_id) REFERENCES email_templates(id) ON DELETE CASCADE,
    UNIQUE (template_id)
);

-- =============================================================================
-- ÉTAPE 3 : INDEX ET OPTIMISATIONS
-- =============================================================================

-- Index pour optimiser les requêtes
CREATE INDEX idx_email_templates_name ON email_templates(name);
CREATE INDEX idx_admin_sessions_expires ON admin_sessions(expires_at);
CREATE INDEX idx_email_logs_template_id ON email_logs(template_id);
CREATE INDEX idx_email_logs_recipient ON email_logs(recipient_email);
CREATE INDEX idx_email_logs_sent_at ON email_logs(sent_at);

-- =============================================================================
-- ÉTAPE 4 : DONNÉES INITIALES
-- =============================================================================

-- Insérer un template par défaut
INSERT INTO email_templates (id, name, subject, html) VALUES 
('welcome', 'Welcome Email', 'Bienvenue {{.first_name}}!', '<h1>Bienvenue {{.first_name}}!</h1><p>Nous sommes ravis de vous avoir parmi nous.</p>');

-- Insérer les paramètres du template par défaut
INSERT INTO template_params (template_id, param_name) VALUES 
('welcome', 'first_name');

-- =============================================================================
-- ÉTAPE 5 : TRIGGER POUR updated_at (PostgreSQL)
-- =============================================================================

-- Fonction pour mettre à jour automatiquement updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger sur la table email_templates
CREATE TRIGGER update_email_templates_updated_at
    BEFORE UPDATE ON email_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();