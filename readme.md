# Email Backend

Backend Go pour l'envoi d'emails via l'API Resend avec interface web de gestion pour crowdlead

## Fonctionnalités

- ✅ API REST pour envoyer des emails avec templates
- ✅ Interface web sécurisée pour gérer les templates
- ✅ Intégration avec l'API Resend
- ✅ Support des templates HTML avec variables
- ✅ Template "welcome" pré-configuré

## Installation

1. Cloner le projet
2. Installer les dépendances : `go mod tidy`
3. Configurer les variables d'environnement
4. Lancer : `go run main.go`

## Variables d'environnement

```bash
RESEND_API_KEY=your_resend_api_key
FROM_EMAIL=noreply@yourdomain.com
PORT=8080
```

## Endpoints API

### Envoyer un email
```bash
POST /email/{template_id}
{
  "to": "user@example.com",
  "params": {
    "first_name": "John",
    "last_name": "Doe"
  }
}
```

### Interface admin
- GET `/admin` - Interface de gestion des templates
- GET `/api/templates` - Liste tous les templates
- POST `/api/templates` - Ajoute un nouveau template
- DELETE `/api/templates/{id}` - Supprime un template

## Exemple d'utilisation

1. Accédez à `/admin` pour gérer vos templates
2. Envoyez un email welcome :

```bash
curl -X POST http://localhost:8080/email/welcome \
  -H "Content-Type: application/json" \
  -d '{
    "to": "user@example.com",
    "params": {
      "first_name": "John"
    }
  }'
```

## Déploiement sur Railway

1. Connectez votre repo GitHub à Railway
2. Configurez les variables d'environnement dans Railway
3. Railway détectera automatiquement le projet Go
4. Le service sera accessible sur l'URL fournie par Railway