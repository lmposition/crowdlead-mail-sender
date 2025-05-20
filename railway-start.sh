#!/bin/bash

echo "🚂 Démarrage Railway Email Manager..."

# Vérifier les variables d'environnement
if [ -z "$ADMIN_PASSWORD" ]; then
    echo "❌ ADMIN_PASSWORD non définie"
    exit 1
fi

if [ -z "$SESSION_SECRET" ]; then
    echo "❌ SESSION_SECRET non définie"
    exit 1
fi

# Créer la structure de dossiers
mkdir -p dist
mkdir -p public

# Build si nécessaire
if [ ! -d "dist" ] || [ ! "$(ls -A dist)" ]; then
    echo "📦 Building application..."
    npm run build
fi

echo "✅ Démarrage du serveur..."
npm start