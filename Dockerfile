FROM golang:1.21-alpine AS builder

WORKDIR /app

# Installer les dépendances de build
RUN apk add --no-cache git gcc musl-dev

# Copier uniquement les fichiers de dépendances d'abord
COPY go.mod go.sum ./

# Forcer la mise à jour des dépendances avec checksum correct
RUN go mod download && go mod verify

# Copier le code source
COPY . .

# Compiler l'application
RUN CGO_ENABLED=1 GOOS=linux go build -o email-api -ldflags="-s -w" .

# Image finale
FROM alpine:3.18

WORKDIR /app

# Installer les dépendances nécessaires pour PostgreSQL et TLS
RUN apk add --no-cache ca-certificates tzdata postgresql-client

# Créer le dossier pour le conteneur
RUN mkdir -p /app/data

# Copier l'exécutable
COPY --from=builder /app/email-api /app/

# Exposer le port
EXPOSE 8080

# Définir la commande à exécuter
CMD ["/app/email-api"]