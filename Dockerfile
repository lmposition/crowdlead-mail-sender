FROM golang:1.21-alpine AS builder

WORKDIR /app

# Installer les dépendances de build
RUN apk add --no-cache git gcc musl-dev

# Copier go.mod et go.sum (s'ils existent)
COPY go.mod go.sum* ./

# Télécharger les dépendances
RUN go mod download

# Copier le code source
COPY . .

# Compiler l'application
RUN CGO_ENABLED=1 GOOS=linux go build -o email-api -ldflags="-s -w" .

# Image finale
FROM alpine:3.18

WORKDIR /app

# Installer les dépendances nécessaires pour SQLite et TLS
RUN apk add --no-cache ca-certificates tzdata sqlite

# Créer le dossier pour la base de données
RUN mkdir -p /app/data

# Copier l'exécutable
COPY --from=builder /app/email-api /app/

# Exposer le port
EXPOSE 8080

# Définir la commande à exécuter
CMD ["/app/email-api"]