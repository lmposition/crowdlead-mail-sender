FROM golang:1.21-alpine AS builder

WORKDIR /app

# Installer les dépendances requises
RUN apk add --no-cache gcc musl-dev postgresql-client

# IMPORTANT: Désactiver la vérification des checksums 
ENV GONOSUMDB="github.com/resendlabs/*"
ENV GOSUMDB=off

# Copier les fichiers Go
COPY go.mod main.go ./

# Initialiser le module et construire
RUN go mod tidy && \
    go mod download && \
    go build -o email-api

# Image finale
FROM alpine:3.18

WORKDIR /app

# Installer les dépendances
RUN apk add --no-cache ca-certificates postgresql-client bash

# Copier l'exécutable compilé
COPY --from=builder /app/email-api .
COPY start.sh .

# Rendre le script exécutable
RUN chmod +x start.sh

# Exposer le port
EXPOSE 8080

# Lancer l'application
CMD ["/bin/bash", "start.sh"]