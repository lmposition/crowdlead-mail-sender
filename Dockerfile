FROM golang:1.21 AS builder

WORKDIR /app

# Désactiver complètement les vérifications de checksums
ENV GOSUMDB=off

# Copier le code et construire
COPY . .
RUN go mod tidy && go build -o app

# Image finale en une seule étape
FROM golang:1.21

WORKDIR /app

# Installer PostgreSQL client
RUN apt-get update && apt-get install -y postgresql-client

# Copier l'application et les scripts
COPY --from=builder /app/app .
COPY start.sh .
RUN chmod +x start.sh

# Exposer le port
EXPOSE 8080

# Démarrer l'application
CMD ["./start.sh"]