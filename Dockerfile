
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Désactiver les vérifications de checksums
ENV GOSUMDB=off

# Copier et construire
COPY . .
RUN go mod tidy && go build -o app

# Image finale minimaliste
FROM alpine:3.18

WORKDIR /app

# Ajouter uniquement les certificats CA
RUN apk add --no-cache ca-certificates

# Copier l'application compilée
COPY --from=builder /app/app .
COPY start.sh .
RUN chmod +x start.sh

# Exposer le port
EXPOSE 8080

# Démarrer
CMD ["./start.sh"]