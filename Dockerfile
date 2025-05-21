FROM golang:1.21-alpine AS builder

WORKDIR /app

# Installer uniquement le minimum nécessaire
RUN apk add --no-cache gcc musl-dev

# Copier go.mod et go.sum
COPY go.mod go.sum ./

# Télécharger les dépendances
RUN go mod download

# Copier le code source
COPY . .

# Compiler l'application
RUN CGO_ENABLED=1 go build -o email-api .

# Image finale ultra légère
FROM alpine:3.18

WORKDIR /app

# Uniquement les certificats nécessaires pour HTTPS
RUN apk add --no-cache ca-certificates

# Copier l'exécutable compilé
COPY --from=builder /app/email-api .

# Exposer le port
EXPOSE 8080

# Lancer l'application
CMD ["/app/email-api"]