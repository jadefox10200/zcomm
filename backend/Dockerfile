FROM golang:1.24.9-alpine AS builder

WORKDIR /app

# Install build dependencies for cgo + sqlite
RUN apk add --no-cache build-base sqlite-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go mod tidy

# Enable CGO for go-sqlite3
ENV CGO_ENABLED=1

RUN go build -o zcomm .

# Final image
FROM alpine

WORKDIR /app

# Add runtime sqlite libs
RUN apk add --no-cache sqlite-libs

# Create data directory for database
RUN mkdir -p /app/data /app/attachments

ENV ATTACHMENT_DIR=/app/attachments

COPY --from=builder /app/zcomm .

CMD ["./zcomm"]