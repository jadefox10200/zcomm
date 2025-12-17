FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies for cgo + sqlite
RUN apk add --no-cache build-base sqlite-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Enable cgo for building with sqlite3 support
ENV CGO_ENABLED=1

RUN go build -o zcomm .

FROM alpine

WORKDIR /app

# Your runtime will need libc and libsqlite3
RUN apk add --no-cache sqlite-libs

COPY --from=builder /app/zcomm .
COPY --from=builder /app/someotherfiles .

CMD ["./zcomm"]