# Stage 1: Build the binary
FROM golang:alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Copy the vendor directory (contains all dependencies)
COPY vendor ./vendor

# Copy the rest of the source code
COPY . .

# Build the binary using the vendor folder (no internet needed)
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o aegislog main.go

# Stage 2: Create a minimal runtime image
FROM alpine:latest

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/aegislog .

# Copy the embedded HTML file
COPY index.html .

# Expose the port
EXPOSE 8080

# Run the binary
CMD ["./aegislog"]
