# Stage 1: Build the binary
FROM golang:alpine AS builder

WORKDIR /app

# Copy the entire source code (including vendor)
COPY . .

# Build using the vendor directory (no network needed)
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o aegislog main.go

# Stage 2: Create a minimal runtime image
FROM alpine:latest

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/aegislog .

# Copy the embedded HTML file
COPY index.html .

EXPOSE 8080

CMD ["./aegislog"]
