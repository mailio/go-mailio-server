# Use the official Golang image to build the Go app
FROM golang:1.23.2 AS builder

WORKDIR /app
# Install Swag CLI before running swag init
RUN go install github.com/swaggo/swag/cmd/swag@latest
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

COPY . .
RUN go mod tidy
RUN swag init --parseDependency=true
RUN go build -o mioserver

# Use a minimal Docker image to run the Go app
# Final minimal image
FROM debian:bookworm-slim
WORKDIR /app
# Install CA certificates
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /app/mioserver .

CMD ["./mioserver"]