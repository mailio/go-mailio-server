# Use the official Golang image to build the Go app
FROM golang:1.23.2 as builder

WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o mioserver

# Use a minimal Docker image to run the Go app
# Final minimal image
FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /app/mioserver .

CMD ["./mioserver"]