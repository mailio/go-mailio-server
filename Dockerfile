# Use the official Golang image to build the Go app
FROM golang:1.22 as builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o mioserver

# Use a minimal Docker image to run the Go app
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/mioserver .
COPY conf.yaml /root/mioserver
COPY test_server_keys.json /root/mioserver
CMD ["./mioserver"]