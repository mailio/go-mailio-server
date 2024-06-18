# Use the official Golang image to build the Go app
FROM golang:1.22 as builder
# Set up environment variables
ENV GO111MODULE=on
ENV GOPRIVATE=github.com/mailio
ARG GITHUB_TOKEN

# Create .netrc file with GitHub token for private repo access
RUN mkdir -p /root && echo "machine github.com login $GITHUB_TOKEN password $GITHUB_TOKEN" > /root/.netrc

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