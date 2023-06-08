# Mailio Server

Mailio Server implementation based on [Mailio MIRs](https://mirs.mail.io) specifications. 


## gRPC Curl Examples

*Install grpcurl* 

```sh
curl -sSL "https://github.com/fullstorydev/grpcurl/releases/download/v1.8.7/grpcurl_1.8.7_linux_x86_64.tar.gz" | sudo tar -xz -C /usr/local/bin
```

**List services**
```sh
grpcurl -plaintext localhost:50051 list
```

**Describe service**
```sh
grpcurl -plaintext localhost:50051 describe pong.PongService
```

### Ping service

Learning servers local time including timezone
```sh
grpcurl -plaintext localhost:50051 pong.PongService.Ping
{
  "message": "2023-04-05T17:00:36-06:00"
}
```

## Development

1. Clone this repository
2. Create `conf.yaml` file with contents:

```yml
version: 1.0
port: 8080
host: localhost # custom domain, for development leave localhost
scheme: http # http or https
title: Mailio Server
description: Mailio Server implementation based on mirs.mail.io specification
swagger: true
mode: debug # "debug": or "release"

couchdb:
  host: localhost
  port: 5984
  scheme: http
  username: admin
  password: admin

awssmtp:
  username: test
  password: test
```
3. `swag init --parseDependency=true` to re-create documentation
4. `go run environment.go main.go` to run the app