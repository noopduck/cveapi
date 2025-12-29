# syntax=docker/dockerfile:1

FROM --platform=linux/amd64 golang:1.21-bullseye AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
RUN GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /bin/cveapi .

FROM --platform=linux/amd64 gcr.io/distroless/static-debian12

WORKDIR /app

COPY --from=builder /bin/cveapi /cveapi
COPY openapi.json swagger.html ./
COPY examples ./examples

ENTRYPOINT ["/cveapi"]
