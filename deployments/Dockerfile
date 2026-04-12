FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /alert-genie ./cmd/alert-genie

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata kubectl

COPY --from=builder /alert-genie /usr/local/bin/alert-genie

RUN adduser -D -u 1000 alertgenie
USER alertgenie

EXPOSE 8080

ENTRYPOINT ["alert-genie"]
CMD ["-config", "/etc/alert-genie/config.yaml"]
