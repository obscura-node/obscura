# Obscura full node — static, CGO-disabled (pure-Go: RSA-2048 accumulator +
# RandomX-style VM PoW, no cgo). Used by the 4-node load test (docker-compose.yml).
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/obscura-node ./cmd/obscura-node

FROM alpine:3.20
RUN adduser -D -h /data obx
COPY --from=build /out/obscura-node /usr/local/bin/obscura-node
USER obx
WORKDIR /data
EXPOSE 18080 18081
ENTRYPOINT ["obscura-node"]
