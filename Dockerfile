# Build estático do dnp3mon (dependências vendorizadas: não precisa de internet para o Go)
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/dnp3mon ./cmd/dnp3mon \
 && CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/dnp3sim ./cmd/dnp3sim

FROM alpine:3.20
COPY --from=build /out/ /usr/local/bin/
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dnp3mon"]
CMD ["live"]
