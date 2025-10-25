FROM golang:1.24-bookworm AS build

WORKDIR /registrar

COPY go.* .
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-w -s" -o registrar github.com/storacha/delegator

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /registrar/registrar /usr/bin/

EXPOSE 8080

ENTRYPOINT ["/usr/bin/registrar"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
