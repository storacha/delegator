# Build stage - use native platform for faster cross-compilation
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build

ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src

# Copy dependency files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with cross-compilation and stripped binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /app github.com/storacha/delegator

FROM alpine:latest AS prod

USER nobody

# Copy binary from build stage
COPY --from=build /app /usr/bin/registrar

EXPOSE 8080

ENTRYPOINT ["/usr/bin/registrar"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
