FROM golang:1.24-alpine AS builder

# Install OpenTelemetry Collector Builder
RUN go install go.opentelemetry.io/collector/cmd/builder@latest

WORKDIR /build

# Copy builder config first
COPY otel-collector/builder-config.yaml /build/

# Copy the entire vercelreceiver project
COPY . /src/vercelreceiver/

# Update the path in builder config for Docker
RUN sed -i 's|path: ../|path: /src/vercelreceiver|g' builder-config.yaml

# Build the custom collector using local source
RUN builder --config=builder-config.yaml

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /otelcol

# Copy the built collector
COPY --from=builder /build/dist/otelcol-vercel /otelcol/otelcol-vercel

# Copy collector configuration
COPY otel-collector/config.yaml /otelcol/config.yaml

# Expose the collector port
EXPOSE 8081

# Run the collector
ENTRYPOINT ["/otelcol/otelcol-vercel", "--config=/otelcol/config.yaml"]

