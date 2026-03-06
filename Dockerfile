# ---------------------------------------------------------
# Multi-stage Dockerfile for servicenow-mcp SSE server
# ---------------------------------------------------------
# Stage 1: build (install deps into a venv)
# Stage 2: runtime (slim image, non-root user)
# ---------------------------------------------------------

# ---- Build stage ----
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build deps
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
COPY config/ ./config/

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir .

# ---- Runtime stage ----
FROM python:3.11-slim AS runtime

# Security: run as non-root
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv

# Copy config directory (tool_packages.yaml)
COPY config/ /app/config/

# Make sure the venv binaries are on PATH
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Switch to non-root user
USER appuser

EXPOSE 8080

# Health check — Docker will mark the container unhealthy if this fails
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

CMD ["servicenow-mcp-sse", "--host=0.0.0.0", "--port=8080"]
