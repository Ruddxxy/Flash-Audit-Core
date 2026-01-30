# =============================================================================
# FlashAudit Backend - Dashboard & API
# =============================================================================

FROM python:3.12-slim

LABEL org.opencontainers.image.title="FlashAudit Backend"
LABEL org.opencontainers.image.description="FlashAudit Dashboard and API Server"
LABEL org.opencontainers.image.source="https://github.com/Ruddxxy/Flash-Audit"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 flashaudit && \
    mkdir -p /app/data && \
    chown -R flashaudit:flashaudit /app

USER flashaudit

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run the application
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port $PORT"]
