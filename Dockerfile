# SecureNet Enterprise SOC Platform - Production Dockerfile
# Multi-stage build for optimized production deployment

# Stage 1: Python Backend Build
FROM python:3.11-slim-bullseye as backend-builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies required for security tools
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    libffi-dev \
    libssl-dev \
    nmap \
    tcpdump \
    net-tools \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app/backend

# Copy requirements and install Python dependencies
COPY flask_backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Node.js Frontend Build
FROM node:18-alpine as frontend-builder

WORKDIR /app/frontend

# Copy package files
COPY client/package*.json ./
RUN npm ci --only=production

# Copy source code and build
COPY client/ .
RUN npm run build

# Stage 3: Production Runtime
FROM python:3.11-slim-bullseye as production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    GUNICORN_WORKERS=4 \
    GUNICORN_THREADS=2 \
    GUNICORN_TIMEOUT=300

# Install runtime system dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    nmap \
    tcpdump \
    net-tools \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r securenet \
    && useradd -r -g securenet securenet

# Set work directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=backend-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=backend-builder /usr/local/bin /usr/local/bin

# Copy built frontend
COPY --from=frontend-builder /app/frontend/dist /app/static

# Copy backend application
COPY flask_backend/ /app/backend/
COPY scripts/ /app/scripts/

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/backups /app/uploads \
    && chown -R securenet:securenet /app

# Copy configuration files
COPY flask_backend/.env.template /app/backend/.env.template
COPY flask_backend/config.py /app/backend/config.py

# Create startup script
RUN echo '#!/bin/bash\n\
cd /app/backend\n\
python init_database.py\n\
exec gunicorn --workers $GUNICORN_WORKERS \\\n\
              --threads $GUNICORN_THREADS \\\n\
              --timeout $GUNICORN_TIMEOUT \\\n\
              --bind 0.0.0.0:5001 \\\n\
              --worker-class eventlet \\\n\
              --worker-connections 1000 \\\n\
              --max-requests 10000 \\\n\
              --max-requests-jitter 1000 \\\n\
              --preload \\\n\
              --access-logfile /app/logs/access.log \\\n\
              --error-logfile /app/logs/error.log \\\n\
              --log-level info \\\n\
              "app:create_app()"' > /app/start.sh \
    && chmod +x /app/start.sh \
    && chown securenet:securenet /app/start.sh

# Switch to non-root user
USER securenet

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5001/api/status || exit 1

# Expose port
EXPOSE 5001

# Set working directory to backend
WORKDIR /app/backend

# Start the application
CMD ["/app/start.sh"]