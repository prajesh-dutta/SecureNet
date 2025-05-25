#!/bin/bash

# SecureNet SOC Platform Deployment Script
# This script deploys the complete SecureNet cybersecurity dashboard platform
# with all production configurations, monitoring, and security hardening

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_ROOT/docker-compose.env"
BACKUP_DIR="$PROJECT_ROOT/backups"
LOG_FILE="$PROJECT_ROOT/deployment.log"

# Default values
ENVIRONMENT="production"
DOMAIN="securenet.local"
ENABLE_MONITORING="true"
ENABLE_ELK="false"
BACKUP_ENABLED="true"
SSL_ENABLED="false"

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        WARN)
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        DEBUG)
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Print banner
print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    _____ ______ _____ _    _ _____  ______ _   _ ______ _______ 
   / ____|  ____/ ____| |  | |  __ \|  ____| \ | |  ____|__   __|
  | (___ | |__ | |    | |  | | |__) | |__  |  \| | |__     | |   
   \___ \|  __|| |    | |  | |  _  /|  __| | . ` |  __|    | |   
   ____) | |___| |____| |__| | | \ \| |____| |\  | |____   | |   
  |_____/|______\_____|\____/|_|  \_\______|_| \_|______|  |_|   
                                                                  
        SecureNet SOC Platform - Production Deployment
EOF
    echo -e "${NC}"
}

# Check prerequisites
check_prerequisites() {
    log INFO "Checking deployment prerequisites..."
    
    local missing_tools=()
    
    # Check for required tools
    for tool in docker docker-compose git openssl curl; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log ERROR "Missing required tools: ${missing_tools[*]}"
        log ERROR "Please install the missing tools and try again"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log ERROR "Docker daemon is not running"
        exit 1
    fi
    
    # Check available disk space (minimum 10GB)
    local available_space=$(df "$PROJECT_ROOT" | awk 'NR==2 {print $4}')
    local required_space=10485760  # 10GB in KB
    
    if [ "$available_space" -lt "$required_space" ]; then
        log WARN "Available disk space is less than 10GB. Continue? (y/N)"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    log INFO "Prerequisites check completed successfully"
}

# Setup environment configuration
setup_environment() {
    log INFO "Setting up environment configuration..."
    
    if [ ! -f "$ENV_FILE" ]; then
        log INFO "Creating environment configuration from template..."
        cp "$PROJECT_ROOT/docker-compose.env.template" "$ENV_FILE" 2>/dev/null || {
            log ERROR "Environment template file not found"
            exit 1
        }
    fi
    
    # Generate secure secrets if not already set
    if ! grep -q "SECRET_KEY=.*[a-zA-Z0-9]" "$ENV_FILE"; then
        local secret_key=$(openssl rand -hex 32)
        sed -i "s/SECRET_KEY=.*/SECRET_KEY=$secret_key/" "$ENV_FILE"
        log INFO "Generated new Flask secret key"
    fi
    
    if ! grep -q "JWT_SECRET_KEY=.*[a-zA-Z0-9]" "$ENV_FILE"; then
        local jwt_secret=$(openssl rand -hex 32)
        sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$jwt_secret/" "$ENV_FILE"
        log INFO "Generated new JWT secret key"
    fi
    
    # Generate database passwords
    if ! grep -q "POSTGRES_PASSWORD=.*[a-zA-Z0-9]" "$ENV_FILE"; then
        local db_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$db_password/" "$ENV_FILE"
        log INFO "Generated new database password"
    fi
    
    # Set domain
    sed -i "s/DOMAIN=.*/DOMAIN=$DOMAIN/" "$ENV_FILE"
    
    log INFO "Environment configuration completed"
}

# Setup SSL certificates
setup_ssl() {
    if [ "$SSL_ENABLED" = "true" ]; then
        log INFO "Setting up SSL certificates..."
        
        local ssl_dir="$PROJECT_ROOT/nginx/ssl"
        mkdir -p "$ssl_dir"
        
        if [ ! -f "$ssl_dir/securenet.crt" ]; then
            log INFO "Generating self-signed SSL certificate..."
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "$ssl_dir/securenet.key" \
                -out "$ssl_dir/securenet.crt" \
                -subj "/C=US/ST=State/L=City/O=SecureNet/CN=$DOMAIN"
            
            # Generate Diffie-Hellman parameters
            openssl dhparam -out "$ssl_dir/dhparam.pem" 2048
            
            log INFO "SSL certificates generated successfully"
        else
            log INFO "SSL certificates already exist"
        fi
    fi
}

# Create necessary directories
create_directories() {
    log INFO "Creating necessary directories..."
    
    local directories=(
        "$BACKUP_DIR"
        "$PROJECT_ROOT/logs"
        "$PROJECT_ROOT/data/postgres"
        "$PROJECT_ROOT/data/redis"
        "$PROJECT_ROOT/nginx/logs"
        "$PROJECT_ROOT/monitoring/prometheus/data"
        "$PROJECT_ROOT/monitoring/grafana/data"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        log DEBUG "Created directory: $dir"
    done
    
    # Set appropriate permissions
    chmod 755 "$PROJECT_ROOT/logs"
    chmod 700 "$PROJECT_ROOT/data"
    
    log INFO "Directory structure created"
}

# Build Docker images
build_images() {
    log INFO "Building Docker images..."
    
    cd "$PROJECT_ROOT"
    
    # Build the main application image
    log INFO "Building SecureNet application image..."
    docker-compose build --no-cache
    
    # Pull required images
    log INFO "Pulling required Docker images..."
    docker-compose pull
    
    log INFO "Docker images built successfully"
}

# Initialize database
initialize_database() {
    log INFO "Initializing database..."
    
    cd "$PROJECT_ROOT"
    
    # Start only the database service
    docker-compose up -d postgres redis
    
    # Wait for database to be ready
    log INFO "Waiting for database to be ready..."
    sleep 10
    
    local retry_count=0
    local max_retries=30
    
    while [ $retry_count -lt $max_retries ]; do
        if docker-compose exec -T postgres pg_isready -U postgres &> /dev/null; then
            log INFO "Database is ready"
            break
        fi
        
        retry_count=$((retry_count + 1))
        log DEBUG "Database not ready, retrying ($retry_count/$max_retries)..."
        sleep 2
    done
    
    if [ $retry_count -eq $max_retries ]; then
        log ERROR "Database failed to start within expected time"
        exit 1
    fi
    
    # Run database initialization script
    log INFO "Running database initialization..."
    docker-compose exec -T securenet-backend python /app/scripts/init_production_database.py
    
    log INFO "Database initialization completed"
}

# Deploy monitoring stack
deploy_monitoring() {
    if [ "$ENABLE_MONITORING" = "true" ]; then
        log INFO "Deploying monitoring stack..."
        
        # Create monitoring configuration
        cat > "$PROJECT_ROOT/monitoring/prometheus/prometheus.yml" << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'securenet-backend'
    static_configs:
      - targets: ['securenet-backend:5000']
    metrics_path: '/metrics'

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx:80']

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
EOF
        
        # Create alert rules
        cat > "$PROJECT_ROOT/monitoring/prometheus/alert_rules.yml" << EOF
groups:
  - name: securenet_alerts
    rules:
      - alert: HighCPUUsage
        expr: rate(cpu_usage_total[5m]) > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage is above 80% for more than 5 minutes"

      - alert: HighMemoryUsage
        expr: memory_usage_percent > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is above 85% for more than 5 minutes"

      - alert: ServiceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service is down"
          description: "{{ \$labels.instance }} of job {{ \$labels.job }} has been down for more than 1 minute"

      - alert: HighThreatDetections
        expr: rate(threat_detections_total[5m]) > 10
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High rate of threat detections"
          description: "More than 10 threats detected per minute for 2 minutes"
EOF
        
        log INFO "Monitoring stack configuration created"
    fi
}

# Start services
start_services() {
    log INFO "Starting SecureNet services..."
    
    cd "$PROJECT_ROOT"
    
    # Create final docker-compose command
    local compose_files="-f docker-compose.yml"
    
    if [ "$ENABLE_MONITORING" = "true" ]; then
        compose_files="$compose_files -f docker-compose.monitoring.yml"
    fi
    
    if [ "$ENABLE_ELK" = "true" ]; then
        compose_files="$compose_files -f docker-compose.elk.yml"
    fi
    
    # Start all services
    eval "docker-compose $compose_files up -d"
    
    log INFO "Services started successfully"
}

# Health checks
run_health_checks() {
    log INFO "Running health checks..."
    
    local services=(
        "nginx:80:/health"
        "securenet-backend:5000/api/health"
        "securenet-frontend:3000"
    )
    
    for service in "${services[@]}"; do
        local host_port=$(echo "$service" | cut -d: -f1-2)
        local path=$(echo "$service" | cut -d: -f3)
        
        local retry_count=0
        local max_retries=30
        
        while [ $retry_count -lt $max_retries ]; do
            if curl -f "http://$host_port$path" &> /dev/null; then
                log INFO "✓ $host_port$path is healthy"
                break
            fi
            
            retry_count=$((retry_count + 1))
            log DEBUG "Health check failed for $host_port$path, retrying ($retry_count/$max_retries)..."
            sleep 2
        done
        
        if [ $retry_count -eq $max_retries ]; then
            log WARN "Health check failed for $host_port$path"
        fi
    done
    
    log INFO "Health checks completed"
}

# Setup backup
setup_backup() {
    if [ "$BACKUP_ENABLED" = "true" ]; then
        log INFO "Setting up backup system..."
        
        # Create backup script
        cat > "$PROJECT_ROOT/scripts/backup.sh" << 'EOF'
#!/bin/bash

BACKUP_DIR="/app/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="securenet_backup_$TIMESTAMP.sql"

# Create database backup
docker-compose exec -T postgres pg_dump -U postgres securenet > "$BACKUP_DIR/$BACKUP_FILE"

# Compress backup
gzip "$BACKUP_DIR/$BACKUP_FILE"

# Keep only last 7 days of backups
find "$BACKUP_DIR" -name "securenet_backup_*.sql.gz" -type f -mtime +7 -delete

echo "Backup completed: $BACKUP_FILE.gz"
EOF
        
        chmod +x "$PROJECT_ROOT/scripts/backup.sh"
        
        # Create cron job for daily backups
        (crontab -l 2>/dev/null; echo "0 2 * * * $PROJECT_ROOT/scripts/backup.sh") | crontab -
        
        log INFO "Backup system configured with daily automated backups"
    fi
}

# Print deployment summary
print_summary() {
    log INFO "Deployment completed successfully!"
    
    cat << EOF

${GREEN}=== SecureNet SOC Platform Deployment Summary ===${NC}

${BLUE}Application URLs:${NC}
  - Web Interface: http://$DOMAIN
  - API Endpoint: http://$DOMAIN/api
  - Health Check: http://$DOMAIN/health

${BLUE}Default Credentials:${NC}
  - Username: admin
  - Password: Check deployment logs or environment file

${BLUE}Services Status:${NC}
$(docker-compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}")

${BLUE}Monitoring:${NC}
$(if [ "$ENABLE_MONITORING" = "true" ]; then
    echo "  - Prometheus: http://$DOMAIN:9090"
    echo "  - Grafana: http://$DOMAIN:3001 (admin/admin)"
    echo "  - Alert Manager: http://$DOMAIN:9093"
else
    echo "  - Monitoring: Disabled"
fi)

${BLUE}Logs:${NC}
  - Application Logs: docker-compose logs -f
  - Deployment Log: $LOG_FILE
  - Nginx Logs: $PROJECT_ROOT/nginx/logs/

${BLUE}Configuration:${NC}
  - Environment: $ENV_FILE
  - Nginx Config: $PROJECT_ROOT/nginx/securenet.conf
  - Data Directory: $PROJECT_ROOT/data/

${BLUE}Backup:${NC}
$(if [ "$BACKUP_ENABLED" = "true" ]; then
    echo "  - Backup Directory: $BACKUP_DIR"
    echo "  - Backup Schedule: Daily at 2:00 AM"
    echo "  - Manual Backup: $PROJECT_ROOT/scripts/backup.sh"
else
    echo "  - Backup: Disabled"
fi)

${YELLOW}Next Steps:${NC}
1. Change default admin password
2. Configure external API keys in $ENV_FILE
3. Set up SSL certificates for production
4. Configure email/SMS alerts
5. Review and customize security rules

${GREEN}SecureNet SOC Platform is ready for use!${NC}

EOF
}

# Cleanup function for script interruption
cleanup() {
    log WARN "Deployment interrupted. Cleaning up..."
    docker-compose down 2>/dev/null || true
    exit 1
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --enable-ssl)
                SSL_ENABLED="true"
                shift
                ;;
            --disable-monitoring)
                ENABLE_MONITORING="false"
                shift
                ;;
            --enable-elk)
                ENABLE_ELK="true"
                shift
                ;;
            --disable-backup)
                BACKUP_ENABLED="false"
                shift
                ;;
            --help)
                cat << EOF
SecureNet SOC Platform Deployment Script

Usage: $0 [OPTIONS]

Options:
  --environment ENV       Set deployment environment (default: production)
  --domain DOMAIN         Set domain name (default: securenet.local)
  --enable-ssl           Enable SSL/TLS with self-signed certificates
  --disable-monitoring   Disable Prometheus/Grafana monitoring
  --enable-elk           Enable ELK stack for log analysis
  --disable-backup       Disable automated backup system
  --help                 Show this help message

Examples:
  $0                                          # Basic deployment
  $0 --domain mycompany.com --enable-ssl      # Production with SSL
  $0 --enable-elk --domain securenet.local   # With ELK stack

EOF
                exit 0
                ;;
            *)
                log ERROR "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# Main deployment function
main() {
    # Set up signal handlers
    trap cleanup SIGINT SIGTERM
    
    # Parse arguments
    parse_arguments "$@"
    
    # Initialize log file
    echo "SecureNet SOC Platform Deployment Started at $(date)" > "$LOG_FILE"
    
    print_banner
    
    log INFO "Starting SecureNet SOC Platform deployment..."
    log INFO "Environment: $ENVIRONMENT"
    log INFO "Domain: $DOMAIN"
    log INFO "SSL Enabled: $SSL_ENABLED"
    log INFO "Monitoring Enabled: $ENABLE_MONITORING"
    log INFO "ELK Stack Enabled: $ENABLE_ELK"
    log INFO "Backup Enabled: $BACKUP_ENABLED"
    
    # Run deployment steps
    check_prerequisites
    setup_environment
    setup_ssl
    create_directories
    build_images
    initialize_database
    deploy_monitoring
    start_services
    run_health_checks
    setup_backup
    
    print_summary
    
    log INFO "SecureNet SOC Platform deployment completed successfully!"
}

# Execute main function
main "$@"
