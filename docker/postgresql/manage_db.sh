#!/bin/sh
set -e

# =========================================================
# Golyn - PostgreSQL Database Manager
# =========================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
CONTAINER_NAME="golyn-postgres"
VOLUME_NAME="golyn_pg_data"

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

info() {
    echo "[INFO] $1"
}

error() {
    echo "[ERROR] $1"
    exit 1
}

require_docker() {
    command -v docker >/dev/null 2>&1 || error "Docker is not installed"
}

require_compose() {
    docker compose version >/dev/null 2>&1 || error "docker compose is not available"
}

# ---------------------------------------------------------
# Actions
# ---------------------------------------------------------

build() {
    info "Building PostgreSQL image"
    docker compose -f "$COMPOSE_FILE" build
}

start() {
    info "Starting PostgreSQL container"
    docker compose -f "$COMPOSE_FILE" up -d
}

stop() {
    info "Stopping PostgreSQL container"
    docker compose -f "$COMPOSE_FILE" stop
}

restart() {
    info "Restarting PostgreSQL container"
    docker compose -f "$COMPOSE_FILE" restart
}

delete() {
    info "Stopping and removing PostgreSQL container"
    docker compose -f "$COMPOSE_FILE" down
}

clean() {
    info "WARNING: this will DELETE ALL DATABASE DATA"
    echo "Type 'yes' to continue:"
    read confirm

    if [ "$confirm" != "yes" ]; then
        info "Aborted"
        exit 0
    fi

    info "Removing PostgreSQL container and volume"
    docker compose -f "$COMPOSE_FILE" down -v
    docker volume rm "$VOLUME_NAME" 2>/dev/null || true
}

status() {
    docker ps --filter "name=$CONTAINER_NAME"
}

logs() {
    docker logs -f "$CONTAINER_NAME"
}

cli() {
    info "Opening psql shell as postgres user"
    docker exec -it "$CONTAINER_NAME" psql -U postgres
}

    cli_golyn() {
    info "Opening psql shell as golyn_user on golyn DB"
    docker exec -it "$CONTAINER_NAME" psql -U golyn_user -d golyn
}

manage_clients() {
    shift
    "$SCRIPT_DIR/manage_clients.sh" "$@"
}

# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

require_docker
require_compose

case "$1" in
    build)
        build
        ;;
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    delete)
        delete
        ;;
    clean)
        clean
        ;;
    status)
        status
        ;;
    logs)
        logs
        ;;
    cli)
        cli
        ;;
    cli-golyn)
        cli_golyn
        ;;
    clients)
        manage_clients "$@"
        ;;
    *)
        echo ""
        echo "Usage: $0 {build|start|stop|restart|delete|clean|status|logs|cli|cli-golyn|clients}"
        echo ""
        echo "Commands:"
        echo "  build       Build PostgreSQL image"
        echo "  start       Start database"
        echo "  stop        Stop database"
        echo "  restart     Restart database"
        echo "  delete      Remove container (keeps data)"
        echo "  clean       Remove container AND data volume"
        echo "  status      Show running container"
        echo "  logs        Follow PostgreSQL logs"
        echo "  cli         Open psql as postgres"
        echo "  cli-golyn   Open psql as golyn_user on golyn DB"
        echo "  clients     Manage sites and users (proxies to manage_clients.sh)"
        echo ""
        exit 1
        ;;
esac
