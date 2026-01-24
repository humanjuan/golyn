#!/bin/bash
set -e

# =========================================================
# Golyn - Manage Clients (Sites) and Users
# =========================================================

CONTAINER_NAME="golyn-postgres"
DB_NAME="golyn"
DB_USER="golyn_user"

info() {
    echo "[INFO] $1" >&2
}

error() {
    echo "[ERROR] $1" >&2
    exit 1
}

run_sql() {
    docker exec -i "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -c "$1"
}

usage() {
    echo ""
    echo "Usage: $0 {add-site|del-site|add-user|del-user|list}"
    echo ""
    echo "Commands:"
    echo "  add-site <key> <host>           Add a new site"
    echo "  del-site <key>                  Delete a site (and all its users)"
    echo "  add-user <site_key> <user> <password> [role]  Add a user (role defaults to 'user')"
    echo "  del-user <user>                 Delete a user"
    echo "  list                            List all sites and users"
    echo ""
    echo "Note: If the password doesn't start with \$2a\$, it will be hashed with bcrypt automatically."
    echo "Roles can be: SuperAdmin, Admin, user (default)"
    echo ""
}

hash_password() {
    # Check if we are at project root or in docker/postgresql
    GOLYN_BIN="./golyn"
    if [ ! -f "$GOLYN_BIN" ]; then
        GOLYN_BIN="../../golyn"
    fi

    if [ ! -f "$GOLYN_BIN" ]; then
        # Try to build it if missing and we have go
        if command -v go >/dev/null 2>&1; then
            info "Building golyn CLI tool..."
            (cd ../.. && go build -o golyn cmd/golyn.go >&2)
            GOLYN_BIN="../../golyn"
        else
            error "golyn binary not found and 'go' is not installed to build it."
        fi
    fi

    "$GOLYN_BIN" --hash "$1"
}

case "$1" in
    add-site)
        if [ -z "$2" ] || [ -z "$3" ]; then
            usage
            exit 1
        fi
        info "Adding site: $2 ($3)"
        run_sql "INSERT INTO core.sites (key, host) VALUES ('$2', '$3');"
        ;;
    del-site)
        if [ -z "$2" ]; then
            usage
            exit 1
        fi
        info "Deleting site: $2"
        run_sql "DELETE FROM core.sites WHERE key = '$2';"
        ;;
    add-user)
        if [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
            usage
            exit 1
        fi
        
        PASS="$4"
        ROLE="${5:-user}"

        # If it doesn't look like a bcrypt hash, hash it
        if [[ ! "$PASS" =~ ^\$2[ayb]\$.* ]]; then
            info "Hashing password..."
            PASS=$(hash_password "$PASS")
        fi

        info "Adding user $3 to site $2 with role $ROLE"
        SITE_ID=$(docker exec -i "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT id FROM core.sites WHERE key = '$2';" | xargs)
        if [ -z "$SITE_ID" ]; then
            error "Site key '$2' not found"
        fi
        run_sql "INSERT INTO auth.users (site_id, username, password_hash, role) VALUES ('$SITE_ID', '$3', '$PASS', '$ROLE');"
        ;;
    del-user)
        if [ -z "$2" ]; then
            usage
            exit 1
        fi
        info "Deleting user: $2"
        run_sql "DELETE FROM auth.users WHERE username = '$2';"
        ;;
    list)
        info "=== Sites ==="
        run_sql "SELECT key, host, status FROM core.sites;"
        info "=== Users ==="
        run_sql "SELECT u.username, s.key as site_key, u.status FROM auth.users u JOIN core.sites s ON u.site_id = s.id;"
        ;;
    *)
        usage
        exit 1
        ;;
esac

# ./manage_clients.sh list: Muestra un resumen de todos los sitios y usuarios actuales.
# ./manage_clients.sh add-site <identificador> <dominio>: Registra un nuevo sitio (ej: add-site empresa-a empresa-a.com).
# ./manage_clients.sh add-user <sitio> <email> <hash>|<pass>: Crea un usuario vinculado a un sitio. Requiere el hash Bcrypt de la password.
# ./manage_clients.sh add-user <site_key> <usuario> <password> <rol>
# ./manage_clients.sh del-site <identificador>: Elimina un sitio y, automáticamente, a todos sus usuarios asociados.