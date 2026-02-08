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
    echo "  add-user <site_key> <user> <password> [role] [is_global] [is_external]  Add a user (role defaults to 'user', is_global to 'true', is_external to 'false')"
    echo "  add-user global <user> <password> [role] [is_external]                  Add a global user without a primary site"
    echo "  del-user <user>                 Delete a user"
    echo "  list                            List all sites and users"
    echo ""
    echo "Note: If the password doesn't start with \$2a\$, it will be hashed with bcrypt automatically."
    echo "Roles can be: SuperAdmin, Admin, user (default)"
    echo "is_global can be: true (default), false"
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
        if [ -z "$2" ]; then
            usage
            exit 1
        fi
        
        # Check if first param is "global" or a site key
        if [ "$2" == "global" ]; then
            if [ -z "$3" ] || [ -z "$4" ]; then
                usage
                exit 1
            fi
            SITE_KEY=""
            USER="$3"
            PASS="$4"
            ROLE="${5:-user}"
            IS_GLOBAL="true"
            IS_EXTERNAL="${6:-false}"
        else
            if [ -z "$3" ] || [ -z "$4" ]; then
                usage
                exit 1
            fi
            SITE_KEY="$2"
            USER="$3"
            PASS="$4"
            ROLE="${5:-user}"
            IS_GLOBAL="${6:-true}"
            IS_EXTERNAL="${7:-false}"
        fi

        # If it doesn't look like a bcrypt hash, hash it
        if [[ ! "$PASS" =~ ^\$2[ayb]\$.* ]]; then
            info "Hashing password..."
            PASS=$(hash_password "$PASS")
        fi

        if [ -z "$SITE_KEY" ]; then
            info "Adding global user $USER with role $ROLE (External: $IS_EXTERNAL)"
            run_sql "INSERT INTO auth.users (site_id, username, password_hash, role, is_global, is_external) VALUES (NULL, '$USER', '$PASS', '$ROLE', 'true', '$IS_EXTERNAL');"
        else
            info "Adding user $USER to site $SITE_KEY with role $ROLE (Global: $IS_GLOBAL, External: $IS_EXTERNAL)"
            SITE_ID=$(docker exec -i "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT id FROM core.sites WHERE key = '$SITE_KEY';" | xargs)
            if [ -z "$SITE_ID" ]; then
                error "Site key '$SITE_KEY' not found"
            fi
            run_sql "INSERT INTO auth.users (site_id, username, password_hash, role, is_global, is_external) VALUES ('$SITE_ID', '$USER', '$PASS', '$ROLE', '$IS_GLOBAL', '$IS_EXTERNAL');"
        fi
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
        run_sql "SELECT u.username, COALESCE(s.key, 'GLOBAL') as site_key, u.status, u.is_global FROM auth.users u LEFT JOIN core.sites s ON u.site_id = s.id;"
        ;;
    *)
        usage
        exit 1
        ;;
esac

# ./manage_clients.sh list: Muestra un resumen de todos los sitios y usuarios actuales.
# ./manage_clients.sh add-site <identificador> <dominio>: Registra un nuevo sitio (ej: add-site empresa-a empresa-a.com).
# ./manage_clients.sh add-user <sitio> <email> <hash>|<pass>: Crea un usuario vinculado a un sitio. Requiere el hash Bcrypt de la password.
# ./manage_clients.sh add-user <site_key> <usuario> <password> <rol> <is_global>
# ./manage_clients.sh del-site <identificador>: Elimina un sitio y, automáticamente, a todos sus usuarios asociados.