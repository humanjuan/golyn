#!/bin/sh

SCRIPT_DIR=$(cd "$(dirname "$0")"; pwd)

container_name="Golyn_PostgreSQL"
image_tag="humanjuan/centos7-postgresql15"
postgresql_dir="$SCRIPT_DIR/postgresql"
volume_name="pgdata"

clean_data() {
    echo "Cleaning data directory for PostgreSQL"
    docker volume rm "$volume_name"
}

build_container() {
    if [ ! -d "$postgresql_dir" ]; then
        echo "ERROR: El directorio $postgresql_dir no existe. Verifica la ruta."
        exit 1
    fi

    echo "Building container $image_tag using directory $postgresql_dir"
    docker build --rm -t "$image_tag" "$postgresql_dir"
}

start_container() {
    if [ ! -d "$postgresql_dir" ]; then
        echo "ERROR: El directorio $postgresql_dir no existe. Verifica la ruta."
        exit 1
    fi

    echo "Starting container $image_tag"
    echo "Golyn PostgreSQL 15 - Centos 7 - Docker"
    echo "Container name: $container_name"
    docker run -d -it \
        -v "$volume_name":/var/lib/postgresql/data \
        -v "$postgresql_dir/sql":/docker-entrypoint-initdb.d \
        -v "$postgresql_dir/sh":/scripts \
        -p 5432:5432 \
        --name "$container_name" "$image_tag"

    # Esperar a que el contenedor se inicialice
    sleep 5

    # Verificación de la creación de tablas y base de datos
    echo "Verifying database and tables creation..."
    if docker exec -it "$container_name" psql -U root -d golyn -c '\dt' | grep 'No relations found.' > /dev/null; then
        echo "ERROR: The tables were not created."
        exit 1
    else
        echo "Database and tables created successfully."
    fi

    docker ps -a
}

stop_container() {
    echo "Stopping $container_name container"
    container_id=$(docker ps -a | grep "$container_name" | awk '{print $1}')

    if [ -n "$container_id" ]; then
        docker stop "$container_id"
        docker rm "$container_id"
        echo "Container $container_name stopped successfully: $container_id"
    else
        echo "$container_name container not found."
    fi
}

delete_container() {
    echo "Deleting $container_name container and data volume"
    stop_container
    clean_data
    echo "Container and data volume deleted successfully."
}

restart_container() {
    stop_container
    start_container
}

exec_cli() {
    echo "Entering PostgreSQL CLI for container $container_name"
    docker exec -it "$container_name" psql -U root -d golyn
}

case "$1" in
    clean)
        clean_data
        ;;
    build)
        build_container
        ;;
    start)
        start_container
        ;;
    stop)
        stop_container
        ;;
    restart)
        restart_container
        ;;
    cli)
        exec_cli
        ;;
    delete)
        delete_container
        ;;
    *)
        echo "Usage: $0 {clean|build|start|stop|restart|cli|delete}"
        exit 1
        ;;
esac