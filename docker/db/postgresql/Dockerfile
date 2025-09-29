# Imagen Centos 7 y postgresql
# Imagen generada por Juan Perez
# Build: docker build --rm -t humanjuan/centos7-postgresql15 .
# Run: docker run -d -it -v /Users/juan/Documents/Minor_Projects/Dockers/Postgresql/sql:/docker-entrypoint-initdb.d -v /Users/juan/Documents/Minor_Projects/Dockers/Postgresql/sh:/scripts -p 5432:5432 --name PostgreSQL humanjuan/centos7-postgresql15
# Exec: docker exec -it PostgreSQL psql -U dev
# Exec: docker exec -it PostgreSQL psql -U dev -d postgres -f /docker-entrypoint-initdb.d/01-init-db.sql
# Get IP: docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' PostgreSQL

FROM postgres:15

# Set environment variables for initialization
ENV POSTGRES_USER root
ENV POSTGRES_PASSWORD P4ss.R00t
ENV POSTGRES_DB golyn

# Copy SQL files to Docker entrypoint-initdb.d directory
COPY sql/*.sql /docker-entrypoint-initdb.d/

# Ensure the SQL files have the correct permissions
RUN chmod -R 700 /docker-entrypoint-initdb.d

# Expose PostgreSQL port
EXPOSE 5432