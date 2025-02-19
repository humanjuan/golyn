# `docker` Directory

This directory contains all the necessary configurations, scripts, and files required for setting up the PostgreSQL database environment in a docker container. This database is used to store the entire content of my personal portfolio. 
Although it is not required for hosting a standard website, it is an essential component to manage my portfolio content and configurations effectively.
## Purpose

This database serves a very specific purpose: to host and manage the content of my personal portfolio and its content management system. It plays a pivotal role in my portfolio as a dynamic and efficient backend, enabling:
- Organized management of portfolio projects, posts, or other structured content.
- Dynamic capabilities like managing updates, edits, and custom functionalities.
- A full-fledged system tailored for showcasing and maintaining my portfolio professionally.

While this setup isn't a prerequisite for hosting a standard static website, it is indispensable for the proper functioning of my own portfolio.

## Contents

1. **`db/manage_db.sh`**: A shell script to manage the lifecycle of the PostgreSQL container. It provides commands to build, start, stop, restart, delete the container, clean persistent data, and access the PostgreSQL CLI.

2. **`db/postgresql/Dockerfile`**: The Dockerfile defines the steps to create the PostgreSQL container with preconfigured settings and initialization scripts.

3. **`db/postgresql/sql/`**:
    - **`01-init-db.sql`**: Initializes the database, user, schema, and extensions required for the application.
    - **`02-tables.sql`**: Defines and creates the database tables, along with comments and permissions.
    - **`03-load-data.sql`**: Seeds the database with initial data, such as a list of countries.

4. **`db/postgresql/sh/`**: A directory intended for additional shell scripts that might be used for further database configurations or administration.

5. **`db/postgresql/versions.txt`**: Contains versioning information or metadata for the PostgreSQL database environment.

## Usage

1. **Build the PostgreSQL Docker Image**:
   ```bash
   ./manage_db.sh build
   ```

2. **Start the PostgreSQL Container**:
   ```bash
   ./manage_db.sh start
   ```

3. **Access the PostgreSQL CLI**:
   ```bash
   ./manage_db.sh cli
   ```

4. **Stop the PostgreSQL Container**:
   ```bash
   ./manage_db.sh stop
   ```

5. **Delete the Container and Cleanup Data**:
   ```bash
   ./manage_db.sh delete
   ```

## Notes

- Ensure Docker is properly installed and running on your machine.
- Modify the `Dockerfile` or SQL files as needed for custom database initialization.
- Data persistence is managed using Docker volumes. To reset the data, use the `clean` or `delete` commands via the `manage_db.sh` script.
- By default, PostgreSQL is configured with the following credentials:
    - **User**: `root`
    - **Password**: `P4ss.R00t`
    - **Database**: `golyn`
      You can modify these values in the `Dockerfile` or environment variables.

## PostgreSQL Initialization Details

The database initialization process includes:
1. Setting up the **golyn** schema with necessary extensions (`uuid-ossp`, `pgcrypto`).
2. Creating and assigning privileges to a database user `dev`.
3. Creating tables for users, countries, and refresh tokens.
4. Loading initial data.

Refer to the `sql/` directory for further details on schema and data definitions.
