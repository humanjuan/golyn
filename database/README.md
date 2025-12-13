# `database` Directory

The `database` directory provides the core database interaction functionality for the project. It includes utilities for database connection, query execution, and ORM-like functionality for mapping database rows to Go structures.

## Files

### 1. `database.go`
This file implements advanced database query execution. It features functions for running custom SQL queries and mapping the resulting rows into Go structures. 

### 2. `instance.go`
Defines the logic for initializing and managing the database instance, including:
- Initializing a connection to the database using credentials and settings from the configuration (`config.Config`).
- Closing the database connection when it's no longer needed.
- Validating the database connection via ping and retrieving metadata such as the database version.

This file uses `pgxpool` for connection pooling and relies on structured logging with the `github.com/humanjuan/acacia` package.

### 3. `queries.go`
Contains pre-defined SQL queries and data structures for mapping query results. It includes:
- SQL query strings for operations like user login and fetching countries.
- Data models which are used to map database rows to Go structs, using `db` struct tags for field mapping.

This file centralizes queries for reusability, reducing redundancy in the codebase.

### 4. `token_repository.go`
Provides functionality for handling refresh tokens in the database. This involves:
- Storing refresh tokens securely in the database.
- Validating and retrieving tokens based on their value.
- Revoking tokens for a specific user when needed.
- 
---
