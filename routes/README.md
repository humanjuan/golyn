# `routes` Directory

The `routes` directory defines the structure and logic for setting up HTTP routes in the application. It supports both public and private APIs, as well as virtual host configurations for serving static files and handling domain-specific requests.

---


---

## Contents

- **`routes.go`**:
    - Serves as the entry point for route configuration.
    - Registers all available routes across API versions and applies middlewares.
    - Ensures distinction between public and private routes, with private routes requiring authentication.

- **`handler.go`**:
    - Provides helper functions for creating dynamic route handlers.
    - Handles secure file serving and validates file extensions and directories.

### **`api` Subdirectories (`api/v1` and `api/v2`)**
- Contains versioned route files to organize public and private APIs.

  #### Key Files:
    - **`public_routes.go`**:
        - Registers routes accessible to the public without authentication.
        - Examples include health checks (`/ping`) and user login (`/login`).
    - **`private_routes.go`**:
        - Registers routes accessible only to authenticated users.
        - Example includes data retrieval endpoints like `/get_countries`.

### **Virtual Hosts**
- **`virtualhosts/virtualhosts.go`**:
    - Configures virtual host routing for serving static content.
    - Associates domains with site directories and sets up routes for assets, styles, and JavaScript files.
    - Serves default files (e.g., `index.html`, `favicon.ico`) for each virtual host.

---

## Purpose

The `routes` package is designed to:
1. Centralize the HTTP routing logic for the application.
2. Distinguish between public and private APIs to manage access control.
3. Provide dynamic routing capabilities for serving static files and handling virtual hosts.

---