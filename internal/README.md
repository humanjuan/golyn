# `internal` Directory

El directorio `internal` encapsula toda la lógica interna del proyecto. Aquí se encuentran controladores, utilidades, gestión de TLS y apagado del servidor. Estos componentes están diseñados para soportar las funcionalidades centrales de la aplicación de manera modular y reutilizable.

---

## Contents

### **`handlers/` Directory**
Controllers that handle incoming requests:
- **`countries.go`**: Returns a list of countries from the database.
- **`error_handler.go`**: Manages custom error pages for different routes.
- **`health_handler.go`**: Simple endpoint (`/ping`) to verify system status.
- **`logs_handler.go`**: Provides access to system logs with pagination and filtering.
- **`server_info.go`**: Returns server information like statistics, version, and TLS details.
- 
### **`utils/` Directory**
Helpers for common tasks:
- **`file_utils.go`**: Checks the existence of files/directories and retrieves the executable's base path.
- **`http_utils.go`**: Maps HTTP codes to descriptive messages.
- **`log_utils.go`**: Methods for analyzing and processing logs (e.g., validate format and timestamp).
- **`network_utils.go`**: Retrieves network info like public and private IP addresses.
- **`tls_utils.go`**: Determines the TLS version used in a connection.

### **`shutdown.go`**
Manages graceful shutdown for HTTP and HTTPS servers upon signals like `SIGINT` or `SIGTERM`.

### **`server.go`**

- Sets up the HTTPS server with certificates.
- Configures HTTP to HTTPS redirection.


---