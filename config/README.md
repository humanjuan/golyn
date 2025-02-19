# `config` Directory

The `config` directory contains all the configuration files and related modules necessary to initialize and manage the Golyn server, including server settings, site-specific configurations, and logging utilities.

---

## Purpose

The `config` directory serves as a centralized location for managing server and site configurations. Its main functionalities include:

- **Global Server Settings:** These are defined in `web_server.conf` within the `server/` directory and include database, cache, and server-related parameters.
- **Site-Specific Configurations:** Individual configuration files for each site (located in the `sites/` directory) define domain settings, directory paths, and security policies.
- **Dynamic Configuration Loading:** The `loaders/config.go` script dynamically loads configurations based on the `.conf` files and validates them.
- **Logging Configuration:** Handled by `setting_log_file.go`, which sets up application and database logs, ensuring proper log rotation and formatting.

---

## Contents

### **`loaders/` Directory**
- **`config.go`**: Loads and validates server and site configurations defined in `.conf` files.
- **`setting_log_file.go`**: Initializes and manages application and database log files.

### **`server/` Directory**

- **`web_server.conf`**: Central configuration file for the server.
    - `[database]`: Includes database connection details such as username, password, host, and port.
    - `[server]`: Defines general server settings, such as the port, timeouts, and JWT token policies.
    - `[sites]`: Maps each site to its corresponding configuration file in the `sites/` directory.
    - `[cache]`: Cache expiration and cleanup intervals.
    - `[log]`: Logging levels, file paths, and rotation limits.

### **`sites/` Directory**

Contains `.conf` files for individual sites hosted on the server. Each configuration file specifies: domain names, static file paths for serving assets, JavaScript, and styles, security settings (e.g., CORS policies, HTTPS redirection).


- **`golyn.conf`**: Default site for the Golyn application. Includes domains such as [`humanjuan.com`](https://www.humanjuan.com)
    and [`golyn.local`](https://www.humanjuan.com).
- **`kayak.conf`**: Example configuration for the "kayak" site, including its assets, domains, and CORS policies.
- **`portal.golyn.conf`**: Example configuration for the "portal.golyn" site, with its own domain routes and settings.

---

## Notes

- If configurations are invalid or missing, the server startup process may fail. Always validate the `.conf` files.
- Ensure directories specified in configurations (e.g., site root paths, static file paths) exist and are accessible.

---