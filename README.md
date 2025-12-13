<h1 align="center">
  Golyn <img src="https://github.com/humanjuan/golyn/blob/main/sites/golyn/assets/Golyn.png?raw=true" alt="Golyn Logo" width="80"> Server
</h1>

![Golang](https://img.shields.io/badge/Language-Go-blue?logo=go)
![Open Source](https://img.shields.io/badge/Open%20Source-Yes-brightgreen?logo=opensourceinitiative)
![Status](https://img.shields.io/badge/Status-In%20Development-orange?logo=githubactions)
![Go Version](https://img.shields.io/badge/Go-v1.25.0-blue?logo=go)
[![Gin Version](https://img.shields.io/badge/Gin%20Framework-v1.10.0-lightblue)](https://github.com/gin-gonic/gin)
[![Logger](https://img.shields.io/badge/Acacia-v2-lightblue)](https://github.com/humanjuan/acacia)

[![Buy Me a Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-Support-orange?logo=buy-me-a-coffee&style=flat-square)](https://www.buymeacoffee.com/humanjuan)

## Golyn Server

The **Golyn Server** is a custom-built, multi-site web server designed to host and manage multiple websites efficiently. The primary purpose of this project is to host my **personal portfolio**, while also supporting additional websites thanks to its robust multi-site capabilities.

This server is currently **under active development** and continues to expand with new features and optimizations.

---

## Features

### Hosting Your Portfolio
- The server is primarily designed to **host and serve my personal portfolio** and its dedicated administration panel. However, it also includes a **multi-site architecture**, allowing it to manage and host any additional websites, providing flexibility to support a variety of projects or domains under the same infrastructure.

### Multi-Site Hosting
- Golyn Server is designed to handle multiple sites simultaneously. Each site is configurable and isolated, making it suitable for various use cases such as personal projects, portfolios, or other hosted websites.
- Configurations for each site are stored in dedicated files, enabling granular control over site-specific settings like domains, paths, proxy settings, SMTP, and security policies.
- Built-in support for multiple domains and subdomains with individual TLS/SSL certificate management.

### Secure and Configurable
- Flexible configuration through `.conf` files for server-level and site-specific settings.
- Security settings, including HTTPS redirection and cross-origin resource sharing (CORS) policies, ensure your sites remain protected and accessible.
- CSRF Protection: Built-in CSRF token generation and validation for forms and API endpoints.
- Email Rate Limiting: Configurable request rate limiting per site and for email services.
- TLS/SSL Management:
    - Per-domain SSL certificate handling
    - Automatic certificate validation and expiration checking
    - Fallback mechanisms for invalid certificates

### SMTP Email Support
- Integrated SMTP support for sending emails through the specific endpoint.
- Each site can configure its own SMTP settings (host, port, user, password) via the site-specific `.conf` file.
- SMTP passwords are encrypted and stored securely using a CLI tool for key generation and encryption.

### Reverse Proxy
- Includes reverse proxy capabilities to forward requests to other servers or services.
- Configurable via the site-specific `.conf` files to define proxy rules, such as forwarding specific routes to backend services or external APIs.
- Supports secure proxying with HTTPS and configurable headers for enhanced flexibility.

### Performance Optimization
- Advanced Compression:
    - Brotli, deflate, Zstandard and Gzip compression support
    - Content-Type aware compression
    - Automatic selection of the best compression method based on client support
- Caching System:
    - Server-side file caching
    - Cache validation
    - Configurable cache expiration
- Content Delivery:
    - Optimized MIME type handling
    - Smart content encoding selection
    - Efficient static file serving

### SEO and Metadata Support
- Built-in endpoints for SEO essentials:
    - `robots.txt` handling
    - `sitemap.xml` generation
    - `humans.txt` support
- Content-Type optimization for XML and text files
- Automated metadata handling

### Extensible Architecture
- Built with modularity in mind, making it easy to add features or scale the server as required.
- Supports logging, caching, JWT authentication (planned), and asset management for scalability and performance.

### Built with Go
The server is developed in **Golang** and, as part of its architecture, uses the following components:

- **[Gin framework](https://github.com/gin-gonic/gin)**: A high-performance HTTP web framework designed for building modular and fast applications.
- **[Logger](https://github.com/humanjuan/acacia)**: A custom logging library developed for advanced and highly configurable logging capabilities.
- **AES-GCM Encryption**: For sensitive configuration data
- **Custom Middleware Stack**: For security, compression, and routing

---

## Project Status

🚧 **Under Development** 🚧  
This project is still a **work in progress**

Even though the server is still under development, it is fully functional for its primary purpose. If you install the server and configure your site correctly, you will be able to serve it without issues. This includes the ability to properly view your website's content through browsers, supporting secure communication over HTTPS if configured with the necessary certificates.

---

## How It Works

The Golyn Server operates as a centralized, multi-site server. Each site's settings are configured separately using `.conf` files, which are loaded dynamically at runtime.

### Directory Structure

- [config](./config): Configuration files for sites and the server.
- [cmd](./cmd): Core executable to start the Golyn server.
- [app](./app): Core logic and shared application components.
- [sites](./sites): Contains the sites that will be served by the server.
- [var](./var): Server and database log files.
- [builds](./builds): Build scripts to package the server for multiple platforms.


### Multi-Site Configurations

- Each site has its own `.conf` file, located in the `config/sites` directory.
- These files define:
    - Domain mappings (e.g., `golyn.local`, `humanjuan.com`).
    - Static file paths for assets, JavaScript and styles.
    - Security settings like allowed origins and HTTPS enforcement.

E.g., `golyn.conf` contains the settings of the principal Golyn server site, including its domain names and directories.

---

## Goals and Use Cases

1. **Personal Portfolio Hosting:**  
   Showcase your work and skills in a polished, professional way.

2. **Multi-Site Management:**  
   Create, configure, and host multiple websites on a single server.

3. **Extendability for Future Use Cases:**  
   The server's modular architecture allows it to adapt to future needs, such as integrating APIs, authentication systems, or more.

---

## Tech Stack

- **Programming Language:** [Golang](https://golang.org)
- **Configuration Management:** Custom `.conf` files loaded dynamically.
- **Logging Library:** Integrated logging for server and database activities.
- **Static Assets:** Hosted via site-specific directories.
- **Database Connectivity (Planned):** Configuration includes database setup, skeleton included.
- **TLS/SSL Support (Planned):** Security-first approach with HTTPS encryption.

---

## Usage

### Running the Server

To start the Golyn Server:

1. Clone or download this repository onto your local machine.
2. Navigate to the project root directory.
3. Run the following command:

```bash
go run cmd/golyn.go
```

This will initialize the server using the configurations set in `config/server/web_server.conf` and site-specific `.conf` files located in `config/sites/`.

---

## Configuration

1. **Server Configuration:**  
   Modify `config/server/web_server.conf` for global settings like ports, timeouts, caching, sites conf and logging.

### Multi-Site Configurations
- Each site has its own `.conf` file in the `config/sites/` directory.
- These files define:
    - `enabled`: Whether the site is active (`true`/`false`).
    - `directory`: Directory for the site (e.g., `golyn`).
    - `domains`: Domain mappings (e.g., `golyn.humanjuan.com, golyn.humanjuan.local`).
    - `static_files_path`, `js_path`, `style_path`: Paths to static assets, JavaScript, and styles.
    - `cert_path`, `key_path`, `chain_path`: Paths to TLS/SSL certificates.
    - `allow_origin`: CORS policies.
    - `enable_https_redirect`: Redirect HTTP to HTTPS (`true`/`false`).
    - `proxy`, `proxy_target`: Reverse proxy settings (e.g., `proxy=true`, `proxy_target=http://backend:8080`).
    - `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`: SMTP settings for email functionality. `smtp_password` corresponds to the environment variable configured with the appropriate format (e.g., `${SMTP_PORTFOLIO_PASS}`

---
### SMTP Password Configuration per Site in Golyn

Golyn allows you to configure SMTP credentials **securely using AES-256 encryption**, protecting sensitive passwords without storing them in plain text. The process below explains how to encrypt, declare, and use an SMTP password for a specific site.


#### Step 1: Encrypt the SMTP password

Use the following command to encrypt your SMTP password using the server’s private key:
```bash
go run cmd/golyn.go --encrypt <password> --site <site_name>
```
- `<password>`: Your plain text SMTP password.
- `<site_name>`: The name of the site this password will be used for (e.g., portfolio).

This will output a line like: `SMTP_PORTFOLIO_PASS=ENC:AES256:2fa8bd3dd10f9e3022c3f739...`

#### Step 2: Declare the environment variable

Copy the entire generated line (including `ENC:AES256:`) and declare it as an environment variable:
```bash
export SMTP_PORTFOLIO_PASS=ENC:AES256:2fa8bd3dd10f9e3022c3f739...
```
You can place this in .bashrc, .env, a systemd unit, or any environment configuration method you use.

#### Step 3: Reference the variable in the site configuration

In the site’s configuration file  `config/sites/<site>.conf`, use the environment variable in `smtp_password` as follows:

```text
smtp_host=smtp.example.com
smtp_port=587
smtp_user=example@golyn.com
smtp_password=${SMTP_PORTFOLIO_PASS}
smtp_rate_limit_requests=2
```

## Contribution

Contributions are welcome! If you'd like to suggest a feature, fix a bug, or improve code/documentation, feel free to open an issue or submit a pull request.

---

## Contact

For any questions, suggestions or collaboration requests, feel free to contact me!

---
