<h1 align="center">
  Golyn <img src="https://github.com/jpengineer/golyn/blob/main/sites/golyn/assets/Golyn.png?raw=true" alt="Golyn Logo" width="80"> Server
</h1>

![Golang](https://img.shields.io/badge/Language-Go-blue?logo=go)
![Open Source](https://img.shields.io/badge/Open%20Source-Yes-brightgreen?logo=opensourceinitiative)
![Status](https://img.shields.io/badge/Status-In%20Development-orange?logo=githubactions)
![Go Version](https://img.shields.io/badge/Go-v1.23.2-blue?logo=go)
[![Gin Version](https://img.shields.io/badge/Gin%20Framework-v1.10.0-lightblue)](https://github.com/gin-gonic/gin)
[![Logger](https://img.shields.io/badge/Logger-v1.6.1-lightblue)](https://github.com/jpengineer/logger)

[//]: # ([![Buy Me a Coffee]&#40;https://img.shields.io/badge/Buy_Me_A_Coffee-Support-orange?logo=buy-me-a-coffee&style=flat-square&#41;]&#40;https://www.buymeacoffee.com/YOUR_PROFILE_LINK&#41;)

## Golyn Server

The **Golyn Server** is a custom-built, multi-site web server designed to host and manage multiple websites efficiently. The primary purpose of this project is to host my **personal portfolio**, while also supporting additional websites thanks to its robust multi-site capabilities.

This server is currently **under active development** and continues to expand with new features and optimizations.

---

## Features

### 🌐 Multi-Site Hosting
- Golyn Server is designed to handle multiple sites simultaneously. Each site is configurable and isolated, making it suitable for various use cases such as personal projects, portfolios, or other hosted websites.
- Configurations for each site are stored in dedicated files, enabling granular control over site-specific settings like domains, paths, and security policies.

### 🚀 Hosting Your Portfolio
- The server is primarily designed to **host and serve my personal portfolio** and its dedicated administration panel. However, it also includes a **multi-site architecture**, allowing it to manage and host any additional websites, providing flexibility to support a variety of projects or domains under the same infrastructure.

### 🔒 Secure and Configurable
- Flexible configuration through `.conf` files for server-level and site-specific settings.
- Security settings, including HTTPS redirection and cross-origin resource sharing (CORS) policies, ensure your sites remain protected and accessible.

### ⚙️ Extensible Architecture
- Built with modularity in mind, making it easy to add features or scale the server as required.
- Supports logging, caching, JWT authentication (planned), and asset management for scalability and performance.

### 💻 Built with Go
The server is developed in **Golang** and, as part of its architecture, uses the following components:

- **[Gin framework](https://github.com/gin-gonic/gin)**: A high-performance HTTP web framework designed for building modular and fast applications.
- **[Logger](https://github.com/jpengineer/logger)**: A custom logging library developed for advanced and highly configurable logging capabilities.


---

## Project Status

🚧 **Under Development** 🚧  
This project is still a **work in progress**

Even though the server is still under development, it is fully functional for its primary purpose. If you install the server and configure your site correctly, you will be able to serve it without issues. This includes the ability to properly view your website's content through browsers, supporting secure communication over HTTPS if configured with the necessary certificates.

---

## How It Works

The Golyn Server operates as a centralized, multi-site server. Each site's settings are configured separately using `.conf` files, which are loaded dynamically at runtime.

### Directory Structure

- [config](./config):  Configuration files for sites and the server.
- [cmd](./cmd): Core executable to start the Golyn server.
- [app](./app): Core logic and shared application components.
- [sites](./sites): Contains the sites that will be served by the server.
- [var](./var): Server and database log files.
- [builds](./builds): Build scripts to package the server for multiple platforms.


### Multi-Site Configurations

- Each site has its own `.conf` file, located in the `config/sites` directory.
- These files define:
    - Domain mappings (e.g., `golyn.local`, `humanjuan.com`).
    - Static file paths for assets, JavaScript, and styles.
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
   Modify `config/server/web_server.conf` for global settings like ports, timeouts, caching, and logging.

2. **Site Configurations:**  
   Add or update site-specific `.conf` files inside the `config/sites/` directory. Define settings such as:
    - `enabled`: Whether the site is active or not.
    - `domains`: Define the domains/subdomains associated with the site.
    - `static_files_path`: Path to the site's static assets like images and CSS.
    - `allow_origin` (CORS policies): Define which origins are allowed to access your sites.

---

## Contribution

Contributions are welcome! If you'd like to suggest a feature, fix a bug, or improve code/documentation, feel free to open an issue or submit a pull request.

---

## Contact

For any questions, suggestions, or collaboration requests, feel free to contact me!

---
