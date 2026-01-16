<h1 align="center">
  Golyn <img src="https://github.com/humanjuan/golyn/blob/main/sites/golyn/assets/Golyn.png?raw=true" alt="Golyn Logo" width="80"> Server
</h1>

![Golang](https://img.shields.io/badge/Language-Go-blue?logo=go)
![Open Source](https://img.shields.io/badge/Open%20Source-Yes-brightgreen?logo=opensourceinitiative)
![Status](https://img.shields.io/badge/Status-In%20Development-orange?logo=githubactions)
![SSL Labs A+](https://img.shields.io/badge/SSL%20Labs-A%2B-brightgreen?logo=ssl)
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
- The server is primarily designed to **host and serve my personal portfolio** and its dedicated administration panel. It includes a **multi-site architecture**, allowing it to manage and host any additional websites, providing flexibility to support a variety of projects or domains under the same infrastructure.
- **Backend-owned Authentication**: Implements a highly secure authentication system using HttpOnly cookies, CSRF protection, and standardized DTOs, ensuring professional-grade security for all hosted sites.

### Multi-Site Hosting
- Golyn Server is designed to handle multiple sites simultaneously. Each site is configurable and isolated, making it suitable for various use cases such as personal projects, portfolios, or other hosted websites.
- Configurations for each site are stored in dedicated files, enabling granular control over site-specific settings like domains, paths, proxy settings, SMTP, and security policies.
- Built-in support for multiple domains and subdomains with individual TLS/SSL certificate management.

### Secure and Configurable
- Flexible configuration through `.conf` files for server-level and site-specific settings.
- Security settings, including HTTPS redirection and cross-origin resource sharing (CORS) policies, ensure your sites remain protected and accessible.
- **Content Security Policy (CSP)**:
    - Default policy provides a high level of security while allowing common resources (CDN for jQuery, Tailwind, Google Fonts, jsDelivr).
    - **Base64 Support**: The default policy automatically allows `data:` schemes for `img-src` and `font-src`, preventing issues with embedded assets.
    - **Per-Site Customization**: Each site can define its own `content_security_policy` in its `.conf` file to override the default server policy.
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

### Extensible Architecture (Extension System)
Golyn features a robust, secure, and orchestrated extension system that allows external modules (like `golyn-ai`) to integrate deeply with the Core.

- **Orchestrated Lifecycle**: Extensions register themselves using a protected handshake (`id` and `secret`).
- **Dynamic Configuration**: Supports environment variable injection in configuration files (both in Core and `golyn-ai`) using `${VAR_NAME}` syntax for secrets and environment-specific paths.
- **Route Sandboxing**: Each extension receives a protected route group (e.g., `/api/v1/extension/{id}/`), preventing them from overwriting Core routes.
- **Emergency Flag**: Use `--no-extensions` to disable all external modules for maintenance.

---

### Platform Identity & Authentication

Golyn provides a centralized multi-site identity platform using standardized JWT contracts, secure cookies, and a robust OAuth2/SSO broker.

### Platform JWT Contract

Tokens issued by Golyn follow a minimal and strict claims structure, ensuring any consumer module can trust the identity without knowing Golyn's internal logic.

| Claim | Type | Description |
| :--- | :--- | :--- |
| `sub` | UUID/String | **Subject**: Unique and stable user identifier. |
| `site_id` | UUID | **Tenant/Organization**: The unique site/context identifier. |
| `iat` | Numeric | **Issued At**: Token generation timestamp. |
| `exp` | Numeric | **Expiration**: Security limit for token validity. |
| `iss` | String | **Issuer**: Always set to `"Golyn"`. |
| `aud` | String | **Audience**: Target validation, set to `"GolynPlatform"`. |

> **Security Note**: Golyn acts as an Identity Provider. Domain-specific data (business roles, permissions, etc.) are **forbidden** within the platform JWT. The token identifies *who* and *where*, while business rules remain in the specific products.

### Token Delivery & Security (Cookies)

To mitigate risks like *Token Leakage* in URLs or logs, Golyn uses a strictly cookie-based delivery mechanism (**Backend-owned sessions**):

- **`access_token`**: Stored in a cookie with `HttpOnly`, `Secure`, and `SameSite=Lax` attributes. The authentication middleware looks for it automatically.
- **`refreshToken`**: Stored in an `HttpOnly` and `Secure` cookie, used exclusively to obtain new access tokens without requiring user intervention.

> **Note**: Tokens are never included in the JSON response body to prevent access from malicious scripts (XSS). All authentication is handled transparently by the browser via secure cookies.

### Multi-provider OAuth2 (SSO Broker)

Golyn acts as an **Identity Broker**, allowing users to authenticate through their corporate or personal accounts from major providers.

#### Supported Providers:
- **Microsoft Azure AD** (Entra ID)
- **Google**
- **GitHub**

#### Authentication Flow:
1.  **Redirection**: Send the user to `GET /api/v1/auth/{provider}/login`.
2.  **Continuity**: Use the `next` parameter to specify where the user should return (e.g., `/login?next=https://your-app.com/dashboard`).
3.  **Handshake**: After a successful login, Golyn redirects the user to the `next` URL. Tokens are automatically set as secure cookies in the browser.

### Logout

Logout is comprehensive and secure:
- **Endpoint**: `POST /api/v1/logout`.
- **Actions**:
    - Clears `access_token` and `refreshToken` cookies (set-cookie with expiration -1).
    - Permanently revokes the refresh token in the database to prevent further use.
    - Clears temporary OAuth2 state cookies.

### Audit & Security

- **Auditing**: All events (local login, OAuth2, refreshes, logout) are logged in `audit.auth_events` with IP and User-Agent.
- **Token Rotation**: Implements a rotation system that invalidates old sessions when starting new ones (configurable).
- **Revocation**: Administrators can revoke tokens globally per user.

### Transport Security

Golyn is designed with a "Security First" approach. Our production configuration consistently achieves an **A+ rating** on [SSL Labs](https://www.ssllabs.com/), thanks to:
- Enforced **HSTS** (HTTP Strict Transport Security) with preloading.
- **TLS 1.3** and **TLS 1.2** only (legacy protocols disabled).
- High-grade cipher suites with **Forward Secrecy**.
- Optimized Elliptic Curve certificates.

---

### Public and User Endpoints (`/api/v1`)

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/login` | `POST` | **Local Login**: Authenticate (Sets secure cookies). |
| `/logout` | `POST` | **Logout**: Revoke tokens and clear cookies. |
| `/refresh_token` | `POST` | **Token Refresh**: Rotates cookies (Returns 204 No Content). |
| `/auth/me` | `GET` | **Profile**: Get current authenticated user details. |
| `/user/theme` | `GET/PUT` | **Theme**: Manage user interface preferences. |
| `/auth/:provider/login`| `GET` | **OAuth2 Login**: Initiate SSO flow. |
| `/csrf-token` | `GET` | **Security**: Obtain a fresh CSRF token (Required for mutable requests). |
| `/send-mail` | `POST` | **Communication**: Send emails (Requires CSRF & Rate limited). |
| `/ping` | `GET` | **Health Check**: Verify server status. |
| `/version` | `GET` | **Version**: Current build information. |

## Administration API

Golyn includes a protected API for platform management, allowing administrators to manage sites and users programmatically. All admin endpoints require a JWT with `SuperAdmin` or `Admin` roles.

### Administrative Roles
- **SuperAdmin**: Full access to all administrative functions.
- **Admin**: Restricted administrative access (e.g., managing a specific set of users).

### Key Endpoints (`/api/v1/admin`)

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/sites` | `POST` | **Create Site**: Register a new tenant (requires `key` and `host`). |
| `/sites` | `GET` | **List Sites**: Retrieve all registered organizations. |
| `/sites/:key` | `DELETE` | **Delete Site**: Remove a site and its configurations. |
| `/sites/:key/status` | `PATCH` | **Update Site Status**: Enable or disable a site. |
| `/users` | `POST` | **Create User**: Add a user to a site (requires `site_key`, `username`, `password`). |
| `/users` | `GET` | **List Users**: List all users or filter by `site_key`. |
| `/users/:username` | `DELETE` | **Delete User**: Remove a user account. |
| `/users/:username/status` | `PATCH` | **Update Status**: Change user account status (active, inactive). |
| `/users/:username/role` | `PUT` | **Update Role**: Change user administrative privileges. |
| `/users/:username/permissions`| `GET/PUT` | **Manage Permissions**: Get or update specific user grants/denies. |
| `/permissions/catalog` | `GET` | **Permissions Catalog**: Get all available platform permissions. |
| `/logs` | `GET` | **System Logs**: View server or database logs (SuperAdmin only). |
| `/stats` | `GET` | **Platform Stats**: Overview of users, sites and system health. |
| `/info` | `GET` | **Server Info**: Detailed technical info about the instance (SuperAdmin only). |

### Environment Variables

To run **Golyn** correctly, especially in production environments, you need to define the following environment variables. These variables handle sensitive information like database passwords, JWT secrets, and OAuth2 credentials.

| Variable | Description | Example / Note |
| :--- | :--- | :--- |
| `GOLYN_DB_PASSWORD` | Password for the PostgreSQL database user. | `your_db_password` |
| `GOLYN_JWT_SECRET` | Secret key used to sign and verify JWT tokens. | Use a long, random string. |
| `GOOGLE_CLIENT_ID` | Client ID for Google OAuth2 integration. | `xxx-yyy.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | Client Secret for Google OAuth2 integration. | `GOCSPX-xxxxxx` |
| `GOOGLE_REDIRECT_URL` | Callback URL for Google OAuth2. | `https://your-domain.com/api/v1/auth/google/callback` |
| `AZURE_CLIENT_ID` | Client ID for Microsoft Azure (Entra ID). | `your-azure-app-id` |
| `AZURE_CLIENT_SECRET` | Client Secret for Microsoft Azure. | `your-azure-secret` |
| `AZURE_TENANT_ID` | Tenant ID for your Azure organization. | `your-tenant-id` |
| `AZURE_REDIRECT_URL` | Callback URL for Azure OAuth2. | `https://your-domain.com/api/v1/auth/azure/callback` |
| `GITHUB_CLIENT_ID` | Client ID for GitHub OAuth2 integration. | `github_client_id` |
| `GITHUB_CLIENT_SECRET` | Client Secret for GitHub OAuth2. | `github_client_secret` |
| `GITHUB_REDIRECT_URL` | Callback URL for GitHub OAuth2. | `https://your-domain.com/api/v1/auth/github/callback` |
| `GOLYN_AI_SECRET` | Secret key for the Golyn-AI extension handshake. | Required if `golyn-ai` is enabled. |
| `SMTP_SITE_PASS` | Encrypted SMTP password for a specific site. | Replace `SITE` with your site name (e.g., `SMTP_PORTFOLIO_PASS`). |

> **Tip**: You can define these variables in a `.env` file at the project root or directly in your system's environment. Golyn will automatically expand these variables when they are referenced in the `.conf` files using the `${VARIABLE_NAME}` syntax.

---

## Configuration

Security secrets and provider credentials must be defined via environment variables.

### 1. Global Secrets
```ini
# config/server/web_server.conf
[server]
tokenExpirationTime = 5         # Access Token duration (minutes)
tokenExpirationRefreshTime = 1440 # Refresh Token duration (minutes)
jwtSecret = ${GOLYN_JWT_SECRET}
```

### 2. OAuth2 Providers
Add your provider credentials to the configuration and the `.env` file:
```ini
[oauth2.azure]
enabled = true
client_id = ${AZURE_CLIENT_ID}
client_secret = ${AZURE_CLIENT_SECRET}
tenant_id = ${AZURE_TENANT_ID}
redirect_url = https://your-domain.com/api/v1/auth/azure/callback
```

---

## Usage for Developers

### 1. Protecting Routes (Middleware)
The `AuthMiddleware()` validates the token and injects the `subject` and `site_id` into the Gin context.

```go
private := router.Group("/api/v1/private", middlewares.AuthMiddleware())
{
    private.GET("/data", func(c *gin.Context) {
        subject := c.GetString("subject") // User UUID
        siteID := c.GetString("site_id")  // Site UUID
        // Business logic here
    })
}
```

### 2. Identity Mapping in Code
If you need to validate a token in an external service, use the `internal/security/jwt` package:

```go
import platjwt "github.com/humanjuan/golyn/internal/security/jwt"

claims, err := platjwt.ValidateRefreshToken(tokenString)
if err == nil {
    // Identity is now trusted
    fmt.Printf("Subject: %s, Site: %s", claims.Subject, claims.SiteID)
}
```

---

## Frontend Integration (TypeScript Example)

This example shows how to interact with the Golyn **Backend-owned session** system from a TypeScript frontend. Since tokens are stored in secure cookies, the frontend doesn't need to manage JWTs in local storage.

### GolynAuthService.ts

```typescript
/**
 * Golyn Authentication Service
 * Handles login, authenticated requests, and automatic token refresh.
 */

interface APIResponse<T> {
  success: boolean;
  message?: string;
  data?: T;
  error?: string;
}

interface UserDTO {
  id: string;
  username: string;
  role: string;
  status: string;
  site_id: string;
  theme?: any;
  permissions?: any;
}

interface LoginResponse {
  message: string;
  user: UserDTO;
  provider?: string;
}

class GolynAuthService {
  private static API_BASE = "https://your-golyn-domain.com/api/v1";

  /**
   * Login to Golyn.
   * The server will set 'access_token' and 'refreshToken' HttpOnly cookies automatically.
   */
  static async login(username: string, password: string): Promise<UserDTO> {
    const response = await fetch(`${this.API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
      // Important: Allow the browser to receive and store secure cookies
      credentials: 'include' 
    });

    const result: APIResponse<LoginResponse> = await response.json();

    if (!result.success) {
      throw new Error(result.message || "Login failed");
    }

    return result.data!.user;
  }

  /**
   * Refreshes the tokens using the Refresh Token stored in the cookie.
   * The server will rotate both cookies automatically.
   */
  static async refreshToken(): Promise<void> {
    const response = await fetch(`${this.API_BASE}/refresh_token`, {
      method: 'POST',
      credentials: 'include', // Crucial to send the refreshToken cookie
    });

    if (response.status !== 204) {
      throw new Error("Session expired. Please login again.");
    }
  }

  /**
   * Fetches a fresh CSRF token. Required for POST, PUT, DELETE.
   */
  static async getCSRFToken(): Promise<string> {
    const response = await fetch(`${this.API_BASE}/csrf-token`, { credentials: 'include' });
    const result = await response.json();
    return result.csrf_token;
  }

  /**
   * Wrapper for authenticated fetch requests.
   * Automatically handles 401 Unauthorized by attempting to refresh the session.
   */
  static async authenticatedFetch(url: string, options: RequestInit = {}): Promise<Response> {
    const fetchOptions = {
        ...options,
        credentials: 'include' as RequestCredentials
    };

    let response = await fetch(url, fetchOptions);

    // If 401, the session might have expired. Try to refresh.
    if (response.status === 401) {
      try {
        await this.refreshToken();
        // Retry the original request
        response = await fetch(url, fetchOptions);
      } catch (err) {
        throw new Error("Session expired");
      }
    }

    return response;
  }

  /**
   * Logout. Clears session on server and removes cookies.
   */
  static async logout(): Promise<void> {
    await fetch(`${this.API_BASE}/logout`, {
      method: 'POST',
      credentials: 'include',
    });
  }
}

// Usage Example:
// const user = await GolynAuthService.login("admin", "password");
// const csrf = await GolynAuthService.getCSRFToken();
// await GolynAuthService.authenticatedFetch("/api/v1/send-mail", {
//    method: 'POST',
//    headers: { 'X-CSRF-Token': csrf },
//    body: formData 
// });
```

---

### Developer Tools (Database & Client Management)

For local development, Golyn provides a set of scripts to manage the infrastructure and multi-site data without manually writing SQL.

#### 1. Infrastructure Management (`manage_db.sh`)
Located in `docker/postgresql/`, this script handles the Docker container lifecycle.
- `./manage_db.sh start`: Launches the PostgreSQL container.
- `./manage_db.sh stop`: Stops the container.
- `./manage_db.sh logs`: Follows the database logs.
- `./manage_db.sh cli-golyn`: Opens an interactive `psql` shell directly in the `golyn` database.
- `./manage_db.sh clean`: **Warning**: Deletes the container and all persistent data.

#### 2. Multi-site Administration (`manage_clients.sh`)
This tool manages tenants (sites) and users. You can also access it via `./manage_db.sh clients`.
- `./manage_db.sh clients list`: Shows all registered sites and users.
- `./manage_db.sh clients add-site <key> <host>`: Registers a new site (e.g., `hr-site hr.local`).
- `./manage_db.sh clients add-user <site_key> <username> <password>`: Creates a user for a specific site.
- **Automatic Hashing**: The script automatically detects if the password is plain text and hashes it using the Golyn binary before storing it in the database.

### SQL Query Centralization

To improve maintainability, Golyn uses a centralized query map in `database/queries.go`. This allows all SQL statements to be audited and optimized in one place, avoiding hardcoded SQL in data repositories.

> **Note on Docker**: The provided Docker configurations are intended for **development only**. Choosing the final production database (PostgreSQL, RDS, etc.) and the orchestration layer (Docker, Kubernetes, or bare metal) is the responsibility of the implementer. Golyn is designed to be infrastructure-agnostic.

---

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
- [internal](./internal): Internal packages, handlers, and utilities.
- [middlewares](./middlewares): Gin middlewares for security and auth.
- [modules](./modules): Feature-specific modules (auth, admin, user).
- [routes](./routes): API route definitions.
- [app](./app): Core logic and shared application components.
- [sites](./sites): Contains the sites that will be served by the server.
- [var](./var): Server and database log files.
- [builds](./builds): Build scripts to package the server for multiple platforms.


### Multi-Site Configurations

- Each site has its own `.conf` file, located in the `config/sites` directory.
- These files define:
    - Domain mappings (e.g., `golyn.local`, `humanjuan.com`).
    - Static file paths for assets, JavaScript and styles.
    - Security settings like allowed origins, HTTPS enforcement, and **Custom Content Security Policy**.
    - SMTP configuration for emails.
    - Reverse proxy settings.

#### Configuration Example (`portfolio.conf`):
```ini
[settings]
enabled = true
directory = portfolio
domains = humanjuan.com, humanjuan.local

# Security settings
allow_origin = https://humanjuan.com, https://humanjuan.local
enable_https_redirect = true
# Optional: Override default CSP
content_security_policy = default-src 'self'; img-src 'self' data:;

# Mail SMTP settings
smtp_host=mail.example.com
smtp_port=587
smtp_user=user@example.com
smtp_password=${SMTP_PASS}
```

---

## Goals and Use Cases

1. **Personal Portfolio Hosting:**  
   Showcase your work and skills in a polished, professional way.

2. **Multi-Site Management:**  
   Create, configure, and host multiple websites on a single server.

3. **Extendability for Future Use Cases:**  
   The server's modular architecture allows it to adapt to future needs, such as integrating APIs, authentication systems, or more.

4. **Identity as a Service (IDaaS):**
   Use Golyn as a centralized authentication hub for all your projects. It provides:
   - **Single Sign-On (SSO)**: One login for multiple subdomains or services.
   - **Multi-tenancy**: Isolated user management per site/tenant.
   - **Token Federation**: Standardized JWTs that can be validated by any backend (Go, Node.js, Python, etc.).

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
