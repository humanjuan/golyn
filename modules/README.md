# `modules` Directory

The module directory contains the core logic for specific application functions. This directory is designed to provide defined functionality, focusing in this case on authentication workflows and token management, which are necessary for my portfolio.

---

## Contents

### **`auth/` Directory**
This submodule handles the **authentication** aspect of the application, including login, token creation, validation, and refresh mechanisms.

- **`login.go`**:
    - Manages the user login workflow.
    - Verifies user credentials against the database.
    - Implements rate-limiting per client IP to prevent brute-force attacks.
    - Generates access and refresh tokens upon successful authentication.

- **`tokens.go`**:
    - Handles the creation and signing of JWT-based tokens.
    - Provides refresh token validation and handles token lifecycle (e.g., revocation, issuance of new tokens).
    - Ensures secure token storage and retrieval from the database.

---
