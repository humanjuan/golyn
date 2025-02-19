# `certificates` Directory

This directory is intended to store the SSL/TLS certificates required for secure communication in the Golyn server.

## Usage

### Adding Certificates
1. Obtain or generate the required SSL/TLS certificates (self-signed or CA-signed).
2. Place the certificate files and private key into this directory.:
    - `cert.pem`: The public certificate file for the server.
    - `privkey.pem`: The private key corresponding to the server certificate.

---

## Notes

- Protect your private keys at all times. Do not expose this directory to public repositories or unauthorized personnel.
- Ensure that the private key files have restricted permissions.
- If new certificates are generated or updated, ensure the server and release packages are rebuilt to include the latest versions.
- Use trusted Certificate Authorities (CAs) to improve compatibility with client browsers and avoid security warnings.

---