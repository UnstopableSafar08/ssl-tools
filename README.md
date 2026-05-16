# SSL Certificate Generator

A production-grade SSL certificate generator and inspection toolkit. Most cryptographic operations run entirely in the browser; optional live domain SSL checking is available through the included local Node helper server.

## Overview

This application provides a secure, browser-only X.509 toolkit for generating:
- Root Certificate Authorities (CA)
- CA-signed certificates
- Certificate Signing Requests (CSR)
- Subject Alternative Names (SAN) support
- RSA/PKI key pairs with PEM, PKCS#8, and PKCS#12 exports
- SSL certificate inspection from domain, uploaded cert file, or pasted PEM
- DevOps-ready export formats

## Architecture

### Client-Only Cryptography

All cryptographic operations are performed entirely in the browser using:
- **WebCrypto API** - For secure key generation and signing
- **node-forge** - For RSA keys, X.509 certificate generation/parsing, CSR, and PKCS#12 creation
- **JSZip** - For bundling artifacts

### Optional Local SSL Checker Helper

Browsers do not expose remote TLS peer certificate details to client-side JavaScript. When the app is served with `node assets/js/server.js` or `./start.sh`, the local helper endpoint `/api/ssl-check` opens the TLS connection and returns certificate details to the UI. Static hosting still supports certificate file upload and pasted PEM parsing.

### Security Model

- **Client-first** - Keys, certificates, parsing, encryption, and ZIP exports happen locally in the browser
- **Optional local helper** - Live domain SSL lookup uses the included Node server only when running locally
- **No data persistence** - Private keys are stored only in memory
- **Secure wipe** - Keys are cleared on page unload
- **LocalStorage cleanup** - App-owned localStorage data is cleared on page load/refresh
- **No console logging** - Secrets are never logged

## Features

### CA Generator
- Generate self-signed Root CA certificates
- Support for RSA (2048, 4096) and ECDSA (P-256, P-384)
- Configurable validity period
- Proper CA extensions (BasicConstraints, KeyUsage)

### Certificate Generator
- Generate certificates signed by your CA
- Dynamic SAN (Subject Alternative Names) support
- DNS and IP address entries
- Optional CSR generation
- Configurable validity period

### DevOps Export Panel
- **Kubernetes Secrets** - Ready-to-use YAML for TLS and CA secrets
- **OpenSSL Commands** - Equivalent commands for reference
- **PEM Viewer** - View and copy generated certificates and keys
- **ZIP Bundle** - Download all artifacts at once
- **Email Delivery** - Optional client-side email via EmailJS

### RSA/PKI Key Pairs
- Generate RSA or ECDSA key pairs
- Export formats: PEM, PKCS#8, Raw Base64, Double-Encoded Base64
- Export RSA PKCS#12 (`.p12`) bundles with a custom password, defaulting to `password123`
- ZIP download includes all formats plus `README.txt` and `password.txt`
- Optional RSA text encryption/decryption utility using generated or pasted PEM keys
- Base64 Tools for encoding/decoding PEM keys to/from Base64 format

### SSL Checker
- Inspect a certificate by domain and port when using the local Node helper server
- Inspect uploaded `.crt`, `.cer`, `.pem`, or pasted PEM content
- Show subject, SANs, issuer, validity, serial number, expiry status, and certificate chain
- Show equivalent OpenSSL commands for remote and local certificate checks

## Usage

### Local Development

1. Clone the repository
2. Open `index.html` in a modern browser for client-only features
3. For live domain SSL checks, run the local helper server:
   ```bash
   ./start.sh
   # or
   node assets/js/server.js
   ```
4. Access at `http://localhost:8080`

### Docker

```bash
# Build the image
docker build -t ssl-generator .

# Run the container
docker run -p 8080:8080 ssl-generator

# Access at http://localhost:8080
```

### GitHub Pages

1. Push the code to your repository
2. Enable GitHub Pages in repository settings
3. Select the `main` branch as source
4. Access at `https://username.github.io/repo/`

## DevOps Usage Examples

### Kubernetes TLS Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-tls
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
```

### Nginx Configuration

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate /path/to/example.com.crt;
    ssl_certificate_key /path/to/example.com.key;
}
```

### Apache Configuration

```apache
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /path/to/example.com.crt
    SSLCertificateKeyFile /path/to/example.com.key
</VirtualHost>
```

## EmailJS Setup (Optional)

To enable email delivery:

1. Sign up at [emailjs.com](https://www.emailjs.com/)
2. Create a service using your Zoho SMTP:
   - SMTP Host: smtp.zoho.com
   - Port: 465
   - Username: admin@sagarmalla.info.np
   - Password: Your Zoho app password
3. Create an email template
4. Add EmailJS SDK to `index.html`:
   ```html
   <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/@emailjs/browser@3/dist/email.min.js"></script>
   <script type="text/javascript">
       emailjs.init("YOUR_PUBLIC_KEY");
   </script>
   ```

## Limitations

- **Not publicly trusted** - Certificates are for development/testing only
- **No revocation** - No CRL or OCSP support
- **Browser compatibility** - Validity > 825 days may have issues
- **Self-signed** - Requires manual trust installation
- **Domain SSL checks** - Live remote domain checks require the local Node helper server; static hosting supports upload/paste checks only
- **ECDSA PKCS#12** - PKCS#12 export is generated for RSA key pairs in this browser implementation

## Security Considerations

- Keep private keys (.key files) secure
- Never share private keys
- Use strong key sizes (RSA 2048 minimum)
- Consider using ECDSA for better performance
- These certificates are NOT for production use

## File Structure

```
ssl-generator/
├── index.html                # Main HTML file
├── README.md                 # This file
├── cli-commands.md           # Comprehensive OpenSSL CLI reference
├── start.sh                  # Starts the local helper server
├── assets/
│   ├── css/
│   │   └── styles.css        # Styles
│   ├── js/
│   │   ├── app.js            # App bootstrap
│   │   ├── crypto.js         # Cryptographic operations
│   │   ├── cert.js           # Certificate generation
│   │   ├── server.js         # Local static server + SSL checker endpoint
│   │   ├── ui.js             # UI interactions
│   │   └── zip.js            # File bundling
│   ├── img/
│   │   └── favicon.ico       # Favicon
├── Dockerfile                # Docker configuration
├── .dockerignore            # Docker ignore file
└── README.md                # This file
```

## Dependencies

- [node-forge](https://github.com/digitalbazaar/forge) - RSA, X.509, CSR, PKCS#12, PEM handling
- [JSZip](https://stuk.github.io/jszip/) - ZIP file creation
- Node.js TLS / X509Certificate - Optional local live SSL checker endpoint
- [EmailJS](https://www.emailjs.com/) - Optional email delivery

## License

MIT License - Use at your own risk for development and testing purposes only.

## Support

For issues and questions, please open an issue on GitHub.
