const fs = require('fs');
const http = require('http');
const path = require('path');
const tls = require('tls');
const { X509Certificate } = require('crypto');
const { URL } = require('url');

const rootDir = path.resolve(__dirname, '../..');
const port = Number(process.env.PORT || 8080);

const mimeTypes = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.ico': 'image/x-icon',
    '.png': 'image/png',
    '.svg': 'image/svg+xml'
};

function sendJson(res, statusCode, payload) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(payload));
}

function isValidHostname(hostname) {
    if (!hostname || hostname.length > 253) return false;
    if (hostname === 'localhost') return true;
    return /^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i.test(hostname);
}

function escapePemLine(value) {
    return String(value || '').replace(/(.{64})/g, '$1\n').trim();
}

function certificateRawToPem(raw) {
    return [
        '-----BEGIN CERTIFICATE-----',
        escapePemLine(raw.toString('base64')),
        '-----END CERTIFICATE-----'
    ].join('\n');
}

function collectCertificateChain(peerCertificate) {
    const chain = [];
    const seen = new Set();
    let current = peerCertificate;

    while (current && current.raw) {
        const fingerprint = current.fingerprint256 || current.fingerprint || current.serialNumber;
        if (seen.has(fingerprint)) break;
        seen.add(fingerprint);
        chain.push(certificateRawToPem(current.raw));

        if (!current.issuerCertificate || current.issuerCertificate === current) break;
        current = current.issuerCertificate;
    }

    return chain;
}

function parseDistinguishedName(name) {
    return String(name || '').split(/\n|,\s*/).reduce((attrs, part) => {
        const separatorIndex = part.indexOf('=');
        if (separatorIndex === -1) return attrs;

        const key = part.substring(0, separatorIndex).trim();
        const value = part.substring(separatorIndex + 1).trim();
        if (key && value && !attrs[key]) {
            attrs[key] = value;
        }
        return attrs;
    }, {});
}

function formatDistinguishedName(name) {
    const attrs = parseDistinguishedName(name);
    return [attrs.CN, attrs.O, attrs.OU, attrs.L, attrs.ST, attrs.C].filter(Boolean).join(', ') || '-';
}

function formatSubjectAltName(subjectAltName) {
    if (!subjectAltName) return '-';
    return subjectAltName
        .split(/,\s*/)
        .map(value => value.replace(/^DNS:/, '').replace(/^IP Address:/, 'IP Address:'))
        .join(', ');
}

function parseCertificateDetails(pem) {
    const cert = new X509Certificate(pem);
    const subject = parseDistinguishedName(cert.subject);

    return {
        commonName: subject.CN || '-',
        subjectAlternativeNames: formatSubjectAltName(cert.subjectAltName),
        organization: subject.O || '-',
        organizationUnit: subject.OU || '-',
        locality: subject.L || '-',
        state: subject.ST || '-',
        country: subject.C || '-',
        validFrom: cert.validFrom,
        validTo: cert.validTo,
        issuer: formatDistinguishedName(cert.issuer),
        serialNumber: String(cert.serialNumber || '').replace(/:/g, '').toLowerCase(),
        subject: formatDistinguishedName(cert.subject)
    };
}

function lookupCertificate(domain, tlsPort) {
    return new Promise((resolve, reject) => {
        const socket = tls.connect({
            host: domain,
            port: tlsPort,
            servername: domain,
            rejectUnauthorized: false,
            timeout: 10000
        });

        socket.once('secureConnect', () => {
            const peerCertificate = socket.getPeerCertificate(true);
            socket.end();

            if (!peerCertificate || !peerCertificate.raw) {
                reject(new Error('No certificate returned by server'));
                return;
            }

            resolve(collectCertificateChain(peerCertificate).join('\n'));
        });

        socket.once('timeout', () => {
            socket.destroy(new Error('TLS connection timed out'));
        });

        socket.once('error', reject);
    });
}

async function handleSSLCheck(req, res, url) {
    const domain = (url.searchParams.get('domain') || '').trim();
    const tlsPort = Number(url.searchParams.get('port') || 443);

    if (!isValidHostname(domain)) {
        sendJson(res, 400, { error: 'Enter a valid domain name' });
        return;
    }

    if (!Number.isInteger(tlsPort) || tlsPort < 1 || tlsPort > 65535) {
        sendJson(res, 400, { error: 'Port number must be between 1 and 65535' });
        return;
    }

    try {
        const pem = await lookupCertificate(domain, tlsPort);
        const certificates = pem
            .match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)
            .map(parseCertificateDetails);
        sendJson(res, 200, { pem, certificates });
    } catch (error) {
        sendJson(res, 502, { error: error.message || 'Unable to fetch certificate' });
    }
}

function serveStatic(req, res, url) {
    const requestedPath = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
    const filePath = path.resolve(rootDir, `.${requestedPath}`);

    if (!filePath.startsWith(rootDir)) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
    }

    fs.readFile(filePath, (error, content) => {
        if (error) {
            res.writeHead(error.code === 'ENOENT' ? 404 : 500);
            res.end(error.code === 'ENOENT' ? 'Not Found' : 'Server Error');
            return;
        }

        const contentType = mimeTypes[path.extname(filePath)] || 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(content);
    });
}

const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || `localhost:${port}`}`);

    if (url.pathname === '/api/ssl-check') {
        handleSSLCheck(req, res, url);
        return;
    }

    serveStatic(req, res, url);
});

server.listen(port, () => {
    console.log(`SSL Generator running at http://localhost:${port}`);
});
