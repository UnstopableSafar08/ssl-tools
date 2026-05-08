import { createServer } from 'http';
import { connect } from 'tls';
import { X509Certificate } from 'crypto';

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
        const socket = connect({
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

function isValidHostname(hostname) {
    if (!hostname || hostname.length > 253) return false;
    if (hostname === 'localhost') return true;
    return /^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i.test(hostname);
}

export default async function handler(req) {
    const url = new URL(req.url);
    const domain = (url.searchParams.get('domain') || '').trim();
    const tlsPort = Number(url.searchParams.get('port') || 443);

    if (!isValidHostname(domain)) {
        return new Response(JSON.stringify({ error: 'Enter a valid domain name' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    if (!Number.isInteger(tlsPort) || tlsPort < 1 || tlsPort > 65535) {
        return new Response(JSON.stringify({ error: 'Port number must be between 1 and 65535' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    try {
        const pem = await lookupCertificate(domain, tlsPort);
        const certificates = pem
            .match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)
            .map(parseCertificateDetails);

        return new Response(JSON.stringify({ pem, certificates }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message || 'Unable to fetch certificate' }), {
            status: 502,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}
