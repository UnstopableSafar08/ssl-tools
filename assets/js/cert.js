/**
 * Certificate Module - X.509 certificate generation using node-forge
 * Supports RSA (2048/4096) and ECDSA (P-256/P-384)
 */

const Cert = (function() {
    'use strict';

    // In-memory storage for certificates
    const certStore = {
        ca: null,
        cert: null,
        csr: null
    };

    /**
     * Generate a random serial number
     */
    function generateSerialNumber() {
        const bytes = forge.random.getBytesSync(16);
        const hex = forge.util.bytesToHex(bytes);
        // Ensure positive by clearing the high bit
        return '00' + hex.substring(1);
    }

    /**
     * Set subject/issuer attributes on a forge certificate or CSR
     */
    function buildAttributes(cn, org, country, state, locality, orgUnit, email) {
        const attrs = [];

        if (country) {
            attrs.push({ shortName: 'C', value: country });
        }
        if (state) {
            attrs.push({ shortName: 'ST', value: state });
        }
        if (locality) {
            attrs.push({ shortName: 'L', value: locality });
        }
        if (org) {
            attrs.push({ shortName: 'O', value: org });
        }
        if (orgUnit) {
            attrs.push({ shortName: 'OU', value: orgUnit });
        }
        if (cn) {
            attrs.push({ shortName: 'CN', value: cn });
        }
        if (email) {
            attrs.push({ name: 'emailAddress', value: email });
        }

        return attrs;
    }

    /**
     * Build SAN extension value for forge
     */
    function buildSANExtension(sanEntries) {
        const altNames = [];
        sanEntries.forEach(entry => {
            if (entry.type === 'DNS') {
                altNames.push({ type: 2, value: entry.value }); // dNSName
            } else if (entry.type === 'IP') {
                altNames.push({ type: 7, ip: entry.value }); // iPAddress
            }
        });
        return altNames;
    }

    /**
     * Generate a self-signed Root CA certificate (RSA only via forge)
     */
    async function generateRootCA(cn, org, country, validityYears, algorithmStr, state, locality, orgUnit, email) {
        const keyPair = await Crypto.generateKeyPair(algorithmStr);
        Crypto.storeKeyPair('ca', keyPair);

        const cert = forge.pki.createCertificate();
        cert.publicKey = keyPair.publicKey;
        cert.serialNumber = generateSerialNumber();

        // Validity
        const now = new Date();
        cert.validity.notBefore = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        cert.validity.notAfter = new Date(now.getTime() + validityYears * 365 * 24 * 60 * 60 * 1000);

        // Subject & Issuer (self-signed)
        const attrs = buildAttributes(cn, org, country, state, locality, orgUnit, email);
        cert.setSubject(attrs);
        cert.setIssuer(attrs);

        // Extensions
        cert.setExtensions([
            {
                name: 'basicConstraints',
                cA: true,
                pathLenConstraint: 0,
                critical: true
            },
            {
                name: 'keyUsage',
                keyCertSign: true,
                cRLSign: true,
                critical: true
            },
            {
                name: 'subjectKeyIdentifier'
            }
        ]);

        // Sign the certificate
        cert.sign(keyPair.privateKey, forge.md.sha256.create());

        certStore.ca = cert;

        const pemCert = forge.pki.certificateToPem(cert);
        const pemKey = forge.pki.privateKeyToPem(keyPair.privateKey);

        return {
            cert,
            keyPair,
            pemCert,
            pemKey
        };
    }

    /**
     * Generate a certificate signed by CA
     */
    async function generateCertificate(cn, org, country, validityYears, algorithmStr, sanEntries, generateCSR = false, state, locality, orgUnit, email) {
        const caKeyPair = Crypto.getKeyPair('ca');
        if (!caKeyPair) {
            throw new Error('CA key pair not found. Generate a CA first.');
        }

        const caCert = certStore.ca;
        if (!caCert) {
            throw new Error('CA certificate not found. Generate a CA first.');
        }

        const keyPair = await Crypto.generateKeyPair(algorithmStr);
        Crypto.storeKeyPair('cert', keyPair);

        const cert = forge.pki.createCertificate();
        cert.publicKey = keyPair.publicKey;
        cert.serialNumber = generateSerialNumber();

        // Validity
        const now = new Date();
        cert.validity.notBefore = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        cert.validity.notAfter = new Date(now.getTime() + validityYears * 365 * 24 * 60 * 60 * 1000);

        // Subject
        const subjectAttrs = buildAttributes(cn, org, country, state, locality, orgUnit, email);
        cert.setSubject(subjectAttrs);

        // Issuer (from CA)
        cert.setIssuer(caCert.subject.attributes);

        // Extensions
        const extensions = [
            {
                name: 'basicConstraints',
                cA: false,
                critical: true
            },
            {
                name: 'keyUsage',
                digitalSignature: true,
                keyEncipherment: true,
                critical: true
            },
            {
                name: 'extKeyUsage',
                serverAuth: true,
                clientAuth: true
            },
            {
                name: 'subjectKeyIdentifier'
            },
            {
                name: 'authorityKeyIdentifier',
                keyIdentifier: true
            }
        ];

        // Add SAN if provided
        if (sanEntries && sanEntries.length > 0) {
            extensions.push({
                name: 'subjectAltName',
                altNames: buildSANExtension(sanEntries),
                critical: true
            });
        }

        cert.setExtensions(extensions);

        // Sign with CA private key
        cert.sign(caKeyPair.privateKey, forge.md.sha256.create());

        certStore.cert = cert;

        let csr = null;
        let pemCSR = null;

        if (generateCSR) {
            csr = generateCSRInternal(cn, org, country, sanEntries, keyPair, state, locality, orgUnit, email);
            pemCSR = forge.pki.certificationRequestToPem(csr);
            certStore.csr = csr;
        }

        const pemCert = forge.pki.certificateToPem(cert);
        const pemKey = forge.pki.privateKeyToPem(keyPair.privateKey);

        return {
            cert,
            keyPair,
            csr,
            pemCert,
            pemKey,
            pemCSR
        };
    }

    /**
     * Generate CSR (Certificate Signing Request)
     */
    function generateCSRInternal(cn, org, country, sanEntries, keyPair, state, locality, orgUnit, email) {
        const csr = forge.pki.createCertificationRequest();
        csr.publicKey = keyPair.publicKey;

        // Subject
        const attrs = buildAttributes(cn, org, country, state, locality, orgUnit, email);
        csr.setSubject(attrs);

        // Add SAN as extension attribute
        if (sanEntries && sanEntries.length > 0) {
            csr.setAttributes([
                {
                    name: 'extensionRequest',
                    extensions: [
                        {
                            name: 'subjectAltName',
                            altNames: buildSANExtension(sanEntries)
                        }
                    ]
                }
            ]);
        }

        // Sign the CSR
        csr.sign(keyPair.privateKey, forge.md.sha256.create());

        return csr;
    }

    /**
     * Get stored CA certificate
     */
    function getCACertificate() {
        return certStore.ca;
    }

    /**
     * Get stored certificate
     */
    function getCertificate() {
        return certStore.cert;
    }

    /**
     * Get stored CSR
     */
    function getCSR() {
        return certStore.csr;
    }

    /**
     * Clear stored certificates
     */
    function clearCertificates() {
        certStore.ca = null;
        certStore.cert = null;
        certStore.csr = null;
    }

    return {
        generateRootCA,
        generateCertificate,
        getCACertificate,
        getCertificate,
        getCSR,
        clearCertificates
    };
})();
