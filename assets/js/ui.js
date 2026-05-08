/**
 * UI Module - User interface interactions and form handling
 */

const UI = (function() {
    'use strict';

    // State
    let currentTab = 'ca';
    let generatedCA = null;
    let generatedCert = null;
    let generatedPKIKeyPairs = [];
    let currentPKIIndex = null; // Track which key pair is being used for CSR
    let currentKeyModalDownload = null;
    const LOCAL_STORAGE_TTL_MS = 3 * 60 * 1000;
    const LOCAL_STORAGE_CREATED_KEY = 'ssl-generator-local-storage-created-at';

    /**
     * Initialize UI
     */
    function init() {
        // setupLocalStorageExpiry();
        clearAppLocalStorage();
        setupTabs();
        setupCAForm();
        setupCertForm();
        setupEmailForm();
        setupOutputActions();
        setupModal();
        setupCustomK8sSecret();
        setupSSLChecker();
        setupValidityInputs();
        setupPKIForm();
        setupPKICrypto();
        setupNextButtons();
        setupThemeToggle();
        setupGoToTop();
    }

    /** 
     * Clear the localstorage on a page/brower tab reload.
    */
    function clearAppLocalStorage() {
        localStorage.removeItem('theme');
    }


    /**
     * Setup modal
     */
    function setupModal() {
        const overlay = document.getElementById('modal-overlay');
        const closeBtn = document.getElementById('modal-close');

        closeBtn.addEventListener('click', hideModal);
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                hideModal();
            }
        });

        // Close on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && overlay.classList.contains('active')) {
                hideModal();
            }
        });

        // Setup key modal
        const keyOverlay = document.getElementById('key-modal-overlay');
        const keyCloseBtn = document.getElementById('key-modal-close');
        const keyCopyBtn = document.getElementById('key-modal-copy');
        const keyDownloadBtn = document.getElementById('key-modal-download');

        keyCloseBtn.addEventListener('click', hideKeyModal);
        keyOverlay.addEventListener('click', (e) => {
            if (e.target === keyOverlay) {
                hideKeyModal();
            }
        });

        keyDownloadBtn.addEventListener('click', () => {
            if (!currentKeyModalDownload) return;

            if (currentKeyModalDownload.type === 'binary') {
                Zip.downloadBinary(currentKeyModalDownload.content, currentKeyModalDownload.filename);
            } else {
                Zip.downloadPEM(currentKeyModalDownload.content, currentKeyModalDownload.filename);
            }
        });

        // Copy button handler
        keyCopyBtn.addEventListener('click', async () => {
            const content = document.getElementById('key-modal-content').textContent;
            const success = await Zip.copyToClipboard(content);
            if (success) {
                const originalText = keyCopyBtn.textContent;
                keyCopyBtn.textContent = 'Copied';
                keyCopyBtn.classList.add('copied');
                setTimeout(() => {
                    keyCopyBtn.textContent = originalText;
                    keyCopyBtn.classList.remove('copied');
                }, 2000);
            }
        });

        // Close on Escape key for key modal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && keyOverlay.classList.contains('active')) {
                hideKeyModal();
            }
        });

        // Setup CSR modal
        const csrOverlay = document.getElementById('csr-modal-overlay');
        const csrCancelBtn = document.getElementById('csr-modal-cancel');
        const csrForm = document.getElementById('csr-form');

        csrCancelBtn.addEventListener('click', hideCSRModal);
        csrOverlay.addEventListener('click', (e) => {
            if (e.target === csrOverlay) {
                hideCSRModal();
            }
        });

        // CSR form submission
        csrForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            await handleCSRGeneration();
        });

        // Add SAN button for CSR
        document.getElementById('csr-add-san').addEventListener('click', () => {
            const container = document.getElementById('csr-san-container');
            const entry = document.createElement('div');
            entry.className = 'san-entry';
            entry.innerHTML = `
                <select class="san-type">
                    <option value="DNS">DNS</option>
                    <option value="IP">IP</option>
                </select>
                <input type="text" class="san-value" placeholder="www.example.com">
                <button type="button" class="btn-remove-san">Remove</button>
            `;
            container.appendChild(entry);

            // Update placeholder when type changes
            const typeSelect = entry.querySelector('.san-type');
            const valueInput = entry.querySelector('.san-value');

            typeSelect.addEventListener('change', () => {
                if (typeSelect.value === 'DNS') {
                    valueInput.placeholder = 'www.example.com';
                } else {
                    valueInput.placeholder = '192.168.1.1';
                }
            });
        });

        // Setup CSR result modal
        const csrResultOverlay = document.getElementById('csr-result-modal-overlay');
        const csrResultCloseBtn = document.getElementById('csr-result-close');
        const csrResultCopyBtn = document.getElementById('csr-result-copy');
        const csrResultDownloadBtn = document.getElementById('csr-result-download');

        csrResultCloseBtn.addEventListener('click', hideCSRResultModal);
        csrResultOverlay.addEventListener('click', (e) => {
            if (e.target === csrResultOverlay) {
                hideCSRResultModal();
            }
        });

        csrResultCopyBtn.addEventListener('click', async () => {
            const content = document.getElementById('csr-result-content').textContent;
            const success = await Zip.copyToClipboard(content);
            if (success) {
                const originalText = csrResultCopyBtn.textContent;
                csrResultCopyBtn.textContent = 'Copied';
                csrResultCopyBtn.classList.add('copied');
                setTimeout(() => {
                    csrResultCopyBtn.textContent = originalText;
                    csrResultCopyBtn.classList.remove('copied');
                }, 2000);
            }
        });

        csrResultDownloadBtn.addEventListener('click', () => {
            const content = document.getElementById('csr-result-content').textContent;
            const keyPair = generatedPKIKeyPairs[currentPKIIndex];
            if (keyPair) {
                Zip.downloadPEM(content, `${keyPair.name}.csr`);
            }
        });

        // Close on Escape key for CSR modals
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && csrOverlay.classList.contains('active')) {
                hideCSRModal();
            }
            if (e.key === 'Escape' && csrResultOverlay.classList.contains('active')) {
                hideCSRResultModal();
            }
        });
    }

    /**
     * Expire app localStorage values after a short window
     */
    function setupLocalStorageExpiry() {
        const now = Date.now();
        const createdAt = parseInt(localStorage.getItem(LOCAL_STORAGE_CREATED_KEY), 10);

        if (createdAt && now - createdAt >= LOCAL_STORAGE_TTL_MS) {
            clearAppLocalStorage();
            localStorage.setItem(LOCAL_STORAGE_CREATED_KEY, String(now));
        } else if (!createdAt) {
            localStorage.setItem(LOCAL_STORAGE_CREATED_KEY, String(now));
        }

        window.setTimeout(() => {
            clearAppLocalStorage();
            localStorage.setItem(LOCAL_STORAGE_CREATED_KEY, String(Date.now()));
        }, LOCAL_STORAGE_TTL_MS);
    }

    /**
     * Clear localStorage keys owned by this app
     */
    function clearAppLocalStorage() {
        localStorage.removeItem('theme');
        localStorage.removeItem(LOCAL_STORAGE_CREATED_KEY);
    }

    /**
     * Show modal with message
     */
    function showModal(title, message) {
        document.getElementById('modal-title').textContent = title;
        document.getElementById('modal-message').textContent = message;
        document.getElementById('modal-overlay').classList.add('active');
    }

    /**
     * Hide modal
     */
    function hideModal() {
        document.getElementById('modal-overlay').classList.remove('active');
    }

    /**
     * Show key modal with content
     */
    function showKeyModal(title, content, downloadOptions = null) {
        document.getElementById('key-modal-title').textContent = title;
        document.getElementById('key-modal-content').textContent = content;
        currentKeyModalDownload = downloadOptions;
        document.getElementById('key-modal-download').classList.toggle('hidden', !downloadOptions);
        document.getElementById('key-modal-overlay').classList.add('active');
    }

    /**
     * Hide key modal
     */
    function hideKeyModal() {
        document.getElementById('key-modal-overlay').classList.remove('active');
        currentKeyModalDownload = null;
    }

    /**
     * Show CSR modal
     */
    function showCSRModal(index) {
        currentPKIIndex = index;
        const keyPair = generatedPKIKeyPairs[index];
        if (keyPair) {
            // Pre-fill CN with key pair name
            document.getElementById('csr-cn').value = keyPair.name;
            // Clear other fields
            document.getElementById('csr-org').value = '';
            document.getElementById('csr-org-unit').value = '';
            document.getElementById('csr-country').value = '';
            document.getElementById('csr-state').value = '';
            document.getElementById('csr-email').value = '';
            // Reset SAN entries
            const sanContainer = document.getElementById('csr-san-container');
            sanContainer.innerHTML = `
                <div class="san-entry">
                    <select class="san-type">
                        <option value="DNS">DNS</option>
                        <option value="IP">IP</option>
                    </select>
                    <input type="text" class="san-value" placeholder="www.example.com">
                    <button type="button" class="btn-remove-san">Remove</button>
                </div>
            `;
            document.getElementById('csr-modal-overlay').classList.add('active');
        }
    }

    /**
     * Hide CSR modal
     */
    function hideCSRModal() {
        document.getElementById('csr-modal-overlay').classList.remove('active');
        currentPKIIndex = null;
    }

    /**
     * Show CSR result modal
     */
    function showCSRResultModal(csrPEM) {
        document.getElementById('csr-result-content').textContent = csrPEM;
        document.getElementById('csr-result-modal-overlay').classList.add('active');
    }

    /**
     * Hide CSR result modal
     */
    function hideCSRResultModal() {
        document.getElementById('csr-result-modal-overlay').classList.remove('active');
    }

    /**
     * Setup tab navigation
     */
    function setupTabs() {
        const tabs = document.querySelectorAll('.tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const tabId = tab.dataset.tab;
                switchTab(tabId);
            });
        });
    }

    /**
     * Switch to a tab
     */
    function switchTab(tabId) {
        currentTab = tabId;

        // Update tab buttons
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.tab === tabId);
        });

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
            content.classList.add('hidden');
        });

        const activeContent = document.getElementById(`${tabId}-section`);
        if (activeContent) {
            activeContent.classList.add('active');
            activeContent.classList.remove('hidden');
        }

        // Update DevOps section
        updateDevOpsSection();
    }

    /**
     * Setup CA form
     */
    function setupCAForm() {
        const form = document.getElementById('ca-form');
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await handleCAGeneration();
        });
    }

    /**
     * Setup Certificate form
     */
    function setupCertForm() {
        const form = document.getElementById('cert-form');
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await handleCertGeneration();
        });

        // Add SAN button
        document.getElementById('add-san').addEventListener('click', addSANEntry);

        // Remove SAN buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('btn-remove-san')) {
                e.target.closest('.san-entry').remove();
            }
        });

        // Setup initial SAN entry placeholder update
        const initialTypeSelect = document.querySelector('#san-container .san-entry .san-type');
        const initialValueInput = document.querySelector('#san-container .san-value');
        if (initialTypeSelect && initialValueInput) {
            initialTypeSelect.addEventListener('change', () => {
                if (initialTypeSelect.value === 'DNS') {
                    initialValueInput.placeholder = 'www.sagarmalla.info.np';
                } else {
                    initialValueInput.placeholder = '192.168.1.8';
                }
            });
        }

        // Handle cert mode radio buttons
        const certModeRadios = document.querySelectorAll('input[name="cert-mode"]');
        const submitBtn = document.getElementById('cert-submit-btn');

        certModeRadios.forEach(radio => {
            radio.addEventListener('change', () => {
                if (radio.value === 'csr-only') {
                    submitBtn.textContent = 'Generate CSR Only';
                } else {
                    submitBtn.textContent = 'Generate Certificate';
                }
            });
        });
    }

    /**
     * Setup Email form
     */
    function setupEmailForm() {
        const form = document.getElementById('email-form');
        const emailInput = document.getElementById('email-recipient');
        const emailWarning = document.getElementById('email-warning');
        const emailContent = document.getElementById('email-content');

        // Show/hide email form based on email input
        const checkEmail = () => {
            if (emailInput.value.trim()) {
                emailWarning.classList.add('hidden');
                emailContent.classList.remove('hidden');
            } else {
                emailWarning.classList.remove('hidden');
                emailContent.classList.add('hidden');
            }
        };

        emailInput.addEventListener('input', checkEmail);

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await handleEmailSend();
        });
    }

    /**
     * Setup PKI form
     */
    function setupPKIForm() {
        const form = document.getElementById('pki-form');
        const algorithmSelect = document.getElementById('pki-algorithm');
        const curveGroup = document.getElementById('pki-curve-group');

        // Set initial state based on default algorithm
        if (algorithmSelect.value === 'ECDSA') {
            curveGroup.classList.remove('hidden');
        } else {
            curveGroup.classList.add('hidden');
        }

        // Show/hide curve field based on algorithm selection
        algorithmSelect.addEventListener('change', () => {
            if (algorithmSelect.value === 'ECDSA') {
                curveGroup.classList.remove('hidden');
            } else {
                curveGroup.classList.add('hidden');
            }
        });

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await handlePKIGeneration();
        });

        const downloadZipBtn = document.getElementById('download-pki-zip');
        if (downloadZipBtn) {
            downloadZipBtn.addEventListener('click', handlePKIZipDownload);
        }
    }

    /**
     * Setup Next buttons for workflow navigation
     */
    function setupNextButtons() {
        // CA Next button - navigate to Certificate tab
        const caNextBtn = document.getElementById('ca-next-btn');
        if (caNextBtn) {
            caNextBtn.addEventListener('click', () => {
                switchTab('cert');
            });
        }

        // Certificate Next button - navigate to DevOps tab
        const certNextBtn = document.getElementById('cert-next-btn');
        if (certNextBtn) {
            certNextBtn.addEventListener('click', () => {
                switchTab('devops');
            });
        }
    }

    /**
     * Setup output action buttons
     */
    function setupOutputActions() {
        // CA output actions
        document.querySelectorAll('[data-action^="download-ca-"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = e.target.dataset.action;
                handleCAAction(action);
            });
        });

        document.querySelectorAll('[data-action^="copy-ca-"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = e.target.dataset.action;
                handleCopyAction(action, e.target);
            });
        });

        // Certificate output actions
        document.querySelectorAll('[data-action^="download-cert-"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = e.target.dataset.action;
                handleCertAction(action);
            });
        });

        document.querySelectorAll('[data-action^="copy-cert-"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = e.target.dataset.action;
                handleCopyAction(action, e.target);
            });
        });

        // DevOps actions
        document.querySelectorAll('[data-action^="copy-k8s-"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = e.target.dataset.action;
                handleCopyAction(action, e.target);
            });
        });

        // PKI actions
        document.querySelectorAll('[data-action^="copy-pki-"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = e.target.dataset.action;
                handleCopyAction(action, e.target);
            });
        });

        // SSL checker actions
        document.querySelectorAll('[data-action^="copy-ssl-"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = e.target.dataset.action;
                handleCopyAction(action, e.target);
            });
        });

        // PEM toggle buttons
        document.querySelectorAll('.btn-toggle').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const target = e.target.dataset.target;
                const element = document.getElementById(target);
                if (element) {
                    element.classList.toggle('hidden');
                }
            });
        });

        // CLI copy buttons
        document.querySelectorAll('.btn-copy').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const target = e.target.dataset.target;
                const element = document.getElementById(target);
                if (element) {
                    const text = element.textContent;
                    const success = await Zip.copyToClipboard(text);
                    if (success) {
                        const originalText = e.target.textContent;
                        e.target.textContent = 'Copied';
                        e.target.classList.add('copied');
                        setTimeout(() => {
                            e.target.textContent = originalText;
                            e.target.classList.remove('copied');
                        }, 2000);
                    }
                }
            });
        });
    }

    /**
     * Add SAN entry
     */
    function addSANEntry() {
        const container = document.getElementById('san-container');
        const entry = document.createElement('div');
        entry.className = 'san-entry';
        entry.innerHTML = `
            <select class="san-type">
                <option value="DNS">DNS</option>
                <option value="IP">IP</option>
            </select>
            <input type="text" class="san-value" placeholder="www.sagarmalla.info.np">
            <button type="button" class="btn-remove-san">Remove</button>
        `;
        container.appendChild(entry);

        // Update placeholder when type changes
        const typeSelect = entry.querySelector('.san-type');
        const valueInput = entry.querySelector('.san-value');

        typeSelect.addEventListener('change', () => {
            if (typeSelect.value === 'DNS') {
                valueInput.placeholder = 'www.sagarmalla.info.np';
            } else {
                valueInput.placeholder = '192.168.1.8';
            }
        });
    }

    /**
     * Get SAN entries from form
     */
    function getSANEntries() {
        const entries = [];
        document.querySelectorAll('.san-entry').forEach(entry => {
            const type = entry.querySelector('.san-type').value;
            const value = entry.querySelector('.san-value').value.trim();
            if (value) {
                entries.push({ type, value });
            }
        });
        return entries;
    }

    /**
     * Validate domain name
     * Accepts regular domains, localhost, and wildcard entries
     */
    function validateDomain(domain) {
        // Allow localhost
        if (domain === 'localhost') {
            return true;
        }

        // Allow wildcard domains (*.example.com)
        if (domain.startsWith('*.')) {
            const baseDomain = domain.substring(2);
            const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
            return domainRegex.test(baseDomain);
        }

        // Regular domain validation
        const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
        return domainRegex.test(domain);
    }

    /**
     * Validate IP address
     */
    function validateIP(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }

    /**
     * Validate email address
     */
    function validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    /**
     * Show error message
     */
    function showError(message) {
        showModal('Error', message);
    }

    /**
     * Show success message
     */
    function showSuccess(message) {
        showModal('Success', message);
    }

    /**
     * Show info message temporarily
     */
    function showInfo(message) {
        const existing = document.querySelector('.info-message');
        if (existing) existing.remove();

        const div = document.createElement('div');
        div.className = 'info-message';
        div.textContent = message;
        document.querySelector('.container').prepend(div);
        return div;
    }

    /**
     * Hide info message
     */
    function hideMessage(el) {
        if (el && el.parentNode) el.remove();
    }

    /**
     * Setup SSL certificate checker
     */
    function setupSSLChecker() {
        const domainBtn = document.getElementById('ssl-check-domain');
        const fileBtn = document.getElementById('ssl-check-file');
        const pemBtn = document.getElementById('ssl-check-pem');
        const fileInput = document.getElementById('ssl-cert-file');
        const domainInput = document.getElementById('ssl-domain');
        const portInput = document.getElementById('ssl-port');

        if (!domainBtn || !fileBtn || !pemBtn || !fileInput || !domainInput || !portInput) return;

        domainBtn.addEventListener('click', handleSSLDomainCheck);
        domainInput.addEventListener('input', updateSSLOpenSSLCommands);
        portInput.addEventListener('input', updateSSLOpenSSLCommands);
        fileBtn.addEventListener('click', async () => {
            if (fileInput.files.length === 0) {
                showError('Please upload a certificate file');
                return;
            }

            try {
                const pem = await readFileAsText(fileInput.files[0]);
                document.getElementById('ssl-pem-content').value = pem;
                parseAndDisplaySSLCertificates(pem);
            } catch (error) {
                showError(`Failed to read certificate file: ${error.message}`);
            }
        });

        pemBtn.addEventListener('click', () => {
            const pem = document.getElementById('ssl-pem-content').value.trim();
            if (!pem) {
                showError('Please paste PEM certificate content');
                return;
            }

            parseAndDisplaySSLCertificates(pem);
        });

        updateSSLOpenSSLCommands();
    }

    /**
     * Update SSL checker OpenSSL command examples
     */
    function updateSSLOpenSSLCommands() {
        const domain = document.getElementById('ssl-domain').value.trim() || 'sagarmalla.info.np';
        const port = document.getElementById('ssl-port').value.trim() || '443';
        const commands = `# Fetch and print the remote certificate chain
openssl s_client -connect ${domain}:${port} -servername ${domain} -showcerts </dev/null

# Show remote leaf certificate details
openssl s_client -connect ${domain}:${port} -servername ${domain} </dev/null 2>/dev/null | \\
  openssl x509 -noout -text

# Show certificate subject, issuer, serial, SAN, and validity dates
openssl s_client -connect ${domain}:${port} -servername ${domain} </dev/null 2>/dev/null | \\
  openssl x509 -noout -subject -issuer -serial -dates -ext subjectAltName

# Check local certificate file details
openssl x509 -in certificate.pem -noout -text

# Check whether a local certificate expires within 30 days
openssl x509 -in certificate.pem -noout -checkend 2592000`;

        document.getElementById('ssl-openssl-commands').textContent = commands;
    }

    /**
     * Explain remote domain SSL checking limitation in a browser-only app
     */
    async function handleSSLDomainCheck() {
        const domain = document.getElementById('ssl-domain').value.trim();
        const port = parseInt(document.getElementById('ssl-port').value, 10);

        if (!domain) {
            showError('Domain name is required');
            return;
        }

        if (!port || port < 1 || port > 65535) {
            showError('Port number must be between 1 and 65535');
            return;
        }

        const command = `openssl s_client -connect ${domain}:${port} -servername ${domain} -showcerts </dev/null 2>/dev/null`;

        // Try SSL Labs API first (works on static hosts)
        try {
            const sslLabsResponse = await fetch(
                `https://api.ssllabs.com/api/v4/analyze?host=${encodeURIComponent(domain)}&port=${port}&startNew=on&all=done`
            );

            if (sslLabsResponse.ok) {
                const data = await sslLabsResponse.json();
                await pollSSLabsResults(domain, port, command);
                return;
            }
        } catch (e) {
            console.log('SSL Labs not available, trying helper server...');
        }

        // Fallback to local helper if available
        if (isLocalSSLHelperHost()) {
            try {
                const response = await fetch(`/api/ssl-check?domain=${encodeURIComponent(domain)}&port=${encodeURIComponent(port)}`);
                const result = await response.json();

                if (!response.ok) {
                    throw new Error(result.error || 'Unable to fetch certificate');
                }

                document.getElementById('ssl-pem-content').value = result.pem;
                if (result.certificates && result.certificates.length > 0) {
                    renderParsedSSLDetails(result.certificates);
                } else {
                    parseAndDisplaySSLCertificates(result.pem);
                }
                return;
            } catch (error) {
                console.log('Local helper server check failed:', error.message);
            }
        }

        // Try Netlify function (works when deployed to Netlify)
        try {
            const netlifyResponse = await fetch('/.netlify/functions/ssl-check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain, port })
            });

            if (netlifyResponse.ok) {
                const result = await netlifyResponse.json();
                document.getElementById('ssl-pem-content').value = result.pem;
                if (result.certificates && result.certificates.length > 0) {
                    renderParsedSSLDetails(result.certificates);
                } else {
                    parseAndDisplaySSLCertificates(result.pem);
                }
                return;
            }
        } catch (e) {
            console.log('Netlify function not available:', e.message);
        }

        // No API available - show helpful modal with copy button
        showModal(
            'Domain SSL Check',
            `Live domain checks require a server-side helper.\n\nThis feature works on:\n• Netlify (auto-detected when deployed)\n• Locally with \`node assets/js/server.js\`\n\nOn GitHub Pages, run this command locally and paste the PEM output:\n\n${command}`
        );

        // Auto-select the text for easy copying
        setTimeout(() => {
            const messageEl = document.getElementById('modal-message');
            if (messageEl) {
                messageEl.style.userSelect = 'all';
                messageEl.style.cursor = 'text';
            }
        }, 100);
    }

    /**
     * Poll SSL Labs API for results
     */
    async function pollSSLabsResults(domain, port, command, maxAttempts = 20) {
        const statusDiv = showInfo('Checking SSL Labs... (this may take 10-20 seconds)');

        for (let i = 0; i < maxAttempts; i++) {
            await new Promise(resolve => setTimeout(resolve, 3000));

            try {
                const response = await fetch(
                    `https://api.ssllabs.com/api/v4/analyze?host=${encodeURIComponent(domain)}&port=${port}&startNew=off&all=done`
                );
                const data = await response.json();

                if (data.status === 'READY' || data.status === 'ERROR') {
                    hideMessage(statusDiv);

                    if (data.status === 'ERROR' || !data.endpoints || data.endpoints.length === 0) {
                        showError('SSL check failed. Try again or use the OpenSSL command below.');
                        return;
                    }

                    const endpoint = data.endpoints[0];
                    const cert = data.certs ? data.certs[0] : null;

                    if (cert && cert.derBase64) {
                        // Convert DER base64 to PEM
                        const pem = `-----BEGIN CERTIFICATE-----\n${cert.derBase64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
                        document.getElementById('ssl-pem-content').value = pem;
                        parseAndDisplaySSLCertificates(pem);
                    } else {
                        showError('Could not extract certificate from SSL Labs. Use the OpenSSL command below.');
                    }
                    return;
                }
            } catch (e) {
                console.log('Polling error:', e);
            }
        }

        hideMessage(statusDiv);
        showError('SSL Labs check timed out. Please use the OpenSSL command below.');
    }

    /**
     * Only call the SSL helper endpoint on local server hosts.
     */
    function isLocalSSLHelperHost() {
        const hostname = window.location.hostname;
        return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
    }

    /**
     * Parse PEM certificates and render SSL details
     */
    function parseAndDisplaySSLCertificates(pemContent) {
        try {
            const certs = extractCertificatesFromPEM(pemContent).map(pem => forge.pki.certificateFromPem(pem));

            if (certs.length === 0) {
                showError('No PEM certificates found');
                return;
            }

            renderSSLDetails(certs);
        } catch (error) {
            showError(`Failed to parse certificate: ${error.message}`);
        }
    }

    /**
     * Render SSL details already parsed by the local helper server
     */
    function renderParsedSSLDetails(certs) {
        const leaf = certs[0];

        setText('ssl-detail-cn', leaf.commonName);
        setText('ssl-detail-san', leaf.subjectAlternativeNames);
        setText('ssl-detail-org', leaf.organization);
        setText('ssl-detail-ou', leaf.organizationUnit);
        setText('ssl-detail-locality', leaf.locality);
        setText('ssl-detail-state', leaf.state);
        setText('ssl-detail-country', leaf.country);
        setText('ssl-detail-valid-from', formatCertificateDate(new Date(leaf.validFrom)));
        setText('ssl-detail-valid-to', formatCertificateDate(new Date(leaf.validTo)));
        setExpiryStatus(new Date(leaf.validTo));
        setText('ssl-detail-issuer', leaf.issuer);
        setText('ssl-detail-serial', leaf.serialNumber);
        setText('ssl-detail-summary', `${leaf.commonName || 'Certificate'} issued by ${leaf.issuer || 'unknown issuer'}`);

        renderParsedSSLChain(certs);

        const output = document.getElementById('ssl-checker-output');
        output.classList.remove('hidden');
        output.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    /**
     * Render parsed certificate chain cards
     */
    function renderParsedSSLChain(certs) {
        const chainList = document.getElementById('ssl-chain-list');
        chainList.innerHTML = '';

        certs.forEach((cert, index) => {
            const item = document.createElement('div');
            item.className = 'ssl-chain-item';
            item.innerHTML = `
                <h5>${index === 0 ? 'Leaf Certificate' : `Chain Certificate ${index}`}</h5>
                <p><strong>Subject:</strong> ${escapeHTML(cert.subject)}</p>
                <p><strong>Issuer:</strong> ${escapeHTML(cert.issuer)}</p>
                <p><strong>Valid:</strong> ${escapeHTML(formatCertificateDate(new Date(cert.validFrom)))} to ${escapeHTML(formatCertificateDate(new Date(cert.validTo)))}</p>
                <p><strong>Serial Number:</strong> ${escapeHTML(cert.serialNumber)}</p>
            `;
            chainList.appendChild(item);
        });
    }

    /**
     * Extract all PEM certificate blocks from pasted text
     */
    function extractCertificatesFromPEM(pemContent) {
        const matches = pemContent.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
        return matches || [];
    }

    /**
     * Render primary certificate details and chain
     */
    function renderSSLDetails(certs) {
        const leaf = certs[0];
        const subject = getCertificateAttributeMap(leaf.subject.attributes);
        const issuerText = formatCertificateName(leaf.issuer.attributes);

        setText('ssl-detail-cn', subject.CN);
        setText('ssl-detail-san', formatSubjectAlternativeNames(leaf));
        setText('ssl-detail-org', subject.O);
        setText('ssl-detail-ou', subject.OU);
        setText('ssl-detail-locality', subject.L);
        setText('ssl-detail-state', subject.ST);
        setText('ssl-detail-country', subject.C);
        setText('ssl-detail-valid-from', formatCertificateDate(leaf.validity.notBefore));
        setText('ssl-detail-valid-to', formatCertificateDate(leaf.validity.notAfter));
        setExpiryStatus(leaf.validity.notAfter);
        setText('ssl-detail-issuer', issuerText);
        setText('ssl-detail-serial', normalizeSerialNumber(leaf.serialNumber));
        setText('ssl-detail-summary', `${subject.CN || 'Certificate'} issued by ${issuerText || 'unknown issuer'}`);

        renderSSLChain(certs);

        const output = document.getElementById('ssl-checker-output');
        output.classList.remove('hidden');
        output.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    /**
     * Render certificate chain cards
     */
    function renderSSLChain(certs) {
        const chainList = document.getElementById('ssl-chain-list');
        chainList.innerHTML = '';

        certs.forEach((cert, index) => {
            const subjectText = formatCertificateName(cert.subject.attributes);
            const issuerText = formatCertificateName(cert.issuer.attributes);
            const item = document.createElement('div');
            item.className = 'ssl-chain-item';
            item.innerHTML = `
                <h5>${index === 0 ? 'Leaf Certificate' : `Chain Certificate ${index}`}</h5>
                <p><strong>Subject:</strong> ${escapeHTML(subjectText)}</p>
                <p><strong>Issuer:</strong> ${escapeHTML(issuerText)}</p>
                <p><strong>Valid:</strong> ${escapeHTML(formatCertificateDate(cert.validity.notBefore))} to ${escapeHTML(formatCertificateDate(cert.validity.notAfter))}</p>
                <p><strong>Serial Number:</strong> ${escapeHTML(normalizeSerialNumber(cert.serialNumber))}</p>
            `;
            chainList.appendChild(item);
        });
    }

    /**
     * Safely set text content with a fallback
     */
    function setText(id, value) {
        document.getElementById(id).textContent = value || '-';
    }

    /**
     * Set expiry text and status classes
     */
    function setExpiryStatus(validTo) {
        const expiryElement = document.getElementById('ssl-detail-expired-in');
        const badge = document.getElementById('ssl-validity-badge');
        const days = getDaysUntilExpiry(validTo);
        const status = getExpiryStatus(days);
        const text = formatExpiryFromDays(days);

        expiryElement.textContent = text;
        expiryElement.classList.remove('ssl-expired', 'ssl-expiring', 'ssl-valid');
        expiryElement.classList.add(`ssl-${status}`);

        badge.textContent = status === 'expired' ? 'Expired' : status === 'expiring' ? 'Expiring Soon' : 'Valid';
        badge.classList.remove('expired', 'expiring');
        if (status !== 'valid') {
            badge.classList.add(status);
        }
    }

    /**
     * Build a convenient attribute lookup from forge certificate attributes
     */
    function getCertificateAttributeMap(attributes) {
        return attributes.reduce((map, attr) => {
            const key = attr.shortName || attr.name;
            if (!map[key]) {
                map[key] = attr.value;
            }
            return map;
        }, {});
    }

    /**
     * Format certificate subject or issuer attributes
     */
    function formatCertificateName(attributes) {
        const map = getCertificateAttributeMap(attributes);
        return [map.CN, map.O, map.OU, map.L, map.ST, map.C].filter(Boolean).join(', ') || '-';
    }

    /**
     * Format SAN entries from a certificate
     */
    function formatSubjectAlternativeNames(cert) {
        const sanExtension = cert.getExtension('subjectAltName');
        if (!sanExtension || !sanExtension.altNames || sanExtension.altNames.length === 0) {
            return '-';
        }

        return sanExtension.altNames.map(altName => {
            if (altName.type === 2) {
                return altName.value;
            }
            if (altName.type === 7) {
                return `IP Address:${altName.ip || altName.value}`;
            }
            if (altName.type === 6) {
                return `URI:${altName.value}`;
            }
            if (altName.type === 1) {
                return `Email:${altName.value}`;
            }
            return altName.value || altName.ip || `Type ${altName.type}`;
        }).filter(Boolean).join(', ');
    }

    /**
     * Format a certificate date
     */
    function formatCertificateDate(date) {
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    }

    /**
     * Format time until expiry
     */
    function formatExpiry(validTo) {
        return formatExpiryFromDays(getDaysUntilExpiry(validTo));
    }

    /**
     * Get days until expiry
     */
    function getDaysUntilExpiry(validTo) {
        const now = new Date();
        const msRemaining = validTo.getTime() - now.getTime();
        return Math.ceil(msRemaining / (24 * 60 * 60 * 1000));
    }

    /**
     * Convert days until expiry to text
     */
    function formatExpiryFromDays(days) {
        if (days < 0) {
            return `Expired ${Math.abs(days)} days ago`;
        }
        if (days === 0) {
            return 'Expires today';
        }
        return `${days} days`;
    }

    /**
     * Convert days until expiry to status name
     */
    function getExpiryStatus(days) {
        if (days < 0) return 'expired';
        if (days <= 30) return 'expiring';
        return 'valid';
    }

    /**
     * Normalize certificate serial number text
     */
    function normalizeSerialNumber(serialNumber) {
        return (serialNumber || '').replace(/^00/, '').toLowerCase();
    }

    /**
     * Escape HTML before rendering chain cards
     */
    function escapeHTML(value) {
        return String(value || '-')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    /**
     * Handle CA generation
     */
    async function handleCAGeneration() {
        try {
            const name = document.getElementById('ca-name').value.trim();
            const org = document.getElementById('ca-org').value.trim();
            const orgUnit = document.getElementById('ca-org-unit').value.trim();
            const country = document.getElementById('ca-country').value.trim().toUpperCase();
            const state = document.getElementById('ca-state').value.trim();
            const email = document.getElementById('ca-email').value.trim();
            const validity = parseInt(document.getElementById('ca-validity').value);
            const algorithm = document.getElementById('ca-algorithm').value;
            const validityWarning = document.querySelector('#ca-form .validity-warning');

            // Validate mandatory fields
            if (!name) {
                showError('CA Common Name (CN) is required');
                return;
            }

            // Validate country if provided
            if (country && country.length !== 2) {
                showError('Country must be a 2-letter ISO code');
                return;
            }

            // Validate email if provided
            if (email && !validateEmail(email)) {
                showError('Invalid email address');
                return;
            }

            // Validate validity range (1-10 years)
            if (validity < 1 || validity > 10) {
                showError('Validity Period must be between 1 and 10 years');
                return;
            }

            // Show warning if validity < 3 years for CA
            if (validity < 3) {
                validityWarning.textContent = 'It is recommended to set the validity period to at least 3 years for a CA certificate.';
                validityWarning.classList.remove('hidden');
                // Continue anyway, just show warning
            } else {
                validityWarning.classList.add('hidden');
            }

            const result = await Cert.generateRootCA(name, org, country, validity, algorithm, state, '', orgUnit, email);
            generatedCA = result;

            // Show output
            const output = document.getElementById('ca-output');
            output.classList.remove('hidden');

            // Display PEM
            document.getElementById('ca-crt-pem').textContent = result.pemCert;

            // Display OpenSSL commands
            const opensslCommands = `# Generate CA Private Key
openssl genrsa -out ca.key 2048

# Generate CA Certificate
openssl req -new -x509 -key ca.key -sha256 -days ${validity * 365} -out ca.crt \\
  -subj "/C=${country || ''}/ST=${state || ''}/O=${org || ''}/OU=${orgUnit || ''}/CN=${name}/emailAddress=${email || ''}" \\
  -addext "basicConstraints=critical,CA:TRUE" \\
  -addext "keyUsage=critical,keyCertSign,cRLSign"`;
            document.getElementById('ca-openssl').textContent = opensslCommands;

            showSuccess('CA Certificate generated successfully!');
            updateDevOpsSection();

            // Scroll to output section
            output.scrollIntoView({ behavior: 'smooth', block: 'start' });

        } catch (error) {
            showError(`Failed to generate CA: ${error.message}`);
        }
    }

    /**
     * Handle certificate generation
     */
    async function handleCertGeneration() {
        try {
            const domain = document.getElementById('cert-domain').value.trim();
            const org = document.getElementById('cert-org').value.trim();
            const orgUnit = document.getElementById('cert-org-unit').value.trim();
            const country = document.getElementById('cert-country').value.trim().toUpperCase();
            const state = document.getElementById('cert-state').value.trim();
            const email = document.getElementById('cert-email').value.trim();
            const validity = parseInt(document.getElementById('cert-validity').value);
            const algorithm = document.getElementById('cert-algorithm').value;
            const sanEntries = getSANEntries();
            const validityWarning = document.querySelector('#cert-form .validity-warning');
            const certMode = document.querySelector('input[name="cert-mode"]:checked').value;

            // Validate mandatory fields
            if (!domain) {
                showError('Domain / Common Name (CN) is required');
                return;
            }

            // SAN is mandatory for certificates and CSR
            if (sanEntries.length === 0) {
                showError('At least one Subject Alternative Name (SAN) entry is required');
                return;
            }

            // Validate country if provided
            if (country && country.length !== 2) {
                showError('Country must be a 2-letter ISO code');
                return;
            }

            // Validate email if provided
            if (email && !validateEmail(email)) {
                showError('Invalid email address');
                return;
            }

            // Validate validity range (1-10 years) - only for certificate mode
            if (certMode === 'certificate') {
                if (validity < 1 || validity > 10) {
                    showError('Validity Period must be between 1 and 10 years');
                    return;
                }

                // Show warning if validity < 1 year for certificate
                if (validity < 1) {
                    validityWarning.textContent = 'It is recommended to set the validity period to at least 1 year for a certificate.';
                    validityWarning.classList.remove('hidden');
                } else {
                    validityWarning.classList.add('hidden');
                }
            }

            // Handle CSR-only mode
            if (certMode === 'csr-only') {
                await handleCSROnlyGeneration(domain, org, country, state, '', orgUnit, email, sanEntries, algorithm);
                return;
            }

            // Handle certificate generation (existing logic)
            const result = await Cert.generateCertificate(
                domain, org, country, validity, algorithm, sanEntries, false, state, '', orgUnit, email
            );
            generatedCert = result;

            // Show output
            const output = document.getElementById('cert-output');
            output.classList.remove('hidden');

            // Update domain name placeholders
            document.querySelectorAll('.domain-name').forEach(el => {
                el.textContent = domain;
            });

            // Display PEMs
            document.getElementById('cert-key-pem').textContent = result.pemKey;
            document.getElementById('cert-crt-pem').textContent = result.pemCert;

            // Hide CSR section for certificate mode
            const csrViewer = document.getElementById('csr-pem-viewer');
            const csrBtn = document.getElementById('download-cert-csr-btn');
            csrViewer.classList.add('hidden');
            csrBtn.classList.add('hidden');

            // Display OpenSSL commands
            const sanStr = sanEntries.map(e => `${e.type}:${e.value}`).join(',');
            const opensslCommands = `# Generate Private Key
openssl genrsa -out ${domain}.key 2048

# Generate CSR
openssl req -new -key ${domain}.key -out ${domain}.csr \\
  -subj "/C=${country || ''}/ST=${state || ''}/O=${org || ''}/OU=${orgUnit || ''}/CN=${domain}/emailAddress=${email || ''}" \\
  -addext "subjectAltName=${sanStr}"

# Sign with CA
openssl x509 -req -in ${domain}.csr -CA ca.crt -CAkey ca.key \\
  -CAcreateserial -out ${domain}.crt -days ${validity * 365} \\
  -sha256 -extfile <(printf "subjectAltName=${sanStr}")`;
            document.getElementById('cert-openssl').textContent = opensslCommands;

            showSuccess('Certificate generated successfully!');
            updateDevOpsSection();

            // Scroll to output section
            output.scrollIntoView({ behavior: 'smooth', block: 'start' });

        } catch (error) {
            showError(`Failed to generate certificate: ${error.message}`);
        }
    }

    /**
     * Handle CSR-only generation
     */
    async function handleCSROnlyGeneration(cn, org, country, state, locality, orgUnit, email, sanEntries, algorithm) {
        try {
            // Generate key pair
            const keyPair = await Crypto.generateKeyPair(algorithm);

            // Generate CSR
            const csrPEM = await generateCSRFromKeyPair(
                { pemKey: forge.pki.privateKeyToPem(keyPair.privateKey), pemPub: forge.pki.publicKeyToPem(keyPair.publicKey), algorithm: algorithm.split('-')[0] },
                cn, org, country, state, locality, orgUnit, email, sanEntries
            );

            // Show output
            const output = document.getElementById('cert-output');
            output.classList.remove('hidden');

            // Update domain name placeholders
            document.querySelectorAll('.domain-name').forEach(el => {
                el.textContent = cn;
            });

            // Display PEMs
            document.getElementById('cert-key-pem').textContent = forge.pki.privateKeyToPem(keyPair.privateKey);
            document.getElementById('cert-crt-pem').textContent = 'Certificate not generated (CSR-only mode)';

            // Show CSR
            const csrViewer = document.getElementById('csr-pem-viewer');
            const csrBtn = document.getElementById('download-cert-csr-btn');
            csrViewer.classList.remove('hidden');
            csrBtn.classList.remove('hidden');
            document.getElementById('cert-csr-pem').textContent = csrPEM;

            // Update generatedCert for download actions
            generatedCert = {
                pemKey: forge.pki.privateKeyToPem(keyPair.privateKey),
                pemCert: null,
                pemCSR: csrPEM
            };

            // Display OpenSSL commands
            const sanStr = sanEntries.map(e => `${e.type}:${e.value}`).join(',');
            const opensslCommands = `# Generate Private Key
openssl genrsa -out ${cn}.key 2048

# Generate CSR
openssl req -new -key ${cn}.key -out ${cn}.csr \\
  -subj "/C=${country || ''}/ST=${state || ''}/O=${org || ''}/OU=${orgUnit || ''}/CN=${cn}/emailAddress=${email || ''}" \\
  -addext "subjectAltName=${sanStr}"

# Send CSR to your CA for signing
# The CA will return a signed certificate`;
            document.getElementById('cert-openssl').textContent = opensslCommands;

            showSuccess('CSR generated successfully! Send it to your CA for signing.');

            // Scroll to output section
            output.scrollIntoView({ behavior: 'smooth', block: 'start' });

        } catch (error) {
            showError(`Failed to generate CSR: ${error.message}`);
        }
    }

    /**
     * Handle CA action
     */
    function handleCAAction(action) {
        if (!generatedCA) {
            showError('No CA generated yet');
            return;
        }

        switch (action) {
            case 'download-ca-key':
                Zip.downloadPEM(generatedCA.pemKey, 'ca.key');
                break;
            case 'download-ca-crt':
                Zip.downloadPEM(generatedCA.pemCert, 'ca.crt');
                break;
        }
    }

    /**
     * Handle certificate action
     */
    function handleCertAction(action) {
        if (!generatedCert) {
            showError('No certificate generated yet');
            return;
        }

        const domain = document.getElementById('cert-domain').value.trim();

        switch (action) {
            case 'download-cert-key':
                Zip.downloadPEM(generatedCert.pemKey, `${domain}.key`);
                break;
            case 'download-cert-crt':
                Zip.downloadPEM(generatedCert.pemCert, `${domain}.crt`);
                break;
            case 'download-cert-csr':
                if (generatedCert.pemCSR) {
                    Zip.downloadPEM(generatedCert.pemCSR, `${domain}.csr`);
                }
                break;
            case 'download-cert-zip':
                const caPemCert = generatedCA ? generatedCA.pemCert : null;
                const caPemKey = generatedCA ? generatedCA.pemKey : null;
                Zip.downloadBundle(
                    caPemCert,
                    caPemKey,
                    generatedCert.pemCert,
                    generatedCert.pemKey,
                    generatedCert.pemCSR,
                    domain
                );
                break;
        }
    }

    /**
     * Handle copy action
     */
    async function handleCopyAction(action, button) {
        let text = '';

        switch (action) {
            case 'copy-ca-pem':
                text = generatedCA ? generatedCA.pemCert : '';
                break;
            case 'copy-ca-openssl':
                text = document.getElementById('ca-openssl').textContent;
                break;
            case 'copy-cert-openssl':
                text = document.getElementById('cert-openssl').textContent;
                break;
            case 'copy-k8s-tls':
                text = document.getElementById('k8s-tls-secret').textContent;
                break;
            case 'copy-k8s-ca':
                text = document.getElementById('k8s-ca-secret').textContent;
                break;
            case 'copy-ca-crt':
                text = generatedCA ? generatedCA.pemCert : '';
                break;
            case 'copy-ca-key':
                text = generatedCA ? generatedCA.pemKey : '';
                break;
            case 'copy-cert-crt':
                text = generatedCert ? generatedCert.pemCert : '';
                break;
            case 'copy-cert-key':
                text = generatedCert ? generatedCert.pemKey : '';
                break;
            case 'copy-pki-openssl':
                text = document.getElementById('pki-openssl').textContent;
                break;
            case 'copy-ssl-openssl':
                text = document.getElementById('ssl-openssl-commands').textContent;
                break;
        }

        if (text) {
            const success = await Zip.copyToClipboard(text);
            if (success && button) {
                const originalText = button.textContent;
                button.textContent = 'Copied';
                button.classList.add('copied');
                setTimeout(() => {
                    button.textContent = originalText;
                    button.classList.remove('copied');
                }, 2000);
            } else if (!success) {
                showError('Failed to copy to clipboard');
            }
        }
    }

    /**
     * Handle email send
     */
    async function handleEmailSend() {
        const recipient = document.getElementById('email-recipient').value.trim();

        if (!recipient) {
            showError('Recipient email is required');
            return;
        }

        if (!generatedCert) {
            showError('Generate a certificate first');
            return;
        }

        const domain = document.getElementById('cert-domain').value.trim();
        const caPemCert = generatedCA ? generatedCA.pemCert : null;
        const caPemKey = generatedCA ? generatedCA.pemKey : null;

        try {
            const base64Zip = await Zip.getBundleAsBase64(
                caPemCert,
                caPemKey,
                generatedCert.pemCert,
                generatedCert.pemKey,
                generatedCert.pemCSR,
                domain
            );

            // Check if EmailJS is configured
            if (typeof emailjs !== 'undefined') {
                await emailjs.send('default_service', 'template_ssl_bundle', {
                    to_email: recipient,
                    attachment: base64Zip,
                    filename: `${domain}-bundle.zip`
                });
                showSuccess('Email sent successfully!');
            } else {
                showError('EmailJS not configured. Please set up EmailJS in the HTML file.');
            }

        } catch (error) {
            showError(`Failed to send email: ${error.message}`);
        }
    }

    /**
     * Handle PKI key pair generation
     */
    async function handlePKIGeneration() {
        try {
            const name = document.getElementById('pki-name').value.trim();
            const count = parseInt(document.getElementById('pki-count').value);
            const size = parseInt(document.getElementById('pki-size').value);
            const algorithm = document.getElementById('pki-algorithm').value;
            const curve = document.getElementById('pki-curve').value;
            const pkcs12Password = getPKCS12Password();

            // Validate mandatory fields
            if (!name) {
                showError('Key Pair Name is required');
                return;
            }

            // Validate curve if ECDSA
            if (algorithm === 'ECDSA' && !curve) {
                showError('Key Pair Curve Name is required for ECDSA algorithm');
                return;
            }

            // Generate key pairs
            const keyPairs = [];
            for (let i = 0; i < count; i++) {
                const keyPairName = count > 1 ? `${name}_${i + 1}` : name;
                const algorithmStr = algorithm === 'ECDSA' ? `ECDSA-${size}-${curve}` : `RSA-${size}`;
                const keyPair = await Crypto.generateKeyPair(algorithmStr);

                let pemKey, pemPub, pkcs8Key, pkcs12Bundle;

                if (keyPair._isECDSA) {
                    // ECDSA: export directly via Web Crypto
                    pemKey = await Crypto.exportPrivateKeyToPEM(keyPair);
                    pemPub = await Crypto.exportPublicKeyToPEM(keyPair);
                    // PKCS8 is the same as PEM for ECDSA
                    pkcs8Key = pemKey;
                    // PKCS12 not supported for ECDSA in this implementation
                    pkcs12Bundle = null;
                } else {
                    // RSA: use forge directly
                    pemKey = forge.pki.privateKeyToPem(keyPair.privateKey);
                    pemPub = forge.pki.publicKeyToPem(keyPair.publicKey);

                    // Generate PKCS8 format
                    const asn1 = forge.pki.privateKeyToAsn1(keyPair.privateKey);
                    const pkcs8 = forge.pki.wrapRsaPrivateKey(asn1);
                    pkcs8Key = forge.pki.privateKeyInfoToPem(pkcs8);

                    // Generate PKCS12 bundle
                    try {
                        const p12Cert = createPKIKeyPairCertificate(keyPairName, keyPair);
                        const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
                            keyPair.privateKey,
                            [p12Cert],
                            pkcs12Password,
                            {
                                algorithm: '3des',
                                friendlyName: keyPairName
                            }
                        );
                        pkcs12Bundle = binaryStringToUint8Array(forge.asn1.toDer(p12Asn1).getBytes());
                    } catch (e) {
                        pkcs12Bundle = null;
                    }
                }

                keyPairs.push({
                    name: keyPairName,
                    size: size,
                    algorithm: algorithm,
                    curve: algorithm === 'ECDSA' ? curve : 'N/A',
                    formats: {
                        pem: { key: pemKey, pub: pemPub },
                        pkcs8: { key: pkcs8Key, pub: pemPub },
                        pkcs12: pkcs12Bundle
                    },
                    pkcs12Password,
                    pemKey,
                    pemPub
                });
            }

            // Display key pairs in table
            displayPKIKeyPairs(keyPairs);
            prefillLatestRSAKeys(false);

            // Generate OpenSSL commands
            const opensslCommands = generatePKIOpenSSLCommands(name, count, size, algorithm, curve, pkcs12Password);

            // Show output section
            const output = document.getElementById('pki-output');
            output.classList.remove('hidden');

            // Display OpenSSL commands
            document.getElementById('pki-openssl').textContent = opensslCommands;

            showSuccess('Key pairs generated successfully!');

            // Scroll to output section
            output.scrollIntoView({ behavior: 'smooth', block: 'start' });

        } catch (error) {
            showError(`Failed to generate key pairs: ${error.message}`);
        }
    }

    /**
     * Create a minimal self-signed certificate so RSA key pairs can be exported as PKCS12
     */
    function createPKIKeyPairCertificate(keyPairName, keyPair) {
        const cert = forge.pki.createCertificate();
        const now = new Date();

        cert.publicKey = keyPair.publicKey;
        cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
        cert.validity.notBefore = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        cert.validity.notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
        cert.setSubject([{ name: 'commonName', value: keyPairName }]);
        cert.setIssuer([{ name: 'commonName', value: keyPairName }]);
        cert.setExtensions([
            {
                name: 'basicConstraints',
                cA: false
            },
            {
                name: 'keyUsage',
                digitalSignature: true,
                keyEncipherment: true
            },
            {
                name: 'subjectKeyIdentifier'
            }
        ]);
        cert.sign(keyPair.privateKey, forge.md.sha256.create());

        return cert;
    }

    /**
     * Convert forge binary string output to bytes safe for Blob and ZIP download
     */
    function binaryStringToUint8Array(binaryString) {
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
    }

    /**
     * Get PKCS12 password from form, defaulting when blank
     */
    function getPKCS12Password() {
        const passwordInput = document.getElementById('pki-pkcs12-password');
        const password = passwordInput ? passwordInput.value.trim() : '';
        return password || 'password123';
    }

    /**
     * Convert bytes to base64 for binary previews
     */
    function uint8ArrayToBase64(bytes) {
        let binary = '';
        bytes.forEach(byte => {
            binary += String.fromCharCode(byte);
        });
        return window.btoa(binary);
    }

    /**
     * Setup RSA text encryption/decryption section
     */
    function setupPKICrypto() {
        const toggleBtn = document.getElementById('toggle-pki-crypto');
        const section = document.getElementById('pki-crypto-section');
        const encryptBtn = document.getElementById('pki-encrypt-btn');
        const decryptBtn = document.getElementById('pki-decrypt-btn');
        const encryptFile = document.getElementById('pki-encrypt-key-file');
        const decryptFile = document.getElementById('pki-decrypt-key-file');
        const copyEncryptBtn = document.getElementById('pki-copy-encrypt-output');
        const copyDecryptBtn = document.getElementById('pki-copy-decrypt-output');

        toggleBtn.addEventListener('click', () => {
            const isHidden = section.classList.contains('hidden');
            section.classList.toggle('hidden');
            toggleBtn.textContent = isHidden ? 'Hide RSA Text Encrypt/Decrypt' : 'Show RSA Text Encrypt/Decrypt';

            if (isHidden) {
                prefillLatestRSAKeys(false);
                section.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });

        encryptFile.addEventListener('change', async () => {
            await loadKeyFileIntoTextarea(encryptFile, 'pki-encrypt-key');
        });

        decryptFile.addEventListener('change', async () => {
            await loadKeyFileIntoTextarea(decryptFile, 'pki-decrypt-key');
        });

        encryptBtn.addEventListener('click', handlePKITextEncryption);
        decryptBtn.addEventListener('click', handlePKITextDecryption);

        copyEncryptBtn.addEventListener('click', async () => {
            await copyTextareaValue('pki-encrypt-output', copyEncryptBtn);
        });

        copyDecryptBtn.addEventListener('click', async () => {
            await copyTextareaValue('pki-decrypt-output', copyDecryptBtn);
        });
    }

    /**
     * Load an uploaded key file into a textarea
     */
    async function loadKeyFileIntoTextarea(fileInput, textareaId) {
        if (fileInput.files.length === 0) return;

        try {
            const text = await readFileAsText(fileInput.files[0]);
            document.getElementById(textareaId).value = text;
        } catch (error) {
            showError(`Failed to read key file: ${error.message}`);
        }
    }

    /**
     * Copy textarea value and show copied state
     */
    async function copyTextareaValue(textareaId, button) {
        const text = document.getElementById(textareaId).value;
        if (!text) {
            showError('Nothing to copy yet');
            return;
        }

        const success = await Zip.copyToClipboard(text);
        if (success) {
            markButtonCopied(button);
        } else {
            showError('Failed to copy to clipboard');
        }
    }

    /**
     * Mark a button as copied temporarily
     */
    function markButtonCopied(button) {
        const originalText = button.textContent;
        button.textContent = 'Copied';
        button.classList.add('copied');
        setTimeout(() => {
            button.textContent = originalText;
            button.classList.remove('copied');
        }, 2000);
    }

    /**
     * Prefill RSA text crypto keys from the latest generated RSA key pair
     */
    function prefillLatestRSAKeys(overwrite) {
        const latestRSAKeyPair = [...generatedPKIKeyPairs].reverse().find(keyPair => keyPair.algorithm === 'RSA');
        if (!latestRSAKeyPair) return;

        const encryptKey = document.getElementById('pki-encrypt-key');
        const decryptKey = document.getElementById('pki-decrypt-key');

        if (overwrite || !encryptKey.value.trim()) {
            encryptKey.value = latestRSAKeyPair.formats.pem.pub;
            document.querySelector('input[name="pki-encrypt-key-type"][value="public"]').checked = true;
        }

        if (overwrite || !decryptKey.value.trim()) {
            decryptKey.value = latestRSAKeyPair.formats.pem.key;
            document.querySelector('input[name="pki-decrypt-key-type"][value="private"]').checked = true;
        }
    }

    /**
     * Get selected radio value
     */
    function getRadioValue(name) {
        const checked = document.querySelector(`input[name="${name}"]:checked`);
        return checked ? checked.value : '';
    }

    /**
     * Encrypt text using a pasted/uploaded RSA key
     */
    function handlePKITextEncryption() {
        const plainText = document.getElementById('pki-encrypt-input').value;
        const pemKey = document.getElementById('pki-encrypt-key').value.trim();
        const keyType = getRadioValue('pki-encrypt-key-type');
        const algorithm = document.getElementById('pki-encrypt-algorithm').value;

        if (!plainText) {
            showError('Enter plain text to encrypt');
            return;
        }

        if (!pemKey) {
            showError('Enter or upload an RSA key for encryption');
            return;
        }

        try {
            const encrypted = Crypto.rsaEncryptText(plainText, pemKey, keyType, algorithm);
            document.getElementById('pki-encrypt-output').value = encrypted;
            document.getElementById('pki-decrypt-input').value = encrypted;
            showSuccess('Text encrypted successfully!');
        } catch (error) {
            showError(`Failed to encrypt text: ${getPKICryptoErrorMessage(error, keyType, algorithm)}`);
        }
    }

    /**
     * Decrypt Base64 text using a pasted/uploaded RSA key
     */
    function handlePKITextDecryption() {
        const encryptedText = document.getElementById('pki-decrypt-input').value.trim();
        const pemKey = document.getElementById('pki-decrypt-key').value.trim();
        const keyType = getRadioValue('pki-decrypt-key-type');
        const algorithm = document.getElementById('pki-decrypt-algorithm').value;

        if (!encryptedText) {
            showError('Enter encrypted Base64 text to decrypt');
            return;
        }

        if (!pemKey) {
            showError('Enter or upload an RSA key for decryption');
            return;
        }

        try {
            const decrypted = Crypto.rsaDecryptText(encryptedText, pemKey, keyType, algorithm);
            document.getElementById('pki-decrypt-output').value = decrypted;
            showSuccess('Text decrypted successfully!');
        } catch (error) {
            showError(`Failed to decrypt text: ${getPKICryptoErrorMessage(error, keyType, algorithm)}`);
        }
    }

    /**
     * Give users a useful RSA crypto error without exposing forge internals only
     */
    function getPKICryptoErrorMessage(error, keyType, algorithm) {
        if (keyType === 'private' && algorithm.includes('OAEP')) {
            return 'OAEP encryption is intended for public-key encryption and private-key decryption. Use a public key to encrypt, or choose PKCS1Padding for legacy private-key operations.';
        }

        if (keyType === 'public' && algorithm.includes('OAEP')) {
            return 'OAEP decryption is intended for private keys. Use the matching private key to decrypt this ciphertext.';
        }

        return error.message || 'Check the key type, key content, algorithm, and input text.';
    }

    /**
     * Generate OpenSSL commands for PKI key pairs
     */
    function generatePKIOpenSSLCommands(name, count, size, algorithm, curve, pkcs12Password) {
        let commands = '';

        if (algorithm === 'RSA') {
            for (let i = 0; i < count; i++) {
                const keyPairName = count > 1 ? `${name}_${i + 1}` : name;
                commands += `# Generate RSA Private Key (${keyPairName})\n`;
                commands += `openssl genrsa -out ${keyPairName}.key ${size}\n\n`;
                commands += `# Extract Public Key\n`;
                commands += `openssl rsa -in ${keyPairName}.key -pubout -out ${keyPairName}_public.pem\n\n`;
                commands += `# Convert to PKCS8\n`;
                commands += `openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ${keyPairName}.key -out ${keyPairName}_private_pkcs8.pem\n\n`;
                commands += `# Create a companion self-signed certificate for PKCS12 export\n`;
                commands += `openssl req -new -x509 -key ${keyPairName}.key -out ${keyPairName}_p12_cert.pem -days 365 -subj "/CN=${keyPairName}"\n\n`;
                commands += `# Create PKCS12 Bundle (password: ${pkcs12Password})\n`;
                commands += `openssl pkcs12 -export -out ${keyPairName}.p12 -inkey ${keyPairName}.key -in ${keyPairName}_p12_cert.pem -passout pass:${pkcs12Password}\n\n`;
                if (i < count - 1) commands += '\n';
            }
        } else {
            // ECDSA
            const curveMap = {
                'secp256r1': 'prime256v1',
                'secp384r1': 'secp384r1',
                'secp521r1': 'secp521r1'
            };
            const opensslCurve = curveMap[curve] || curve;

            for (let i = 0; i < count; i++) {
                const keyPairName = count > 1 ? `${name}_${i + 1}` : name;
                commands += `# Generate ECDSA Private Key (${keyPairName})\n`;
                commands += `openssl ecparam -name ${opensslCurve} -genkey -noout -out ${keyPairName}.key\n\n`;
                commands += `# Extract Public Key\n`;
                commands += `openssl ec -in ${keyPairName}.key -pubout -out ${keyPairName}_public.pem\n\n`;
                commands += `# Convert to PKCS8\n`;
                commands += `openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ${keyPairName}.key -out ${keyPairName}_private_pkcs8.pem\n\n`;
                commands += `# Note: PKCS12 format is not commonly used for ECDSA keys\n`;
                if (i < count - 1) commands += '\n';
            }
        }

        return commands;
    }

    /**
     * Display PKI key pairs in table
     */
    function displayPKIKeyPairs(keyPairs) {
        generatedPKIKeyPairs = keyPairs;
        const tableBody = document.getElementById('pki-table-body');
        tableBody.innerHTML = '';

        keyPairs.forEach((keyPair, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${keyPair.name}</td>
                <td>${keyPair.size}</td>
                <td>${keyPair.algorithm}</td>
                <td>${keyPair.curve}</td>
                <td>
                    <div class="pki-action-stack">
                        <div class="pki-action-row">
                            <span>Public</span>
                            <button class="btn btn-secondary btn-sm" data-action="open-pki-pem-pub" data-index="${index}" title="Open Public PEM">PEM</button>
                            <button class="btn btn-secondary btn-sm" data-action="open-pki-pkcs8-pub" data-index="${index}" title="Open Public PKCS8">PKCS8</button>
                        </div>
                        <div class="pki-action-row">
                            <span>Private</span>
                            <button class="btn btn-secondary btn-sm" data-action="open-pki-pem-key" data-index="${index}" title="Open Private PEM">PEM</button>
                            <button class="btn btn-secondary btn-sm" data-action="open-pki-pkcs8-key" data-index="${index}" title="Open Private PKCS8">PKCS8</button>
                        </div>
                        <div class="pki-action-row">
                            <span>PKCS12</span>
                            ${keyPair.formats.pkcs12
                                ? `<button class="btn btn-secondary btn-sm" data-action="open-pki-pkcs12" data-index="${index}" title="Open PKCS12 Bundle">P12</button>`
                                : '<button class="btn btn-secondary btn-sm" disabled>N/A</button>'}
                            <button class="btn btn-primary btn-sm" data-action="generate-pki-csr" data-index="${index}" title="Generate CSR">CSR</button>
                        </div>
                    </div>
                </td>
            `;
            tableBody.appendChild(row);
        });

        // Setup all PKI action buttons
        tableBody.querySelectorAll('[data-action^="open-pki-"], [data-action="generate-pki-csr"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = e.target.dataset.action;
                const index = parseInt(e.target.dataset.index);
                handlePKIAction(action, index, e.target);
            });
        });

    }

    /**
     * Handle PKI key pair action (download, view, generate CSR)
     */
    async function handlePKIAction(action, index, button) {
        const keyPair = generatedPKIKeyPairs[index];
        if (!keyPair) return;

        switch (action) {
            // PEM format artifacts
            case 'open-pki-pem-pub':
                showPKIArtifactModal('Public Key (PEM)', keyPair.formats.pem.pub, `${keyPair.name}_public.pem`);
                break;
            case 'open-pki-pem-key':
                showPKIArtifactModal('Private Key (PEM)', keyPair.formats.pem.key, `${keyPair.name}_private.pem`);
                break;
            // PKCS8 format artifacts
            case 'open-pki-pkcs8-pub':
                showPKIArtifactModal('Public Key (PKCS8)', keyPair.formats.pkcs8.pub, `${keyPair.name}_public_pkcs8.pem`);
                break;
            case 'open-pki-pkcs8-key':
                showPKIArtifactModal('Private Key (PKCS8)', keyPair.formats.pkcs8.key, `${keyPair.name}_private_pkcs8.pem`);
                break;
            // PKCS12 format artifact
            case 'open-pki-pkcs12':
                if (keyPair.formats.pkcs12) {
                    showPKIArtifactModal(
                        'PKCS12 Bundle (Base64 Preview)',
                        uint8ArrayToBase64(keyPair.formats.pkcs12),
                        `${keyPair.name}.p12`,
                        keyPair.formats.pkcs12,
                        'binary'
                    );
                } else {
                    showError('PKCS12 format not available for ECDSA keys');
                }
                break;
            // Generate CSR
            case 'generate-pki-csr':
                showCSRModal(index);
                break;
        }
    }

    /**
     * Show a PKI artifact in the key modal with copy and download actions
     */
    function showPKIArtifactModal(title, previewContent, filename, downloadContent = previewContent, type = 'text') {
        showKeyModal(title, previewContent, {
            filename,
            content: downloadContent,
            type
        });
    }

    /**
     * Handle CSR generation
     */
    async function handleCSRGeneration() {
        try {
            if (currentPKIIndex === null) {
                showError('No key pair selected');
                return;
            }

            const keyPair = generatedPKIKeyPairs[currentPKIIndex];
            if (!keyPair) {
                showError('Key pair not found');
                return;
            }

            // Check if key pair is ECDSA (not supported for CSR generation yet)
            if (keyPair.algorithm === 'ECDSA') {
                showError('CSR generation for ECDSA keys is not yet supported. Please use RSA keys.');
                return;
            }

            // Get form values
            const cn = document.getElementById('csr-cn').value.trim();
            const org = document.getElementById('csr-org').value.trim();
            const orgUnit = document.getElementById('csr-org-unit').value.trim();
            const country = document.getElementById('csr-country').value.trim().toUpperCase();
            const state = document.getElementById('csr-state').value.trim();
            const email = document.getElementById('csr-email').value.trim();

            // Validate mandatory fields
            if (!cn) {
                showError('Common Name (CN) is required');
                return;
            }

            // Validate country if provided
            if (country && country.length !== 2) {
                showError('Country must be a 2-letter ISO code');
                return;
            }

            // Validate email if provided
            if (email && !validateEmail(email)) {
                showError('Invalid email address');
                return;
            }

            // Get SAN entries
            const sanEntries = [];
            document.querySelectorAll('#csr-san-container .san-entry').forEach(entry => {
                const type = entry.querySelector('.san-type').value;
                const value = entry.querySelector('.san-value').value.trim();
                if (value) {
                    sanEntries.push({ type, value });
                }
            });

            // Validate SAN entries
            for (const entry of sanEntries) {
                if (entry.type === 'DNS' && !validateDomain(entry.value)) {
                    showError(`Invalid domain: ${entry.value}`);
                    return;
                }
                if (entry.type === 'IP' && !validateIP(entry.value)) {
                    showError(`Invalid IP address: ${entry.value}`);
                    return;
                }
            }

            // Generate CSR
            const csrPEM = await generateCSRFromKeyPair(keyPair, cn, org, country, state, '', orgUnit, email, sanEntries);

            // Hide CSR form modal and show result
            hideCSRModal();
            showCSRResultModal(csrPEM);

        } catch (error) {
            showError(`Failed to generate CSR: ${error.message}`);
        }
    }

    /**
     * Generate CSR from key pair
     */
    async function generateCSRFromKeyPair(keyPair, cn, org, country, state, locality, orgUnit, email, sanEntries) {
        // For RSA keys, we need to parse the PEM back to forge format
        const privateKey = forge.pki.privateKeyFromPem(keyPair.pemKey);
        const publicKey = forge.pki.publicKeyFromPem(keyPair.pemPub);

        const csr = forge.pki.createCertificationRequest();
        csr.publicKey = publicKey;

        // Build subject attributes
        const attrs = [];
        if (country) attrs.push({ shortName: 'C', value: country });
        if (state) attrs.push({ shortName: 'ST', value: state });
        if (locality) attrs.push({ shortName: 'L', value: locality });
        if (org) attrs.push({ shortName: 'O', value: org });
        if (orgUnit) attrs.push({ shortName: 'OU', value: orgUnit });
        if (cn) attrs.push({ shortName: 'CN', value: cn });
        if (email) attrs.push({ name: 'emailAddress', value: email });

        csr.setSubject(attrs);

        // Add SAN as extension attribute if provided
        if (sanEntries && sanEntries.length > 0) {
            const altNames = [];
            sanEntries.forEach(entry => {
                if (entry.type === 'DNS') {
                    altNames.push({ type: 2, value: entry.value }); // dNSName
                } else if (entry.type === 'IP') {
                    altNames.push({ type: 7, ip: entry.value }); // iPAddress
                }
            });

            csr.setAttributes([
                {
                    name: 'extensionRequest',
                    extensions: [
                        {
                            name: 'subjectAltName',
                            altNames: altNames
                        }
                    ]
                }
            ]);
        }

        // Sign the CSR
        csr.sign(privateKey, forge.md.sha256.create());

        return forge.pki.certificationRequestToPem(csr);
    }
    async function handlePKIZipDownload() {
        if (generatedPKIKeyPairs.length === 0) {
            showError('No key pairs generated yet');
            return;
        }

        try {
            const zip = new JSZip();
            const readmeLines = [
                'PKI Key Pairs Bundle',
                '',
                'Generated by SSL Certificate Generator.',
                '',
                'Files included per key pair:',
                '- *_public.pem: Public key in PEM format',
                '- *_private.pem: Private key in PEM format',
                '- *_public_pkcs8.pem: Public key export used by this tool for PKCS8 table actions',
                '- *_private_pkcs8.pem: Private key in PKCS8 PEM format',
                '- *.p12: PKCS12 bundle when available',
                '',
                'Security notes:',
                '- Keep private keys and PKCS12 passwords secret.',
                '- PKCS12 files are password-protected with the passwords listed in password.txt.',
                '- ECDSA PKCS12 export is not generated by this browser implementation.'
            ];

            const passwordLines = [
                'PKCS12 Passwords',
                ''
            ];

            generatedPKIKeyPairs.forEach(keyPair => {
                // PEM format
                zip.file(`${keyPair.name}_public.pem`, keyPair.formats.pem.pub);
                zip.file(`${keyPair.name}_private.pem`, keyPair.formats.pem.key);

                // PKCS8 format
                zip.file(`${keyPair.name}_public_pkcs8.pem`, keyPair.formats.pkcs8.pub);
                zip.file(`${keyPair.name}_private_pkcs8.pem`, keyPair.formats.pkcs8.key);

                // PKCS12 format (if available)
                if (keyPair.formats.pkcs12) {
                    zip.file(`${keyPair.name}.p12`, keyPair.formats.pkcs12);
                    passwordLines.push(`${keyPair.name}.p12: ${keyPair.pkcs12Password || 'password123'}`);
                } else {
                    passwordLines.push(`${keyPair.name}.p12: N/A`);
                }
            });

            zip.file('README.txt', readmeLines.join('\n'));
            zip.file('password.txt', passwordLines.join('\n'));

            const content = await zip.generateAsync({ type: 'blob' });
            const url = URL.createObjectURL(content);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'pki_key_pairs.zip';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);

            showSuccess('ZIP bundle downloaded successfully!');
        } catch (error) {
            showError(`Failed to create ZIP: ${error.message}`);
        }
    }

    /**
     * Update DevOps section
     */
    function updateDevOpsSection() {
        const pemWarning = document.getElementById('pem-warning');
        const pemContent = document.getElementById('pem-content');
        const k8sWarning = document.getElementById('k8s-warning');
        const k8sContent = document.getElementById('k8s-content');

        if (generatedCA && generatedCert) {
            // Show PEM content
            pemWarning.classList.add('hidden');
            pemContent.classList.remove('hidden');

            // Enable PEM copy buttons
            document.querySelectorAll('#pem-content .btn-secondary').forEach(btn => {
                btn.disabled = false;
            });

            // Show Kubernetes content
            k8sWarning.classList.add('hidden');
            k8sContent.classList.remove('hidden');

            const domain = document.getElementById('cert-domain').value.trim();

            // Generate Kubernetes TLS Secret
            const tlsSecret = `apiVersion: v1
kind: Secret
metadata:
  name: ${domain}-tls
  namespace: default
type: kubernetes.io/tls
data:
  tls.crt: ${Zip.stringToBase64(generatedCert.pemCert)}
  tls.key: ${Zip.stringToBase64(generatedCert.pemKey)}`;
            document.getElementById('k8s-tls-secret').textContent = tlsSecret;

            // Generate Kubernetes CA Secret
            const caSecret = `apiVersion: v1
kind: Secret
metadata:
  name: ca-secret
  namespace: default
type: Opaque
data:
  ca.crt: ${Zip.stringToBase64(generatedCA.pemCert)}`;
            document.getElementById('k8s-ca-secret').textContent = caSecret;

        } else {
            // Hide PEM content and show warning
            pemWarning.classList.remove('hidden');
            pemContent.classList.add('hidden');

            // Disable PEM copy buttons
            document.querySelectorAll('#pem-content .btn-secondary').forEach(btn => {
                btn.disabled = true;
            });

            // Hide Kubernetes content and show warning
            k8sWarning.classList.remove('hidden');
            k8sContent.classList.add('hidden');
        }
    }

    /**
     * Setup custom Kubernetes Secret generation
     */
    function setupCustomK8sSecret() {
        const certInput = document.getElementById('k8s-custom-cert');
        const keyInput = document.getElementById('k8s-custom-key');
        const generateBtn = document.getElementById('k8s-generate-custom');
        const copyBtn = document.getElementById('k8s-copy-custom');
        const warning = document.getElementById('k8s-custom-warning');
        const output = document.getElementById('k8s-custom-output');

        // File inputs are always visible, only show/hide the warning and output section
        const checkFiles = () => {
            if (certInput.files.length > 0 && keyInput.files.length > 0) {
                warning.classList.add('hidden');
            } else {
                warning.classList.remove('hidden');
                output.classList.add('hidden');
            }
        };

        certInput.addEventListener('change', checkFiles);
        keyInput.addEventListener('change', checkFiles);

        // Generate YAML from uploaded files
        generateBtn.addEventListener('click', async () => {
            if (certInput.files.length === 0 || keyInput.files.length === 0) {
                showError('Please upload both certificate and key files');
                return;
            }

            try {
                const certFile = certInput.files[0];
                const keyFile = keyInput.files[0];
                const secretName = document.getElementById('k8s-custom-name').value.trim() || 'my-tls-secret';
                const namespace = document.getElementById('k8s-custom-namespace').value.trim() || 'default';

                const certText = await readFileAsText(certFile);
                const keyText = await readFileAsText(keyFile);

                const secret = `apiVersion: v1
kind: Secret
metadata:
  name: ${secretName}
  namespace: ${namespace}
type: kubernetes.io/tls
data:
  tls.crt: ${Zip.stringToBase64(certText)}
  tls.key: ${Zip.stringToBase64(keyText)}`;

                document.getElementById('k8s-custom-secret').textContent = secret;
                output.classList.remove('hidden');
                showSuccess('Kubernetes Secret YAML generated successfully!');

            } catch (error) {
                showError(`Failed to generate YAML: ${error.message}`);
            }
        });

        // Copy custom YAML
        copyBtn.addEventListener('click', async () => {
            const text = document.getElementById('k8s-custom-secret').textContent;
            const success = await Zip.copyToClipboard(text);
            if (success) {
                const originalText = copyBtn.textContent;
                copyBtn.textContent = 'Copied';
                copyBtn.classList.add('copied');
                setTimeout(() => {
                    copyBtn.textContent = originalText;
                    copyBtn.classList.remove('copied');
                }, 2000);
            } else {
                showError('Failed to copy to clipboard');
            }
        });
    }

    /**
     * Read file as text
     */
    function readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    }

    /**
     * Setup validity input validation
     */
    function setupValidityInputs() {
        const caValidity = document.getElementById('ca-validity');
        const certValidity = document.getElementById('cert-validity');

        const checkCAValidity = () => {
            const value = parseInt(caValidity.value);
            const warning = caValidity.parentElement.querySelector('.validity-warning');
            if (warning) {
                if (value < 3) {
                    warning.textContent = 'It is recommended to set the validity period to at least 3 years for a CA certificate.';
                    warning.classList.remove('hidden');
                } else {
                    warning.classList.add('hidden');
                }
            }
        };

        const checkCertValidity = () => {
            const value = parseInt(certValidity.value);
            const warning = certValidity.parentElement.querySelector('.validity-warning');
            if (warning) {
                if (value < 1) {
                    warning.textContent = 'It is recommended to set the validity period to at least 1 year for a certificate.';
                    warning.classList.remove('hidden');
                } else {
                    warning.classList.add('hidden');
                }
            }
        };

        // Use 'change' event for select dropdowns
        caValidity.addEventListener('change', checkCAValidity);
        certValidity.addEventListener('change', checkCertValidity);
    }

    /**
     * Get generated CA
     */
    function getGeneratedCA() {
        return generatedCA;
    }

    /**
     * Get generated certificate
     */
    function getGeneratedCert() {
        return generatedCert;
    }

    /**
     * Setup theme toggle
     */
    function setupThemeToggle() {
        const themeToggle = document.getElementById('theme-toggle');
        const themeIcon = themeToggle.querySelector('.theme-icon');

        // Check for saved theme preference or default to light
        // const savedTheme = localStorage.getItem('theme') || 'light';
        const savedTheme = localStorage.getItem('theme') || 'dark';
        if (savedTheme === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
            themeIcon.textContent = '☀️';
        }

        themeToggle.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            themeIcon.textContent = newTheme === 'dark' ? '☀️' : '🌙';
        });
    }

    /**
     * Setup go to top button
     */
    function setupGoToTop() {
        const goToTopBtn = document.getElementById('go-to-top');

        // Show/hide button based on scroll position
        window.addEventListener('scroll', () => {
            if (window.scrollY > 300) {
                goToTopBtn.classList.add('visible');
            } else {
                goToTopBtn.classList.remove('visible');
            }
        });

        // Scroll to top when clicked
        goToTopBtn.addEventListener('click', () => {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }

    return {
        init,
        getGeneratedCA,
        getGeneratedCert
    };
})();
