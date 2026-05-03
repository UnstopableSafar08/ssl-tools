/**
 * App Module - Application bootstrap and initialization
 */

(function() {
    'use strict';

    /**
     * Initialize application when DOM is ready
     */
    document.addEventListener('DOMContentLoaded', () => {
        // Initialize UI
        UI.init();
    });

    /**
     * Handle page unload - clear sensitive data from memory
     */
    window.addEventListener('beforeunload', () => {
        // Clear all keys and certificates from memory
        Crypto.clearAllKeys();
        Cert.clearCertificates();
    });

})();
