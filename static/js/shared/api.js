(function (global) {
    'use strict';
    global.portalRequest = async function (path, options = {}) {
        const response = await fetch(path, {
            ...options,
            credentials: 'same-origin',
            cache: 'no-store',
            headers: {Accept: 'application/json', ...options.headers}
        });
        const failure = (message, code) => {
            const error = new Error(message);
            error.status = response.status;
            error.code = code;
            return error;
        };
        if (response.redirected || response.status === 401) {
            throw failure('Your session has expired. Sign in again before retrying.', 'authentication_required');
        }
        if (!(response.headers.get('content-type') || '').toLowerCase().includes('application/json')) {
            throw failure('The server returned a page instead of an API response. Sign in again; if this continues, ask the administrator to check the portal URL and proxy configuration.', 'unexpected_response');
        }
        let data;
        try {
            data = await response.json();
        } catch (_) {
            throw failure('The server returned an unreadable response. Please retry.', 'invalid_response');
        }
        if (!response.ok) {
            throw failure(data.error || 'Request failed. Please retry.', data.code || 'request_failed');
        }
        return data;
    };
}(window));
