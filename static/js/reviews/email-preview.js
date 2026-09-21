(function () {
    function setVisible(element, visible) {
        if (element) element.classList.toggle('d-none', !visible);
    }

    function errorMessage(response, body) {
        if (response.ok && (response.headers.get('Content-Type') || '').toLowerCase().includes('text/html')) {
            return '';
        }
        try {
            const parsed = JSON.parse(body);
            if (parsed && parsed.error) return parsed.error;
        } catch (error) {
            // Fall through to the translated generic message.
        }
        return t('Unable to render email preview.');
    }

    function resizeFrame(frame) {
        try {
            const documentElement = frame.contentDocument && frame.contentDocument.documentElement;
            const body = frame.contentDocument && frame.contentDocument.body;
            const contentHeight = Math.max(
                documentElement ? documentElement.scrollHeight : 0,
                body ? body.scrollHeight : 0,
                480
            );
            frame.style.height = contentHeight + 'px';
            if (frame.parentElement) {
                // Expanding the iframe must start the outer preview viewport
                // at the greeting. Browser scroll anchoring can otherwise
                // preserve the clicked table row and open in a blank-looking
                // middle section of the email.
                frame.parentElement.scrollTop = 0;
            }
        } catch (error) {
            // A browser may keep a sandboxed document isolated. The fixed
            // minimum height still leaves the preview usable in that case.
            frame.style.height = '30rem';
            if (frame.parentElement) frame.parentElement.scrollTop = 0;
        }
    }

    window.loadReviewEmailPreview = function (options) {
        const frame = options.frame;
        const loading = options.loading;
        const error = options.error;
        const url = options.url;
        const token = String(Number(frame.dataset.previewToken || '0') + 1);
        frame.dataset.previewToken = token;
        frame.srcdoc = '';
        setVisible(frame, false);
        setVisible(error, false);
        setVisible(loading, true);
        frame.onload = null;
        frame.style.height = '30rem';

        if (!url) {
            loading.classList.add('d-none');
            error.textContent = t('Unable to render email preview.');
            setVisible(error, true);
            return;
        }

        fetch(url, {credentials: 'same-origin', headers: {Accept: 'text/html'}})
            .then(function (response) {
                return response.text().then(function (body) {
                    const message = errorMessage(response, body);
                    if (message) throw new Error(message);
                    return body;
                });
            })
            .then(function (body) {
                if (frame.dataset.previewToken !== token) return;
                frame.onload = function () {
                    if (frame.dataset.previewToken !== token) return;
                    resizeFrame(frame);
                };
                frame.srcdoc = body;
                setVisible(loading, false);
                setVisible(frame, true);
                resizeFrame(frame);
            })
            .catch(function (reason) {
                if (frame.dataset.previewToken !== token) return;
                setVisible(loading, false);
                error.textContent = reason.message || t('Unable to render email preview.');
                setVisible(error, true);
            });
    };

    window.clearReviewEmailPreview = function (frame, loading, error) {
        if (!frame) return;
        frame.dataset.previewToken = String(Number(frame.dataset.previewToken || '0') + 1);
        frame.onload = null;
        frame.srcdoc = '';
        frame.style.height = '30rem';
        setVisible(frame, false);
        setVisible(error, false);
        setVisible(loading, true);
    };
})();
