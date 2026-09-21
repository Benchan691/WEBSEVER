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
                frame.srcdoc = body;
                setVisible(loading, false);
                setVisible(frame, true);
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
        frame.srcdoc = '';
        setVisible(frame, false);
        setVisible(error, false);
        setVisible(loading, true);
    };
})();
