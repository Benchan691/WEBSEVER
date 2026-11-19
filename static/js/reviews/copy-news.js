(function () {
    let activeCopy;

    async function fetchNews(url, signal) {
        const response = await fetch(url, {
            mode: 'same-origin',
            redirect: 'error',
            headers: {Accept: 'text/html'},
            signal,
        });
        if (!response.ok || !(response.headers.get('Content-Type') || '').includes('text/html')) {
            throw new Error('Newsletter preview could not be loaded');
        }

        const template = document.createElement('template');
        template.innerHTML = await response.text();
        const content = template.content;
        // The preview is a whole HTML page. Copy its content without the document metadata.
        content.querySelectorAll('base, link, meta, script, style, title').forEach(function (element) {
            element.remove();
        });
        const links = content.querySelectorAll('a[href]');
        for (const link of links) {
            const href = link.getAttribute('href').trim();
            if (/^https?:\/\//i.test(href)) link.setAttribute('href', href);
            else link.removeAttribute('href');
        }
        const html = template.innerHTML.trim();

        for (const link of links) {
            const href = link.getAttribute('href');
            if (href && link.textContent.trim() !== href) link.append(' (' + href + ')');
        }
        const walker = document.createTreeWalker(content, NodeFilter.SHOW_TEXT);
        while (walker.nextNode()) {
            const node = walker.currentNode;
            if (!node.parentElement?.closest('pre, .source-text')) node.data = node.data.replace(/\s+/g, ' ');
        }
        content.querySelectorAll('h1, h2, h3, h4, h5, h6, p, div, section, header, footer, ul, ol, dl, pre, table')
            .forEach(function (element) { element.after('\n\n'); });
        content.querySelectorAll('br, tr, dd').forEach(function (element) { element.after('\n'); });
        content.querySelectorAll('dt').forEach(function (element) { element.after('\t'); });
        content.querySelectorAll('th, td').forEach(function (cell) {
            if (cell.nextElementSibling) cell.after('\t');
        });
        content.querySelectorAll('li').forEach(function (item) {
            item.prepend('• ');
            item.after('\n');
        });
        const text = content.textContent.replace(/[ \t]*\n[ \t]*/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
        if (!text) throw new Error('Newsletter preview was empty');
        return {html, text};
    }

    async function writeClipboard(news) {
        if (!navigator.clipboard?.write || typeof ClipboardItem !== 'function') return false;
        const html = news.then(function (data) { return new Blob([data.html], {type: 'text/html'}); });
        const text = news.then(function (data) { return new Blob([data.text], {type: 'text/plain'}); });
        // A browser can refuse clipboard access before reading the data promises.
        html.catch(function () {});
        text.catch(function () {});
        try {
            // Start the write in the click handler while the preview loads.
            await navigator.clipboard.write([new ClipboardItem({'text/html': html, 'text/plain': text})]);
            return true;
        } catch {
            return false;
        }
    }

    function copyWithEvent(news) {
        let copied = false;
        function onCopy(event) {
            if (!event.clipboardData) return;
            event.clipboardData.setData('text/html', news.html);
            event.clipboardData.setData('text/plain', news.text);
            event.preventDefault();
            copied = true;
        }
        document.addEventListener('copy', onCopy);
        try {
            // The portal also runs over HTTP, where the Clipboard API is unavailable.
            return document.execCommand('copy') && copied;
        } catch {
            return false;
        } finally {
            document.removeEventListener('copy', onCopy);
        }
    }

    window.appendReviewActions = function (cell, viewButton, previewUrl) {
        viewButton.classList.add('me-1', 'my-1', 'text-nowrap');
        cell.append(viewButton);
        if (!previewUrl) return;

        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-outline-secondary btn-sm my-1 text-nowrap';
        const icon = document.createElement('i');
        icon.className = 'bi bi-clipboard me-1';
        icon.setAttribute('aria-hidden', 'true');
        button.append(icon, t('Copy news'));
        const status = document.createElement('div');
        status.className = 'small';
        status.setAttribute('role', 'status');
        cell.append(button, status);

        let ready = null;
        let clearStatus;
        button.addEventListener('click', async function () {
            if (button.getAttribute('aria-disabled') === 'true') return;
            activeCopy?.abort();
            const request = new AbortController();
            activeCopy = request;
            button.setAttribute('aria-disabled', 'true');
            clearTimeout(clearStatus);
            status.className = 'small text-muted';
            status.textContent = t('Copying news...');
            try {
                const news = ready ? Promise.resolve(ready) : fetchNews(previewUrl, request.signal);
                const write = (ready && copyWithEvent(ready)) || writeClipboard(news);
                const [data, written] = await Promise.all([news, write]);
                if (request.signal.aborted) return;
                if (!written && !copyWithEvent(data)) {
                    // Retry with the content ready when a browser requires a synchronous copy.
                    ready = data;
                    status.className = 'small text-danger';
                    status.textContent = t('Clipboard unavailable. Try again or copy from View.');
                    return;
                }
                ready = null;
                status.className = 'small text-success';
                status.textContent = t('News copied to clipboard.');
                clearStatus = setTimeout(function () { status.textContent = ''; }, 3000);
            } catch {
                if (!request.signal.aborted) {
                    status.className = 'small text-danger';
                    status.textContent = t('Unable to load news to copy.');
                }
            } finally {
                if (request.signal.aborted) status.textContent = '';
                if (activeCopy === request) activeCopy = null;
                button.removeAttribute('aria-disabled');
            }
        });
    };
})();
