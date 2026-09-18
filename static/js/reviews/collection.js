(function () {
    const {initialError, collectionName, apiUrl} = JSON.parse(
        document.getElementById('page-config').textContent
    );
    const selectionStorageKey = 'vulnerabilityReviewSelections';
    const form = document.getElementById('filter-form');
    const rows = document.getElementById('document-rows');
    const loading = document.getElementById('loading');
    const empty = document.getElementById('empty-state');
    const error = document.getElementById('error-alert');
    const resultCount = document.getElementById('result-count');
    const pageLabel = document.getElementById('page-label');
    const pageSize = document.getElementById('page-size');
    const previous = document.getElementById('previous-btn');
    const next = document.getElementById('next-btn');
    const modal = new bootstrap.Modal(document.getElementById('detail-modal'));
    const detailJson = document.getElementById('detail-json');
    const detailTitle = document.getElementById('detail-modal-title');
    const selectedCount = document.getElementById('selected-count');
    const clearSelection = document.getElementById('clear-selection-btn');
    let page = 1;
    let pages = 1;
    let currentDocuments = [];

    function getSelections() {
        try {
            const selections = JSON.parse(localStorage.getItem(selectionStorageKey) || '[]');
            return Array.isArray(selections) ? selections : [];
        } catch (error) {
            return [];
        }
    }

    function saveSelections(selections) {
        localStorage.setItem(selectionStorageKey, JSON.stringify(selections));
        updateSelectedCount();
    }

    function selectionKey(collection, selectionId) {
        return collection + '\u0000' + selectionId;
    }

    function updateSelectedCount() {
        const count = getSelections().length;
        selectedCount.textContent = t('{count} selected', {count: count});
        clearSelection.disabled = count === 0;
    }

    function displayValue(value) {
        if (value === null || value === undefined || value === '') return '—';
        if (Array.isArray(value)) {
            return value.map(function (item) {
                return typeof item === 'object' ? JSON.stringify(item) : String(item);
            }).join(', ') || '—';
        }
        return typeof value === 'object' ? JSON.stringify(value) : String(value);
    }

    function addCell(row, value, className) {
        const cell = document.createElement('td');
        cell.className = className || '';
        cell.textContent = displayValue(value);
        row.append(cell);
    }

    function severityValue(document) {
        return document.severity || document.status || document.impacts;
    }

    function buildQueryParams() {
        const parameters = new URLSearchParams();
        new FormData(form).forEach(function (value, key) {
            if (key === 'include_unknown') return;
            value = value.trim();
            if (value) parameters.set(key, value);
        });
        if (document.getElementById('include-unknown').checked) {
            parameters.set('include_unknown', 'true');
        }
        parameters.set('page', page);
        parameters.set('page_size', pageSize.value);
        return parameters;
    }

    function renderDocuments(documents) {
        rows.replaceChildren();
        const selectedKeys = new Set(getSelections().map(function (selection) {
            return selectionKey(selection.collection, selection.selection_id);
        }));
        documents.forEach(function (item, index) {
            const document = item.document;
            const tr = window.document.createElement('tr');
            const selectCell = window.document.createElement('td');
            const checkbox = window.document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'form-check-input document-selection';
            checkbox.dataset.selectionId = item.selection_id;
            checkbox.checked = selectedKeys.has(selectionKey(collectionName, item.selection_id));
            checkbox.setAttribute('aria-label', t('Select {label}', {label: document.code || document.cve || document.title || t('document')}));
            selectCell.append(checkbox);
            tr.append(selectCell);
            addCell(tr, document.code || document.cve, 'fw-medium');
            addCell(tr, document.title);
            addCell(tr, severityValue(document));
            addCell(tr, document.affected || document.affected_products, 'small');

            const action = window.document.createElement('td');
            const button = window.document.createElement('button');
            button.className = 'btn btn-outline-primary btn-sm';
            button.type = 'button';
            button.dataset.index = index;
            button.innerHTML = '<i class="bi bi-eye me-1"></i>' + t('View');
            action.append(button);
            tr.append(action);
            rows.append(tr);
        });
    }

    function loadDocuments() {
        if (initialError) {
            loading.classList.add('d-none');
            previous.disabled = true;
            next.disabled = true;
            return;
        }

        const parameters = buildQueryParams();
        loading.classList.remove('d-none');
        empty.classList.add('d-none');
        error.classList.add('d-none');
        rows.replaceChildren();

        fetch(apiUrl + '?' + parameters.toString())
            .then(function (response) {
                return response.json().then(function (body) {
                    if (!response.ok) throw new Error(body.error || t('Unable to load documents.'));
                    return body;
                });
            })
            .then(function (body) {
                currentDocuments = body.data;
                pages = body.pages;
                renderDocuments(body.data);
                empty.classList.toggle('d-none', body.data.length !== 0);
                resultCount.textContent = body.total === 1
                    ? t('{total} matching document', {total: body.total})
                    : t('{total} matching documents', {total: body.total});
                pageLabel.textContent = t('Page {current} of {total}', {current: body.page, total: body.pages});
                previous.disabled = body.page <= 1;
                next.disabled = body.page >= body.pages;
            })
            .catch(function (reason) {
                error.textContent = reason.message;
                error.classList.remove('d-none');
                previous.disabled = true;
                next.disabled = true;
            })
            .finally(function () {
                loading.classList.add('d-none');
            });
    }

    rows.addEventListener('click', function (event) {
        const button = event.target.closest('button[data-index]');
        if (!button) return;
        const document = currentDocuments[Number(button.dataset.index)].document;
        detailTitle.textContent = document.code || document.cve || document.title || t('Document Detail');
        detailJson.textContent = JSON.stringify(document, null, 2);
        modal.show();
    });

    rows.addEventListener('change', function (event) {
        const checkbox = event.target.closest('.document-selection');
        if (!checkbox) return;
        const selections = getSelections();
        const key = selectionKey(collectionName, checkbox.dataset.selectionId);
        const index = selections.findIndex(function (selection) {
            return selectionKey(selection.collection, selection.selection_id) === key;
        });

        if (checkbox.checked && index === -1) {
            selections.push({
                collection: collectionName,
                selection_id: checkbox.dataset.selectionId,
            });
        } else if (!checkbox.checked && index !== -1) {
            selections.splice(index, 1);
        }
        saveSelections(selections);
    });

    form.addEventListener('submit', function (event) {
        event.preventDefault();
        page = 1;
        loadDocuments();
    });
    document.getElementById('clear-btn').addEventListener('click', function () {
        form.reset();
        page = 1;
        loadDocuments();
    });
    document.getElementById('refresh-btn').addEventListener('click', loadDocuments);
    clearSelection.addEventListener('click', function () {
        localStorage.removeItem(selectionStorageKey);
        updateSelectedCount();
        renderDocuments(currentDocuments);
    });
    pageSize.addEventListener('change', function () { page = 1; loadDocuments(); });
    previous.addEventListener('click', function () { if (page > 1) { page--; loadDocuments(); } });
    next.addEventListener('click', function () { if (page < pages) { page++; loadDocuments(); } });

    updateSelectedCount();
    loadDocuments();
})();
