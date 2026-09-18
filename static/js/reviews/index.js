(function () {
    const {exportUrl, searchUrl, autoSelectUrl} = JSON.parse(
        document.getElementById('page-config').textContent
    );
    const error = document.getElementById('error-alert');
    const statusAlert = document.getElementById('status-alert');
    const refresh = document.getElementById('refresh-btn');
    const filterForm = document.getElementById('global-filter-form');
    const clearFilter = document.getElementById('clear-filter-btn');
    const resultsLoading = document.getElementById('results-loading');
    const resultsEmpty = document.getElementById('results-empty');
    const resultsTableWrap = document.getElementById('results-table-wrap');
    const resultsHead = document.getElementById('results-head');
    const resultsBody = document.getElementById('results-body');
    const resultsTitle = document.getElementById('results-title');
    const resultsCount = document.getElementById('results-count');
    const timeWindow = document.getElementById('filter-time-window');
    const customWindow = document.getElementById('filter-custom-window');
    const pagination = document.getElementById('pagination');
    const previousPage = document.getElementById('previous-page');
    const nextPage = document.getElementById('next-page');
    const pageLabel = document.getElementById('page-label');
    const pageSize = document.getElementById('page-size');
    const exportButton = document.getElementById('export-btn');
    const clearSelection = document.getElementById('clear-selection-btn');
    const autoSelectCount = document.getElementById('auto-select-count');
    const autoSelectButton = document.getElementById('auto-select-btn');
    const selectedCount = document.getElementById('selected-count');
    const generateReportButton = document.getElementById('generate-report-btn');
    const documentModal = bootstrap.Modal.getOrCreateInstance(document.getElementById('document-modal'));
    const documentModalTitle = document.getElementById('document-modal-title');
    const documentJson = document.getElementById('document-json');
    const relatedModal = bootstrap.Modal.getOrCreateInstance(document.getElementById('related-modal'));
    const relatedModalTitle = document.getElementById('related-modal-title');
    const relatedCount = document.getElementById('related-count');
    const relatedEmpty = document.getElementById('related-empty');
    const relatedTableWrap = document.getElementById('related-table-wrap');
    const relatedBody = document.getElementById('related-body');
    const relatedSelectAll = document.getElementById('related-select-all');
    const relatedClear = document.getElementById('related-clear');
    const relatedModalElement = document.getElementById('related-modal');
    const documentModalElement = document.getElementById('document-modal');
    const selectionStorageKey = 'vulnerabilityReviewSelections';
    let activeFilters = null;
    let currentPage = 1;
    let totalPages = 1;
    let currentBody = null;
    let currentRelated = [];
    let restoreRelatedModalAfterDocument = false;

    function getSelections() {
        try {
            const selections = JSON.parse(localStorage.getItem(selectionStorageKey) || '[]');
            return Array.isArray(selections) ? selections : [];
        } catch (error) {
            return [];
        }
    }

    function setSelections(selections) {
        localStorage.setItem(selectionStorageKey, JSON.stringify(selections));
    }

    function selectionKey(collection, selectionId) {
        return collection + '\u0000' + selectionId;
    }

    function selectedKeys() {
        return new Set(getSelections().map(function (selection) {
            return selectionKey(selection.collection, selection.selection_id);
        }));
    }

    function updateSelectedCount() {
        const count = getSelections().length;
        selectedCount.textContent = t('{count} selected', {count: count});
        clearSelection.disabled = count === 0;
        exportButton.disabled = count === 0;
        generateReportButton.classList.toggle('disabled', count === 0);
        generateReportButton.setAttribute('aria-disabled', count === 0 ? 'true' : 'false');
    }

    function syncVisibleSelections() {
        const keys = selectedKeys();
        document.querySelectorAll('[data-selection-collection][data-selection-id]').forEach(function (input) {
            input.checked = keys.has(selectionKey(input.dataset.selectionCollection, input.dataset.selectionId));
        });
    }

    function showError(message) {
        statusAlert.classList.add('d-none');
        error.textContent = message;
        error.classList.remove('d-none');
    }

    function showStatus(message) {
        error.classList.add('d-none');
        statusAlert.textContent = message;
        statusAlert.classList.remove('d-none');
    }

    function summaryValue(value) {
        if (value === null || value === undefined || value === '') return '';
        if (Array.isArray(value)) return value.map(summaryValue).filter(Boolean).join(', ');
        if (typeof value === 'object') return Object.values(value).map(summaryValue).filter(Boolean).join(', ');
        return String(value);
    }

    function firstValue(document, fields) {
        for (const field of fields) {
            const value = summaryValue(document[field]);
            if (value) return value;
        }
        return '';
    }

    function buildFilterPayload() {
        const payload = { mode: 'cve' };
        const search = document.getElementById('filter-search').value.trim();
        const statuses = Array.from(document.querySelectorAll('input[name="status"]:checked'))
            .map(function (input) { return input.value.trim(); })
            .filter(Boolean);
        const windowValue = timeWindow.value;
        if (search) {
            payload.search = search;
        }
        if (statuses.length) {
            payload.status = statuses;
        }
        if (document.getElementById('filter-include-unknown').checked) {
            payload.include_unknown = true;
        }
        if (windowValue && windowValue !== 'all') {
            payload.time_window = windowValue;
            if (windowValue === 'custom') {
                const start = document.getElementById('filter-start').value.trim();
                const end = document.getElementById('filter-end').value.trim();
                if (start) payload.start = start;
                if (end) payload.end = end;
            }
        }
        return payload;
    }

    function buildFilterParams() {
        const payload = buildFilterPayload();
        const params = new URLSearchParams();
        Object.keys(payload).forEach(function (key) {
            const value = payload[key];
            if (key === 'status' && Array.isArray(value)) {
                value.forEach(function (status) {
                    params.append('status', status);
                });
                return;
            }
            if (key === 'include_unknown' && value === true) {
                params.set('include_unknown', 'true');
                return;
            }
            params.set(key, value);
        });
        return params;
    }

    function parseJsonResponse(response, fallback) {
        const contentType = response.headers.get('Content-Type') || '';
        if (contentType.includes('application/json')) {
            return response.json().then(function (body) {
                if (!response.ok) throw new Error(body.error || fallback);
                return body;
            });
        }
        return response.text().then(function (text) {
            if (!response.ok) {
                throw new Error(text ? text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim() : fallback);
            }
            throw new Error(fallback);
        });
    }

    function updateCustomWindow() {
        customWindow.classList.toggle('d-none', timeWindow.value !== 'custom');
    }

    function updateSelection(collection, selectionId, checked) {
        const key = selectionKey(collection, selectionId);
        let selections = getSelections().filter(function (selection) {
            return selectionKey(selection.collection, selection.selection_id) !== key;
        });
        if (checked) selections.push({ collection: collection, selection_id: selectionId });
        setSelections(selections);
        updateSelectedCount();
        syncVisibleSelections();
    }

    function updateRelatedSelections(related, checked) {
        const relatedKeys = new Set(related.map(function (item) {
            return selectionKey(item.collection, item.selection_id);
        }));
        let selections = getSelections().filter(function (selection) {
            return !relatedKeys.has(selectionKey(selection.collection, selection.selection_id));
        });
        if (checked) {
            related.forEach(function (item) {
                selections.push({ collection: item.collection, selection_id: item.selection_id });
            });
        }
        setSelections(selections);
        updateSelectedCount();
        syncVisibleSelections();
    }

    function addHeader(label) {
        const cell = document.createElement('th');
        cell.scope = 'col';
        cell.textContent = label;
        resultsHead.append(cell);
        return cell;
    }

    function addCell(row, value, className, truncate) {
        const cell = document.createElement('td');
        const text = value || '-';
        cell.className = [className || '', truncate ? 'truncate-cell' : ''].filter(Boolean).join(' ');
        cell.textContent = text;
        if (truncate && text !== '-') cell.title = text;
        row.append(cell);
        return cell;
    }

    function vendorProductDisplay(document) {
        const vendor = document && document.vendor;
        const product = document && document.product;
        return {
            vendor: vendor || '-',
            product: product || '-',
        };
    }

    function renderHeaders() {
        resultsHead.replaceChildren();
        addHeader(t('Select'));
        addHeader(t('CVE'));
        addHeader(t('Severity'));
        addHeader(t('Description'));
        addHeader(t('Vendor'));
        addHeader(t('Product'));
        addHeader(t('Action'));
    }

    function renderRelatedButtonCell(row, item) {
        const cell = document.createElement('td');
        const related = Array.isArray(item.related) ? item.related : [];
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-outline-primary btn-sm';
        button.textContent = t('Relate ({count})', {count: related.length});
        button.disabled = related.length === 0;
        button.addEventListener('click', function () {
            openRelatedModal(item);
        });
        cell.append(button);
        row.append(cell);
    }

    function addRelatedCell(row, value, className) {
        const cell = document.createElement('td');
        const text = value || '-';
        cell.className = [className || '', 'truncate-cell'].filter(Boolean).join(' ');
        cell.textContent = text;
        if (text !== '-') cell.title = text;
        row.append(cell);
    }

    function showDocument(title, reviewDocument, options) {
        options = options || {};
        documentModalTitle.textContent = title;
        documentJson.textContent = JSON.stringify(reviewDocument || {}, null, 2);

        if (options.fromRelatedModal && relatedModalElement.classList.contains('show')) {
            restoreRelatedModalAfterDocument = true;
            relatedModalElement.addEventListener('hidden.bs.modal', function onRelatedHidden() {
                documentModal.show();
            }, { once: true });
            relatedModal.hide();
            return;
        }

        restoreRelatedModalAfterDocument = false;
        documentModal.show();
    }

    function renderRelatedModalRows(related) {
        const keys = selectedKeys();
        relatedBody.replaceChildren();
        related.forEach(function (relatedItem) {
            const row = document.createElement('tr');
            const selectCell = document.createElement('td');
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'form-check-input related-selection';
            checkbox.dataset.selectionCollection = relatedItem.collection;
            checkbox.dataset.selectionId = relatedItem.selection_id;
            checkbox.checked = keys.has(selectionKey(relatedItem.collection, relatedItem.selection_id));
            checkbox.setAttribute('aria-label', t('Select related {label}', {label: relatedItem.code || relatedItem.title || relatedItem.selection_id}));
            checkbox.addEventListener('change', function () {
                updateSelection(relatedItem.collection, relatedItem.selection_id, checkbox.checked);
            });
            selectCell.append(checkbox);
            row.append(selectCell);
            addRelatedCell(row, relatedItem.collection);

            const codeCell = document.createElement('td');
            const codeText = relatedItem.code || relatedItem.selection_id || '-';
            codeCell.className = 'fw-medium truncate-cell';
            codeCell.textContent = codeText;
            if (codeText !== '-') codeCell.title = codeText;
            if (relatedItem.is_self) {
                const self = document.createElement('span');
                self.className = 'badge text-bg-secondary ms-2';
                self.textContent = t('self');
                codeCell.append(self);
            }
            row.append(codeCell);

            addRelatedCell(row, relatedItem.title);
            addRelatedCell(row, relatedItem.severity);
            addRelatedCell(row, relatedItem.affected, 'small');

            const actionCell = document.createElement('td');
            const viewButton = document.createElement('button');
            viewButton.type = 'button';
            viewButton.className = 'btn btn-outline-primary btn-sm';
            viewButton.innerHTML = '<i class="bi bi-eye me-1"></i>' + t('View');
            viewButton.addEventListener('click', function () {
                showDocument(relatedItem.collection + ' ' + t('Document'), relatedItem.document, { fromRelatedModal: true });
            });
            actionCell.append(viewButton);
            row.append(actionCell);
            relatedBody.append(row);
        });
    }

    function openRelatedModal(item) {
        currentRelated = Array.isArray(item.related) ? item.related : [];
        const code = firstValue(item.document, ['code', 'cve']) || item.selection_id;
        relatedModalTitle.textContent = t('Related CVE Records: {code}', {code: code});
        relatedCount.textContent = currentRelated.length === 1 ? t('{count} related record', {count: currentRelated.length}) : t('{count} related records', {count: currentRelated.length});
        relatedEmpty.classList.toggle('d-none', currentRelated.length !== 0);
        relatedTableWrap.classList.toggle('d-none', currentRelated.length === 0);
        relatedSelectAll.disabled = currentRelated.length === 0;
        relatedClear.disabled = currentRelated.length === 0;
        renderRelatedModalRows(currentRelated);
        relatedModal.show();
    }

    function renderSelectCell(row, item, keys) {
        const selectCell = document.createElement('td');
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'form-check-input';
        checkbox.dataset.selectionCollection = item.collection;
        checkbox.dataset.selectionId = item.selection_id;
        checkbox.checked = keys.has(selectionKey(item.collection, item.selection_id));
        checkbox.setAttribute('aria-label', t('Select review document'));
        checkbox.addEventListener('change', function () {
            updateSelection(item.collection, item.selection_id, checkbox.checked);
        });
        selectCell.append(checkbox);
        row.append(selectCell);
    }

    function renderResults(body) {
        currentBody = body;
        const keys = selectedKeys();
        resultsBody.replaceChildren();
        renderHeaders();
        resultsTitle.textContent = t('CVE Results');

        body.data.forEach(function (item) {
            const projectedDocument = item.document;
            const row = document.createElement('tr');
            renderSelectCell(row, item, keys);
            addCell(
                row,
                firstValue(projectedDocument, ['code', 'cve', 'title']),
                'fw-medium',
                true
            );
            addCell(
                row,
                firstValue(projectedDocument, ['severity', 'impacts', 'status']),
                '',
                true
            );
            addCell(
                row,
                firstValue(projectedDocument, ['description', 'summary', 'overview', 'intro']),
                'small',
                true
            );
            const classified = vendorProductDisplay(projectedDocument);
            addCell(row, classified.vendor, '', true);
            addCell(row, classified.product, '', true);

            const actionCell = document.createElement('td');
            const viewButton = document.createElement('button');
            viewButton.type = 'button';
            viewButton.className = 'btn btn-outline-primary btn-sm';
            viewButton.innerHTML = '<i class="bi bi-eye me-1"></i>' + t('View');
            viewButton.addEventListener('click', function () {
                showDocument(item.collection + ' ' + t('Document'), projectedDocument);
            });
            actionCell.append(viewButton);
            row.append(actionCell);
            resultsBody.append(row);
        });

        resultsCount.textContent = body.total === 1
            ? t('{total} matching document', {total: body.total})
            : t('{total} matching documents', {total: body.total});
        resultsEmpty.classList.toggle('d-none', body.data.length !== 0);
        resultsTableWrap.classList.toggle('d-none', body.data.length === 0);
        pagination.classList.toggle('d-none', body.total === 0);
        currentPage = body.page;
        totalPages = body.pages;
        pageLabel.textContent = t('Page {current} of {total}', {current: currentPage, total: totalPages});
        previousPage.disabled = currentPage <= 1;
        nextPage.disabled = currentPage >= totalPages;
    }

    function runSearch(page) {
        activeFilters = buildFilterParams();
        resultsLoading.classList.remove('d-none');
        resultsEmpty.classList.add('d-none');
        resultsTableWrap.classList.add('d-none');
        pagination.classList.add('d-none');
        error.classList.add('d-none');
        statusAlert.classList.add('d-none');
        refresh.disabled = true;

        const params = new URLSearchParams(activeFilters);
        params.set('page', page);
        params.set('page_size', pageSize.value);
        fetch(searchUrl + '?' + params.toString())
            .then(function (response) { return parseJsonResponse(response, t('Unable to search review documents.')); })
            .then(renderResults)
            .catch(function (reason) {
                showError(reason.message);
            })
            .finally(function () {
                resultsLoading.classList.add('d-none');
                refresh.disabled = false;
            });
    }

    filterForm.addEventListener('submit', function (event) {
        event.preventDefault();
        runSearch(1);
    });
    timeWindow.addEventListener('change', function () {
        updateCustomWindow();
        if (timeWindow.value !== 'custom') runSearch(1);
    });
    clearFilter.addEventListener('click', function () {
        filterForm.reset();
        updateCustomWindow();
        runSearch(1);
    });
    previousPage.addEventListener('click', function () { runSearch(currentPage - 1); });
    nextPage.addEventListener('click', function () { runSearch(currentPage + 1); });
    pageSize.addEventListener('change', function () { runSearch(1); });
    refresh.addEventListener('click', function () { runSearch(currentPage); });
    relatedSelectAll.addEventListener('click', function () {
        updateRelatedSelections(currentRelated, true);
    });
    relatedClear.addEventListener('click', function () {
        updateRelatedSelections(currentRelated, false);
    });
    documentModalElement.addEventListener('hidden.bs.modal', function () {
        if (!restoreRelatedModalAfterDocument || !currentRelated.length) {
            return;
        }
        restoreRelatedModalAfterDocument = false;
        relatedModal.show();
    });

    function buildAutoSelectPayload() {
        const payload = buildFilterPayload();
        const count = parseInt(autoSelectCount.value, 10);
        payload.count = Number.isFinite(count) ? count : 0;
        return payload;
    }

    function formatAutoSelectSummary(summary) {
        return ['Critical', 'High', 'Medium', 'Low']
            .map(function (priority) {
                const count = summary && summary[priority] ? summary[priority] : 0;
                return count ? t(priority) + ': ' + count : '';
            })
            .filter(Boolean)
            .join(', ');
    }

    autoSelectButton.addEventListener('click', function () {
        activeFilters = buildFilterParams();
        const payload = buildAutoSelectPayload();
        if (!payload.count || payload.count < 1 || payload.count > 500) {
            showError(t('Auto-select count must be between 1 and 500.'));
            return;
        }

        error.classList.add('d-none');
        statusAlert.classList.add('d-none');
        autoSelectButton.disabled = true;
        autoSelectButton.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>' + t('Selecting...');

        fetch(autoSelectUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        })
            .then(function (response) { return parseJsonResponse(response, t('Unable to auto-select review documents.')); })
            .then(function (body) {
                const selections = (body.selections || []).map(function (item) {
                    return {
                        collection: item.collection,
                        selection_id: item.selection_id,
                        selection_score: item.selection_score,
                        patch_priority: item.patch_priority,
                    };
                });
                setSelections(selections);
                updateSelectedCount();
                if (currentBody) {
                    syncVisibleSelections();
                }
                const summaryText = formatAutoSelectSummary(body.summary);
                showStatus(
                    t('Auto-selected {selected} of {matched}', {selected: body.selected, matched: body.matched})
                    + ' ' + (body.matched === 1
                        ? t('{total} matching document', {total: body.matched})
                        : t('{total} matching documents', {total: body.matched}))
                    + (summaryText ? ' (' + summaryText + ').' : '.')
                );
            })
            .catch(function (reason) {
                showError(reason.message);
            })
            .finally(function () {
                autoSelectButton.disabled = false;
                autoSelectButton.innerHTML = '<i class="bi bi-magic me-1"></i>' + t('By importance');
            });
    });

    clearSelection.addEventListener('click', function () {
        localStorage.removeItem(selectionStorageKey);
        updateSelectedCount();
        if (currentBody) renderResults(currentBody);
    });

    exportButton.addEventListener('click', function () {
        const selections = getSelections();
        if (!selections.length) return;

        error.classList.add('d-none');
        exportButton.disabled = true;
        exportButton.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>' + t('Exporting...');

        fetch(exportUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ selections: selections })
        })
            .then(function (response) {
                if (!response.ok) {
                    return response.json().then(function (body) {
                        throw new Error(body.error || t('Unable to export documents.'));
                    });
                }
                const disposition = response.headers.get('Content-Disposition') || '';
                const match = disposition.match(/filename="([^"]+)"/);
                return response.blob().then(function (blob) {
                    return { blob: blob, filename: match ? match[1] : 'vulnerability-export.json' };
                });
            })
            .then(function (download) {
                const link = document.createElement('a');
                const url = URL.createObjectURL(download.blob);
                link.href = url;
                link.download = download.filename;
                document.body.append(link);
                link.click();
                link.remove();
                URL.revokeObjectURL(url);
                localStorage.removeItem(selectionStorageKey);
                updateSelectedCount();
                if (currentBody) renderResults(currentBody);
            })
            .catch(function (reason) {
                showError(reason.message);
            })
            .finally(function () {
                exportButton.innerHTML = '<i class="bi bi-download me-1"></i>' + t('Export JSON');
                updateSelectedCount();
            });
    });

    updateSelectedCount();
    updateCustomWindow();
    runSearch(1);
})();
