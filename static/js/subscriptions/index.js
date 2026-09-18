(function () {
    const {
        subscriptionsUrl,
        previewUrl,
        reviewsUrl,
        vendorProductImportUrl,
        vendorProductTemplateUrl,
        isAdmin,
        accountHubEnabled,
    } = JSON.parse(document.getElementById('page-config').textContent);
    const modal = new bootstrap.Modal(document.getElementById('subscription-modal'));
    const newsletterCollections = new CollectionPicker('newsletter', {emptySelectionMeansAll: true});
    const rows = document.getElementById('rows');
    const message = document.getElementById('message');
    let collections = [], subscriptions = [], editingId = null;
    let newsletterVendorProductFilter = emptyVendorProductFilter();
    let reportVendorProductFilter = emptyVendorProductFilter();
    let reportLegacyKeywords = [];
    let reportOriginalLegacyKeywords = [];
    let reportHasLegacyKeywords = false;
    let vendorProductImportBusy = false;
    let vendorProductImportRequestId = 0;
    let previewTimer = null;
    let previewAbortController = null;
    let previewRequestId = 0;

    const severityLevels = ['Critical', 'High', 'Medium', 'Low'];
    function emptyVendorProductFilter() {
        return {
            enabled: false,
            schema_version: 1,
            include_possible_matches: false,
            rows: []
        };
    }
    function getVendorProductFilter(prefix) {
        return prefix === 'newsletter' ? newsletterVendorProductFilter : reportVendorProductFilter;
    }
    function setVendorProductFilter(prefix, value) {
        if (prefix === 'newsletter') {
            newsletterVendorProductFilter = value;
        } else {
            reportVendorProductFilter = value;
        }
    }
    function vendorProductImportMarkup(prefix, options) {
        options = options || {};
        const warning = options.matchWarning
            || t('CVE vendor and product data may be incomplete. Matching can produce false positives or false negatives.');
        const legacyWarning = options.includeLegacyWarning
            ? '<div id="' + prefix + '-legacy-keywords-warning" class="alert alert-warning small py-2 mt-2 mb-0 d-none" role="alert"></div>'
            : '';
        return '<div class="col-12"><div id="' + prefix + '-vendor-product-import" class="subscription-vendor-product-import border rounded p-3">' +
        '<div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2"><label class="form-label small fw-semibold mb-0" for="' + prefix + '-vendor-product-file">' + t('Product inventory (CSV)') + '</label><a id="' + prefix + '-vendor-product-template" class="btn btn-outline-secondary btn-sm" href="#" download><i class="bi bi-download me-1"></i>' + t('Download CSV template') + '</a></div>' +
        '<input id="' + prefix + '-vendor-product-file" class="form-control form-control-sm" type="file" accept=".csv,text/csv" aria-describedby="' + prefix + '-vendor-product-help">' +
        '<div id="' + prefix + '-vendor-product-help" class="form-text">' + t('Choose a CSV with vendor and product rows. It is validated and loaded into this form; changes apply only after you save.') + '</div>' +
        '<div class="subscription-match-warning small mt-2"><i class="bi bi-exclamation-triangle me-1"></i>' + warning + '</div>' +
        legacyWarning +
        '<div id="' + prefix + '-vendor-product-status" class="alert small py-2 mt-2 mb-0 d-none" role="status" aria-live="polite"></div>' +
        '<div id="' + prefix + '-vendor-product-summary" class="small text-muted mt-2"></div>' +
        '<div id="' + prefix + '-vendor-product-preview" class="table-responsive subscription-vendor-product-preview mt-2 d-none"><table class="table table-sm table-bordered align-middle mb-0"><thead class="table-light"><tr><th>' + t('CSV row') + '</th><th>' + t('Vendor') + '</th><th>' + t('Product') + '</th><th>' + t('Vendor aliases') + '</th><th>' + t('Product aliases') + '</th></tr></thead><tbody id="' + prefix + '-vendor-product-rows"></tbody></table></div>' +
        '<div id="' + prefix + '-vendor-product-preview-note" class="form-text d-none"></div>' +
        '<div class="d-flex flex-wrap justify-content-between align-items-start gap-2 mt-2"><div class="form-check"><input id="' + prefix + '-include-possible-matches" class="form-check-input" type="checkbox" aria-describedby="' + prefix + '-include-possible-help"><label class="form-check-label small" for="' + prefix + '-include-possible-matches">' + t('Include product-only possible matches when structured vendor data is missing') + '</label><div id="' + prefix + '-include-possible-help" class="form-text">' + t('This may reduce false negatives but increases false-positive risk. Ambiguous products and known conflicting inventory vendors are suppressed.') + '</div></div><button id="' + prefix + '-vendor-product-clear" class="btn btn-outline-danger btn-sm" type="button">' + t('Clear inventory') + '</button></div>' +
        '</div></div>';
    }
    function newsletterFilterMarkup() {
        return '<div class="row g-2">' +
        '<div class="col-md-6">' +
        '<label for="newsletter-collections-toggle" class="form-label small">' + t('Collections') + '</label>' +
        '<div class="dropdown w-100">' +
        '<button id="newsletter-collections-toggle" type="button" class="form-select form-select-sm dropdown-toggle subscription-collections-toggle text-start w-100" data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false">' + t('All collections') + '</button>' +
        '<div id="newsletter-collections-menu" class="dropdown-menu w-100 shadow-sm p-2">' +
        '<input id="newsletter-collections-search" type="search" class="form-control form-control-sm mb-2" placeholder="' + t('Search collections...') + '" autocomplete="off">' +
        '<div id="newsletter-collections-options" class="subscription-collections-options"></div>' +
        '<div class="dropdown-divider my-2"></div>' +
        '<div class="d-flex justify-content-between px-1">' +
        '<button type="button" class="btn btn-link btn-sm p-0 collections-action" data-action="all">' + t('Select all') + '</button>' +
        '<button type="button" class="btn btn-link btn-sm p-0 text-muted collections-action" data-action="reset">' + t('Reset to all') + '</button>' +
        '</div></div></div></div>' +
        '<div class="col-12"><label class="form-label small">' + t('Severity / status') + '</label><div class="d-flex flex-wrap gap-3">' +
        severityLevels.map(function (level) {
            return '<div class="form-check"><input id="newsletter-status-' + level + '" class="form-check-input newsletter-status-checkbox" type="checkbox" value="' + level + '"><label class="form-check-label small" for="newsletter-status-' + level + '">' + t(level) + '</label></div>';
        }).join('') +
        '</div><div class="form-text">' + t('Leave all unchecked to match all known severities.') + '</div><div class="form-check mt-2"><input id="newsletter-include-unknown" class="form-check-input" type="checkbox"><label class="form-check-label small" for="newsletter-include-unknown">' + t('Include unknown severity') + '</label></div></div>' +
        vendorProductImportMarkup('newsletter', {
            matchWarning: t('CVE vendor and product data may be incomplete. Matching can produce false positives or false negatives; only inventory-matched advisories are emailed when an inventory is saved.')
        }) +
        '</div>';
    }

    function reportFilterMarkup() {
        return '<div class="row g-2">' +
        '<div class="col-12"><label class="form-label small">' + t('Severity / status') + '</label><div class="d-flex flex-wrap gap-3">' +
        severityLevels.map(function (level) {
            return '<div class="form-check"><input id="report-status-' + level + '" class="form-check-input report-status-checkbox" type="checkbox" value="' + level + '"><label class="form-check-label small" for="report-status-' + level + '">' + t(level) + '</label></div>';
        }).join('') +
        '</div><div class="form-text">' + t('Leave all unchecked to match all known severities.') + '</div></div>' +
        vendorProductImportMarkup('report', {
            matchWarning: t('CVE vendor and product data may be incomplete. Matching can produce false positives or false negatives; review the report preview before saving.'),
            includeLegacyWarning: true
        }) +
        '<div class="col-md-6 d-flex align-items-end"><div class="form-check mb-2"><input id="report-include-unknown" class="form-check-input" type="checkbox"><label class="form-check-label small" for="report-include-unknown">' + t('Include unknown severity') + '</label></div></div>' +
        timeWindowMarkup('report') +
        '</div>';
    }

    function timeWindowMarkup(prefix) {
        return '<div class="col-md-6"><label class="form-label small">' + t('Time window') + '</label><select id="' + prefix + '-time-window" class="form-select form-select-sm"><option value="all">' + t('All time') + '</option><option value="daily">' + t('Today') + '</option><option value="week">' + t('Last 7 days') + '</option><option value="custom">' + t('Custom') + '</option></select></div>' +
        '<div id="' + prefix + '-custom-window" class="col-12 d-none"><div class="row g-2">' +
        '<div class="col-md-6"><label class="form-label small">' + t('Start') + '</label><input id="' + prefix + '-start" type="datetime-local" class="form-control form-control-sm"></div>' +
        '<div class="col-md-6"><label class="form-label small">' + t('End') + '</label><input id="' + prefix + '-end" type="datetime-local" class="form-control form-control-sm"></div></div></div>';
    }

    document.getElementById('newsletter-fields').innerHTML = newsletterFilterMarkup();
    document.getElementById('report-fields').innerHTML = reportFilterMarkup();
    document.getElementById('newsletter-vendor-product-template').href = vendorProductTemplateUrl;
    document.getElementById('report-vendor-product-template').href = vendorProductTemplateUrl;

    function showMessage(text, kind) { message.textContent = text; message.className = 'alert alert-' + kind; }
    function showModalMessage(text, kind) {
        const modalMessage = document.getElementById('subscription-modal-message');
        modalMessage.textContent = text || '';
        modalMessage.className = text ? 'alert alert-' + kind : 'alert d-none';
    }
    function renderRecipientInputs(emails) {
        const list = document.getElementById('recipient-list');
        list.replaceChildren();
        const values = Array.isArray(emails) && emails.length ? emails : [''];
        values.forEach(function (email) {
            const row = document.createElement('div');
            row.className = 'input-group';
            const input = document.createElement('input');
            input.type = 'email';
            input.className = 'form-control recipient-input';
            input.placeholder = t('recipient@example.com');
            input.value = email || '';
            input.required = true;
            input.readOnly = !isAdmin;
            input.setAttribute('aria-label', t('Email recipient'));
            row.append(input);
            if (isAdmin) {
                const remove = document.createElement('button');
                remove.type = 'button';
                remove.className = 'btn btn-outline-danger remove-recipient';
                remove.innerHTML = '<i class="bi bi-dash-lg" aria-hidden="true"></i><span class="visually-hidden">' + t('Remove recipient') + '</span>';
                remove.onclick = function () {
                    if (list.children.length > 1) {
                        row.remove();
                        updateRecipientRemoveButtons();
                    }
                };
                row.append(remove);
            }
            list.append(row);
        });
        updateRecipientRemoveButtons();
    }
    function updateRecipientRemoveButtons() {
        const list = document.getElementById('recipient-list');
        list.querySelectorAll('.remove-recipient').forEach(function (button) {
            button.disabled = list.children.length <= 1;
        });
    }
    function recipientValues() {
        return Array.from(document.querySelectorAll('.recipient-input')).map(function (input) {
            return input.value.trim();
        });
    }
    function setSendStatisticStatus(text, kind) {
        const status = document.getElementById('newsletter-send-statistic-status');
        if (!text) {
            status.textContent = '';
            status.className = 'alert small mt-2 mb-0 d-none';
            return;
        }
        status.textContent = text;
        status.className = 'alert alert-' + kind + ' small mt-2 mb-0';
    }
    function setSendStatisticBusy(busy) {
        const button = document.getElementById('newsletter-send-statistic');
        const label = button.querySelector('.send-statistic-label');
        button.disabled = busy;
        if (busy) {
            label.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>' + t('Sending...');
        } else {
            label.textContent = t('Send Statistic');
        }
    }
    function requestJson(url, options) {
        return fetch(url, options).then(function (response) {
            const contentType = (response.headers.get('content-type') || '').toLowerCase();
            if (!contentType.includes('application/json')) {
                return response.text().then(function () {
                    throw new Error(t('Server returned HTML instead of JSON.'));
                });
            }
            return response.json().then(function (body) {
                if (!response.ok) throw new Error(body.error || t('Request failed.'));
                return body;
            });
        });
    }
    function apiUrl(id, suffix) { return subscriptionsUrl + '/' + encodeURIComponent(id) + (suffix || ''); }
    function setReportPreview(summary, kind, examples) {
        const box = document.getElementById('report-preview');
        const target = document.getElementById('report-preview-summary');
        const exampleList = document.getElementById('report-preview-examples');
        box.className = 'alert border small mt-3 mb-0 alert-' + kind;
        target.textContent = summary;
        exampleList.replaceChildren();
        const confidenceLabels = {
            confirmed: t('Confirmed'),
            probable: t('Probable'),
            possible: t('Possible')
        };
        (Array.isArray(examples) ? examples : []).forEach(function (example) {
            const evidence = example.evidence && typeof example.evidence === 'object'
                ? example.evidence : {};
            const evidenceSummary = evidence.text || evidence.product || [
                evidence.vendor,
                evidence.product
            ].filter(Boolean).join(' / ') || evidence.source || evidence.type || '—';
            const item = document.createElement('li');
            item.textContent = t('{cve} — {confidence} vendor/product match: {vendor} / {product}. Evidence: {evidence}', {
                cve: example.cve || '—',
                confidence: confidenceLabels[example.confidence] || example.confidence || '—',
                vendor: example.matched_vendor || '—',
                product: example.matched_product || '—',
                evidence: evidence.source
                    ? evidence.source + ': ' + evidenceSummary
                    : evidenceSummary
            });
            exampleList.append(item);
        });
        exampleList.classList.toggle('d-none', exampleList.children.length === 0);
    }
    function isReportEnriched() {
        return document.getElementById('report-generation-mode').value === 'enriched_weekly';
    }
    function updateReportSearchPromptVisibility() {
        const wrap = document.getElementById('report-search-prompt-wrap');
        if (wrap) {
            wrap.classList.toggle('d-none', !isReportEnriched());
        }
    }
    function normalizeVendorProductRow(value) {
        if (!value || typeof value !== 'object') return null;
        const vendor = typeof value.vendor === 'string' ? value.vendor.trim() : '';
        const product = typeof value.product === 'string' ? value.product.trim() : '';
        if (!vendor || !product) return null;
        function aliases(items) {
            if (!Array.isArray(items)) return [];
            return items.filter(function (item) { return typeof item === 'string' && item.trim(); })
                .map(function (item) { return item.trim(); });
        }
        const normalized = {
            vendor: vendor,
            product: product,
            vendor_aliases: aliases(value.vendor_aliases),
            product_aliases: aliases(value.product_aliases)
        };
        if (Number.isInteger(value.row_number) && value.row_number >= 2) {
            normalized.row_number = value.row_number;
        }
        return normalized;
    }
    function normalizeVendorProductFilter(value) {
        value = value && typeof value === 'object' ? value : {};
        const normalizedRows = Array.isArray(value.rows) ? value.rows.map(normalizeVendorProductRow).filter(Boolean) : [];
        return {
            enabled: value.enabled === true && normalizedRows.length > 0,
            schema_version: 1,
            include_possible_matches: value.include_possible_matches === true,
            rows: normalizedRows
        };
    }
    function hasValidVendorProductInventory(prefix) {
        const inventory = getVendorProductFilter(prefix);
        return inventory.enabled === true && inventory.rows.length > 0;
    }
    function vendorProductFilterPayload(prefix) {
        const inventory = getVendorProductFilter(prefix);
        return {
            enabled: hasValidVendorProductInventory(prefix),
            schema_version: 1,
            include_possible_matches: document.getElementById(prefix + '-include-possible-matches').checked,
            rows: inventory.rows.map(function (row) {
                const payloadRow = {
                    vendor: row.vendor,
                    product: row.product,
                    vendor_aliases: row.vendor_aliases.slice(),
                    product_aliases: row.product_aliases.slice()
                };
                if (Number.isInteger(row.row_number) && row.row_number >= 2) {
                    payloadRow.row_number = row.row_number;
                }
                return payloadRow;
            })
        };
    }
    function renderLegacyKeywordWarning() {
        const warning = document.getElementById('report-legacy-keywords-warning');
        if (!warning) return;
        warning.classList.toggle('d-none', !reportHasLegacyKeywords);
        warning.textContent = reportHasLegacyKeywords
            ? (reportLegacyKeywords.length
                ? t('This subscription contains a legacy keyword filter. It remains unchanged unless you load a valid product CSV and save the subscription.')
                : t('A valid product inventory is ready. It will replace the legacy keyword filter when you save.'))
            : '';
    }
    function renderVendorProductInventory(prefix) {
        const preview = document.getElementById(prefix + '-vendor-product-preview');
        const previewRows = document.getElementById(prefix + '-vendor-product-rows');
        const summary = document.getElementById(prefix + '-vendor-product-summary');
        const note = document.getElementById(prefix + '-vendor-product-preview-note');
        const clearButton = document.getElementById(prefix + '-vendor-product-clear');
        const inventoryRows = getVendorProductFilter(prefix).rows;
        const shownRows = inventoryRows.slice(0, 25);
        const emptyHint = prefix === 'newsletter'
            ? t('No vendor/product inventory loaded. Newsletter delivery may include all vendors and products in the selected collections.')
            : t('No vendor/product inventory loaded. Other report filters may match all vendors and products.');

        previewRows.replaceChildren();
        summary.textContent = inventoryRows.length
            ? t('{count} vendor/product row(s) loaded and ready to save.', {count: inventoryRows.length})
            : emptyHint;
        preview.classList.toggle('d-none', inventoryRows.length === 0);
        clearButton.disabled = vendorProductImportBusy || inventoryRows.length === 0;

        shownRows.forEach(function (row, index) {
            const tr = document.createElement('tr');
            [
                row.row_number || index + 2,
                row.vendor,
                row.product,
                row.vendor_aliases.join(', ') || '—',
                row.product_aliases.join(', ') || '—'
            ].forEach(function (value) {
                const td = document.createElement('td');
                td.textContent = value;
                tr.append(td);
            });
            previewRows.append(tr);
        });

        const truncated = inventoryRows.length > shownRows.length;
        note.classList.toggle('d-none', !truncated);
        note.textContent = truncated
            ? t('Showing the first {shown} of {count} loaded rows.', {shown: shownRows.length, count: inventoryRows.length})
            : '';
        if (prefix === 'report') {
            renderLegacyKeywordWarning();
        }
    }
    function setVendorProductImportStatus(prefix, text, kind, warnings) {
        const status = document.getElementById(prefix + '-vendor-product-status');
        status.replaceChildren();
        if (!text && (!warnings || !warnings.length)) {
            status.className = 'alert small py-2 mt-2 mb-0 d-none';
            return;
        }
        status.className = 'alert alert-' + kind + ' small py-2 mt-2 mb-0';
        if (text) {
            const messageText = document.createElement('div');
            messageText.textContent = text;
            status.append(messageText);
        }
        if (Array.isArray(warnings) && warnings.length) {
            const list = document.createElement('ul');
            list.className = 'mb-0 mt-1 ps-3';
            warnings.forEach(function (warning) {
                const item = document.createElement('li');
                item.textContent = String(warning);
                list.append(item);
            });
            status.append(list);
        }
    }
    function setVendorProductImportBusy(busy) {
        vendorProductImportBusy = busy;
        const saveButton = document.querySelector('#subscription-form button[type="submit"]');
        saveButton.disabled = busy;
        ['newsletter', 'report'].forEach(function (prefix) {
            const container = document.getElementById(prefix + '-vendor-product-import');
            const input = document.getElementById(prefix + '-vendor-product-file');
            const includePossible = document.getElementById(prefix + '-include-possible-matches');
            container.setAttribute('aria-busy', busy ? 'true' : 'false');
            input.disabled = busy;
            includePossible.disabled = busy;
            renderVendorProductInventory(prefix);
        });
    }
    function importVendorProductCsv(prefix, file) {
        if (!file || vendorProductImportBusy) return;
        const requestId = ++vendorProductImportRequestId;
        const includePossibleMatches = document.getElementById(prefix + '-include-possible-matches').checked;
        const form = new FormData();
        form.append('file', file);
        setVendorProductImportBusy(true);
        setVendorProductImportStatus(prefix, t('Validating CSV...'), 'info');
        requestJson(vendorProductImportUrl, {method: 'POST', body: form})
            .then(function (body) {
                if (requestId !== vendorProductImportRequestId) return;
                const imported = normalizeVendorProductFilter(body.vendor_product_filter);
                if (!imported.enabled || !imported.rows.length) {
                    throw new Error(t('The CSV did not contain any valid vendor/product rows.'));
                }
                imported.include_possible_matches = includePossibleMatches;
                setVendorProductFilter(prefix, imported);
                if (prefix === 'report') {
                    reportLegacyKeywords = [];
                }
                document.getElementById(prefix + '-include-possible-matches').checked = includePossibleMatches;
                renderVendorProductInventory(prefix);
                setVendorProductImportStatus(
                    prefix,
                    t('Validated and loaded {count} vendor/product row(s). Save the subscription to apply them.', {count: imported.rows.length}),
                    body.warnings && body.warnings.length ? 'warning' : 'success',
                    body.warnings
                );
                if (prefix === 'report') {
                    scheduleReportPreview();
                }
            })
            .catch(function (error) {
                if (requestId !== vendorProductImportRequestId) return;
                setVendorProductImportStatus(prefix, error.message, 'danger');
            })
            .finally(function () {
                if (requestId !== vendorProductImportRequestId) return;
                document.getElementById(prefix + '-vendor-product-file').value = '';
                setVendorProductImportBusy(false);
            });
    }
    function clearVendorProductInventory(prefix) {
        const confirmMessage = prefix === 'newsletter'
            ? t('Clear the product inventory? Newsletter delivery may then include all vendors and products in the selected collections.')
            : t('Clear the product inventory? Other report filters may then match all vendors and products.');
        if (!window.confirm(confirmMessage)) {
            return;
        }
        const includePossibleMatches = document.getElementById(prefix + '-include-possible-matches').checked;
        const cleared = emptyVendorProductFilter();
        cleared.include_possible_matches = includePossibleMatches;
        setVendorProductFilter(prefix, cleared);
        if (prefix === 'report') {
            reportLegacyKeywords = reportOriginalLegacyKeywords.slice();
        }
        document.getElementById(prefix + '-vendor-product-file').value = '';
        renderVendorProductInventory(prefix);
        setVendorProductImportStatus(prefix, t('Product inventory will be cleared when you save.'), 'secondary');
        if (prefix === 'report') {
            scheduleReportPreview();
        }
    }

    function toggleCustomWindow(prefix) {
        const custom = document.getElementById(prefix + '-time-window').value === 'custom';
        document.getElementById(prefix + '-custom-window').classList.toggle('d-none', !custom);
    }
    function setStatusFilters(prefix, status) {
        const selected = Array.isArray(status) ? status : (status ? [status] : []);
        if (prefix === 'report' || prefix === 'newsletter') {
            const selector = prefix === 'report'
                ? '#report-fields .report-status-checkbox'
                : '#newsletter-fields .newsletter-status-checkbox';
            document.querySelectorAll(selector).forEach(function (input) {
                input.checked = selected.includes(input.value);
            });
            return;
        }
        document.getElementById(prefix + '-status').value = selected[0] || '';
    }
    function readStatusFilters(prefix) {
        if (prefix === 'report' || prefix === 'newsletter') {
            const selector = prefix === 'report'
                ? '#report-fields .report-status-checkbox'
                : '#newsletter-fields .newsletter-status-checkbox';
            return Array.from(document.querySelectorAll(selector))
                .filter(function (input) { return input.checked; })
                .map(function (input) { return input.value; });
        }
        return document.getElementById(prefix + '-status').value;
    }
    function setFilters(prefix, filters) {
        filters = filters || {};
        if (prefix === 'newsletter') {
            newsletterCollections.render(collections, filters.collections || []);
            setVendorProductFilter(prefix, normalizeVendorProductFilter(filters.vendor_product_filter));
            document.getElementById(prefix + '-include-possible-matches').checked = getVendorProductFilter(prefix).include_possible_matches;
            document.getElementById(prefix + '-vendor-product-file').value = '';
            setVendorProductImportStatus(prefix, '', '');
            renderVendorProductInventory(prefix);
            setStatusFilters(prefix, filters.status || []);
            document.getElementById(prefix + '-include-unknown').checked = filters.include_unknown === true;
            return;
        }
        if (prefix === 'report') {
            const legacyKeywords = Array.isArray(filters.keywords)
                ? filters.keywords.filter(function (item) { return typeof item === 'string' && item.trim(); })
                : [];
            setVendorProductFilter(prefix, normalizeVendorProductFilter(filters.vendor_product_filter));
            reportOriginalLegacyKeywords = legacyKeywords.slice();
            reportHasLegacyKeywords = legacyKeywords.length > 0;
            reportLegacyKeywords = hasValidVendorProductInventory(prefix) ? [] : legacyKeywords.slice();
            document.getElementById(prefix + '-include-possible-matches').checked = getVendorProductFilter(prefix).include_possible_matches;
            document.getElementById(prefix + '-vendor-product-file').value = '';
            setVendorProductImportStatus(prefix, '', '');
            renderVendorProductInventory(prefix);
        }
        setStatusFilters(prefix, filters.status || []);
        document.getElementById(prefix + '-include-unknown').checked = filters.include_unknown === true;
        document.getElementById(prefix + '-time-window').value = filters.time_window || 'all';
        toggleCustomWindow(prefix);
    }
    function readFilters(prefix) {
        const filters = {};
        if (prefix === 'newsletter') {
            return {
                collections: newsletterCollections.selectedValues(),
                status: readStatusFilters(prefix),
                include_unknown: document.getElementById(prefix + '-include-unknown').checked,
                vendor_product_filter: vendorProductFilterPayload(prefix)
            };
        } else if (isReportEnriched()) {
            filters.collections = ['cve_review'];
        }
        filters.status = readStatusFilters(prefix);
        if (prefix === 'report') {
            filters.vendor_product_filter = vendorProductFilterPayload(prefix);
            if (reportLegacyKeywords.length && !hasValidVendorProductInventory(prefix)) {
                filters.keywords = reportLegacyKeywords.slice();
            }
        }
        filters.include_unknown = document.getElementById(prefix + '-include-unknown').checked;
        filters.time_window = document.getElementById(prefix + '-time-window').value;
        filters.start = document.getElementById(prefix + '-start').value;
        filters.end = document.getElementById(prefix + '-end').value;
        if (filters.time_window !== 'custom') { filters.start = ''; filters.end = ''; }
        return filters;
    }
    function buildReportProfilePayload() {
        const payload = {
            report_profile: {
                enabled: document.getElementById('report-enabled').checked,
                filters: readFilters('report'),
                generation_mode: document.getElementById('report-generation-mode').value,
                report_language: document.getElementById('report-language').value,
                schedule_enabled: document.getElementById('report-schedule-enabled').checked,
                schedule_weekday: document.getElementById('report-schedule-weekday').value,
                schedule_time: document.getElementById('report-schedule-time').value
            }
        };
        if (editingId) payload.subscription_id = editingId;
        if (isReportEnriched()) {
            payload.report_profile.search_prompt = (document.getElementById('report-search-prompt').value || '').trim();
        }
        return payload;
    }
    function refreshReportPreview() {
        const requestId = ++previewRequestId;
        if (previewAbortController) {
            previewAbortController.abort();
            previewAbortController = null;
        }
        if (!document.getElementById('report-enabled').checked) {
            setReportPreview(t('Report profile is disabled.'), 'secondary');
            return;
        }
        if (reportLegacyKeywords.length && !hasValidVendorProductInventory('report')) {
            setReportPreview(
                t('Import a vendor/product CSV to replace the legacy keyword filter and preview confidence levels.'),
                'warning'
            );
            return;
        }
        previewAbortController = new AbortController();
        setReportPreview(t('Loading preview...'), 'light');
        requestJson(previewUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(buildReportProfilePayload()),
            signal: previewAbortController.signal
        }).then(function (body) {
            if (requestId !== previewRequestId) return;
            const top = body.top_cves && body.top_cves.length ? body.top_cves.join(', ') : t('No example CVEs yet');
            const summary = body.vendor_product_filter_enabled
                ? t('{count} CVE(s) matched the inventory. Vendor/product match confidence: {confirmed} confirmed, {probable} probable, {possible} possible. Top examples: {top}.', {
                    count: body.count || 0,
                    confirmed: body.confirmed_count || 0,
                    probable: body.probable_count || 0,
                    possible: body.possible_count || 0,
                    top: top
                })
                : t('{count} matching CVE(s). Top examples: {top}.', {count: body.count || 0, top: top});
            setReportPreview(
                summary,
                body.count ? 'info' : 'warning',
                body.match_examples || []
            );
        }).catch(function (e) {
            if (e.name === 'AbortError') return;
            if (requestId !== previewRequestId) return;
            setReportPreview(e.message, 'danger');
        });
    }
    function scheduleReportPreview() {
        if (previewTimer) window.clearTimeout(previewTimer);
        previewTimer = window.setTimeout(refreshReportPreview, 400);
    }
    function openEditor(subscription) {
        vendorProductImportRequestId += 1;
        setVendorProductImportBusy(false);
        showModalMessage('', '');
        editingId = subscription ? subscription.id : null;
        document.getElementById('modal-title').textContent = subscription ? t('Edit Subscription') : t('Add Subscription');
        const username = document.getElementById('username');
        username.value = subscription ? (subscription.username || '') : '';
        username.readOnly = !isAdmin;
        renderRecipientInputs(subscription ? (subscription.emails || [subscription.email]) : ['']);
        document.getElementById('team').value = subscription ? subscription.team : '';
        document.getElementById('delivery-mode').value = subscription ? (subscription.delivery_mode || 'individual') : 'individual';
        if (isAdmin && !accountHubEnabled) {
            document.getElementById('password').value = '';
            document.getElementById('password-help').textContent = subscription
                ? t('Leave blank to keep the current password.')
                : t('Required when creating a subscription.');
        }
        const newsletter = subscription ? subscription.newsletter_profile : {enabled:false,filters:{}};
        const report = subscription ? subscription.report_profile : {enabled:false,filters:{},generation_mode:'template',report_language:'en'};
        document.getElementById('newsletter-enabled').checked = newsletter.enabled; setFilters('newsletter', newsletter.filters);
        document.getElementById('newsletter-statistic-schedule-enabled').checked = newsletter.statistic_schedule_enabled === true;
        document.getElementById('report-enabled').checked = report.enabled; setFilters('report', report.filters);
        setVendorProductImportBusy(false);
        document.getElementById('report-generation-mode').value = report.generation_mode;
        document.getElementById('report-language').value = report.report_language;
        document.getElementById('report-search-prompt').value = report.search_prompt || '';
        document.getElementById('report-schedule-enabled').checked = report.schedule_enabled === true;
        document.getElementById('report-schedule-weekday').value = report.schedule_weekday || 'mon';
        document.getElementById('report-schedule-time').value = report.schedule_time || '09:00';
        setSendStatisticBusy(false);
        setSendStatisticStatus('', '');
        updateNewsletterSendStatisticVisibility();
        updateReportSearchPromptVisibility();
        refreshReportPreview();
        modal.show();
    }
    function updateNewsletterSendStatisticVisibility() {
        const wrap = document.getElementById('newsletter-send-statistic-wrap');
        const show = !!editingId && document.getElementById('newsletter-enabled').checked;
        wrap.classList.toggle('d-none', !show);
        if (!show) {
            setSendStatisticStatus('', '');
            setSendStatisticBusy(false);
        }
    }
    function inventorySummarySuffix(filters) {
        const inventory = (filters && filters.vendor_product_filter) || {};
        if (inventory.enabled && Array.isArray(inventory.rows) && inventory.rows.length) {
            return t('{count} product(s)', {count: inventory.rows.length});
        }
        return '';
    }
    function renderRows() {
        rows.replaceChildren(); document.getElementById('empty').classList.toggle('d-none', subscriptions.length !== 0);
        subscriptions.forEach(function (item) {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td><strong></strong><div class="text-muted small recipients"></div><div class="text-muted small team"></div><div class="text-muted small delivery-mode"></div></td><td></td><td></td><td></td>';
            const emails = Array.isArray(item.emails) && item.emails.length ? item.emails : [item.email];
            tr.children[0].querySelector('strong').textContent = item.username || t('Unnamed user');
            tr.children[0].querySelector('.recipients').textContent = emails.filter(Boolean).join(', ');
            tr.children[0].querySelector('.team').textContent = item.team || '';
            tr.children[0].querySelector('.delivery-mode').textContent = t('Delivery: {mode}', {
                mode: item.delivery_mode === 'grouped' ? t('Grouped') : t('Individual'),
            });
            if (item.newsletter_profile.enabled) {
                const collectionCount = item.newsletter_profile.filters.collections.length;
                const newsletterSummary = [
                    collectionCount
                        ? t('Enabled · {count} collection(s)', {count: collectionCount})
                        : t('Enabled · all collection(s)')
                ];
                const inventorySuffix = inventorySummarySuffix(item.newsletter_profile.filters);
                if (inventorySuffix) {
                    newsletterSummary.push(inventorySuffix);
                }
                const newsletterFilters = item.newsletter_profile.filters || {};
                if (Array.isArray(newsletterFilters.status) && newsletterFilters.status.length) {
                    newsletterSummary.push(t('Severity: {values}', {
                        values: newsletterFilters.status.map(function (value) { return t(value); }).join(', '),
                    }));
                }
                if (newsletterFilters.include_unknown) {
                    newsletterSummary.push(t('Unknown severity included'));
                }
                tr.children[1].textContent = newsletterSummary.join(' · ');
            } else {
                tr.children[1].textContent = t('Disabled');
            }
            if (item.report_profile.enabled) {
                const reportSummary = [item.report_profile.schedule_enabled
                    ? t('Enabled · weekly {weekday} {time} HKT', {weekday: item.report_profile.schedule_weekday || '', time: item.report_profile.schedule_time || ''})
                    : t('Enabled')];
                const inventorySuffix = inventorySummarySuffix(item.report_profile.filters);
                if (inventorySuffix) {
                    reportSummary.push(inventorySuffix);
                } else if (Array.isArray(item.report_profile.filters.keywords) && item.report_profile.filters.keywords.length) {
                    reportSummary.push(t('legacy keyword filter'));
                }
                tr.children[2].textContent = reportSummary.join(' · ');
            } else {
                tr.children[2].textContent = t('Disabled');
            }
            const actions = document.createElement('div'); actions.className = 'd-flex flex-wrap gap-1';
            actions.innerHTML = '<button class="btn btn-outline-primary btn-sm edit" type="button">' + t('Edit') + '</button><button class="btn btn-outline-danger btn-sm remove" type="button">' + t('Delete') + '</button>';
            actions.querySelector('.edit').onclick = function () { openEditor(item); };
            actions.querySelector('.remove').onclick = function () { if (confirm(t('Delete subscription for {username}?', {username: item.username || item.email}))) requestJson(apiUrl(item.id), {method:'DELETE'}).then(load).catch(function(e){showMessage(e.message,'danger');}); };
            tr.children[3].append(actions); rows.append(tr);
        });
    }
    function load() { return requestJson(subscriptionsUrl).then(function(body){subscriptions=body.data;renderRows();}).catch(function(e){showMessage(e.message,'danger');}).finally(function(){document.getElementById('loading').classList.add('d-none');}); }
    newsletterCollections.wire();
    document.getElementById('report-time-window').addEventListener('change', function () { toggleCustomWindow('report'); });
    ['newsletter', 'report'].forEach(function (prefix) {
        document.getElementById(prefix + '-vendor-product-file').addEventListener('change', function (event) {
            importVendorProductCsv(prefix, event.target.files && event.target.files[0]);
        });
        document.getElementById(prefix + '-vendor-product-clear').addEventListener('click', function () {
            clearVendorProductInventory(prefix);
        });
        document.getElementById(prefix + '-include-possible-matches').addEventListener('change', function (event) {
            getVendorProductFilter(prefix).include_possible_matches = event.target.checked;
            if (prefix === 'report') {
                scheduleReportPreview();
            }
        });
    });
    document.getElementById('report-enabled').addEventListener('change', refreshReportPreview);
    document.getElementById('report-generation-mode').addEventListener('change', function () {
        updateReportSearchPromptVisibility();
        scheduleReportPreview();
    });
    document.getElementById('report-language').addEventListener('change', scheduleReportPreview);
    document.getElementById('report-schedule-enabled').addEventListener('change', scheduleReportPreview);
    document.getElementById('report-schedule-weekday').addEventListener('change', scheduleReportPreview);
    document.getElementById('report-schedule-time').addEventListener('change', scheduleReportPreview);
    document.getElementById('report-time-window').addEventListener('change', scheduleReportPreview);
    document.getElementById('report-start').addEventListener('input', scheduleReportPreview);
    document.getElementById('report-end').addEventListener('input', scheduleReportPreview);
    document.querySelectorAll('#report-fields .report-status-checkbox').forEach(function (input) {
        input.addEventListener('change', scheduleReportPreview);
    });
    document.getElementById('report-include-unknown').addEventListener('change', scheduleReportPreview);
    const addButton = document.getElementById('add-btn');
    if (addButton) addButton.onclick = function () { openEditor(null); };
    document.getElementById('newsletter-enabled').addEventListener('change', updateNewsletterSendStatisticVisibility);
    const addRecipientButton = document.getElementById('add-recipient-btn');
    if (addRecipientButton) addRecipientButton.onclick = function () {
        const list = document.getElementById('recipient-list');
        const values = recipientValues();
        values.push('');
        renderRecipientInputs(values);
        list.lastElementChild.querySelector('input').focus();
    };
    document.getElementById('newsletter-send-statistic').addEventListener('click', function () {
        if (!editingId || document.getElementById('newsletter-send-statistic').disabled) return;
        setSendStatisticBusy(true);
        setSendStatisticStatus(t('Sending statistics email...'), 'info');
        requestJson(apiUrl(editingId, '/send-statistic'), {method: 'POST'})
            .then(function (body) {
                const text = body.message || t('Newsletter statistics email sent.');
                setSendStatisticStatus(text, 'success');
                showMessage(text, 'success');
            })
            .catch(function (e) {
                setSendStatisticStatus(e.message, 'danger');
                showMessage(e.message, 'danger');
            })
            .finally(function () {
                setSendStatisticBusy(false);
            });
    });
    document.getElementById('subscription-form').onsubmit = function (event) {
        event.preventDefault();
        if (vendorProductImportBusy) {
            showModalMessage(t('Wait for CSV validation to finish before saving.'), 'warning');
            return;
        }
        showModalMessage('', '');
        const password = isAdmin && !accountHubEnabled ? document.getElementById('password').value : '';
        if (isAdmin && !accountHubEnabled && !editingId && !password) {
            showModalMessage(t('Password is required.'), 'danger');
            return;
        }
        const payload = { team:document.getElementById('team').value,
            delivery_mode: document.getElementById('delivery-mode').value,
            newsletter_profile:{
                enabled:document.getElementById('newsletter-enabled').checked,
                filters:readFilters('newsletter'),
                statistic_schedule_enabled:document.getElementById('newsletter-statistic-schedule-enabled').checked
            },
            report_profile: buildReportProfilePayload().report_profile };
        if (isAdmin) {
            payload.username = document.getElementById('username').value;
            payload.emails = recipientValues();
            if (!accountHubEnabled) payload.password = password;
        }
        requestJson(editingId ? apiUrl(editingId) : subscriptionsUrl, {method:editingId?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}).then(function(){modal.hide();showMessage(t('Subscription saved.'),'success');return load();}).catch(function(e){showModalMessage(e.message,'danger');});
    };
    requestJson(reviewsUrl).then(function(body){collections=body.data.map(function(item){return item.name;});return load();}).catch(function(e){showMessage(e.message,'danger');});
})();
