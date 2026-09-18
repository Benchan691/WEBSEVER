(function () {
    const pageConfig = JSON.parse(document.getElementById('page-config').textContent);
    const refreshMs = 20000;
    let templatesLoaded = false;
    let sourceListLoaded = false;
    const editorState = { data: null, currentSource: '', dirty: false, previewToken: 0, commonBound: false };

    function showMessage(text, type) {
        const box = document.getElementById('message');
        box.className = 'alert alert-' + type;
        box.textContent = text;
        box.classList.remove('d-none');
    }

    function clearMessage() {
        document.getElementById('message').classList.add('d-none');
    }

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function formatTime(value) {
        if (!value) return '—';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return escapeHtml(value);
        return escapeHtml(date.toLocaleString());
    }

    function requestJson(url, options) {
        const requestOptions = Object.assign({ headers: { Accept: 'application/json' } }, options || {});
        requestOptions.headers = Object.assign({ Accept: 'application/json' }, requestOptions.headers || {});
        return fetch(url, requestOptions).then(function (response) {
            return response.json().then(function (body) {
                if (!response.ok) {
                    throw new Error((body && body.error) || t('Request failed.'));
                }
                return body;
            });
        });
    }

    function renderScheduler(scheduler) {
        const banner = document.getElementById('scheduler-banner');
        const alive = Boolean(scheduler && scheduler.alive);
        banner.className = 'alert mb-4 ' + (alive ? 'alert-success' : 'alert-warning');
        const retention = (scheduler && scheduler.retention) || {};
        const retentionResult = retention.last_result
            ? JSON.stringify(retention.last_result)
            : '—';
        banner.innerHTML =
            '<div class="d-flex flex-wrap justify-content-between gap-2">' +
            '<div><strong>' + t('Scheduler:') + '</strong> ' + (alive ? t('Alive') : t('Stale / not running')) + '</div>' +
            '<div class="small">' + t('Last tick:') + ' ' + formatTime(scheduler && scheduler.last_tick_at) + '</div>' +
            '</div>' +
            '<div class="small mt-2">' +
            t('Host:') + ' ' + escapeHtml((scheduler && scheduler.hostname) || '—') +
            ' · ' + t('PID:') + ' ' + escapeHtml((scheduler && scheduler.pid) != null ? scheduler.pid : '—') +
            ' · ' + t('Retention last run:') + ' ' + formatTime(retention.last_run_at) +
            ' · ' + t('Retention result:') + ' ' + escapeHtml(retentionResult) +
            '</div>';
    }

    function renderReports(rows) {
        const body = document.getElementById('report-rows');
        const empty = document.getElementById('reports-empty');
        body.innerHTML = '';
        if (!rows.length) {
            empty.classList.remove('d-none');
            return;
        }
        empty.classList.add('d-none');
        rows.forEach(function (row) {
            const delivery = row.delivery || {};
            const recipients = Array.isArray(row.emails) && row.emails.length
                ? row.emails.join(', ')
                : row.email;
            const schedule = row.schedule_enabled
                ? escapeHtml(row.schedule_weekday) + ' ' + escapeHtml(row.schedule_time) + ' ' + t('HKT')
                : t('Off');
            const next = row.due
                ? '<span class="badge text-bg-warning">' + t('Due') + '</span> ' + formatTime(row.next_run_at)
                : formatTime(row.next_run_at);
            const deliveryText = delivery.delivery_status
                ? escapeHtml(delivery.delivery_status) + ' / ' + escapeHtml(delivery.status || '—')
                : '—';
            const tr = document.createElement('tr');
            tr.innerHTML =
                '<td><div class="fw-semibold">' + escapeHtml(row.username || row.email) + '</div>' +
                '<div class="small text-muted">' + escapeHtml(recipients || '') + '</div>' +
                '<div class="small text-muted">' + escapeHtml(row.team || '') + '</div>' +
                '<div class="small">' + escapeHtml(row.delivery_mode || 'individual') + '</div>' +
                '<div class="small">' + (row.enabled ? t('Enabled') : t('Disabled')) +
                ' · ' + escapeHtml(row.generation_mode || '') + '</div></td>' +
                '<td>' + schedule + '</td>' +
                '<td>' + next +
                (row.schedule_claim_owner
                    ? '<div class="small text-muted">' + t('Claim:') + ' ' + escapeHtml(row.schedule_claim_owner) + '</div>'
                    : '') +
                '</td>' +
                '<td>' + formatTime(row.last_run_at) +
                (row.last_job_id
                    ? '<div class="small text-muted">' + t('Job') + ' ' + escapeHtml(row.last_job_id) + '</div>'
                    : '') +
                (row.last_match_count != null
                    ? '<div class="small text-muted">' + t('Matches') + ' ' + escapeHtml(row.last_match_count) + '</div>'
                    : '') +
                '</td>' +
                '<td>' + deliveryText +
                (delivery.delivery_error
                    ? '<div class="small text-danger">' + escapeHtml(delivery.delivery_error) + '</div>'
                    : '') +
                '</td>' +
                '<td class="small text-danger">' + escapeHtml(row.last_error || '—') + '</td>';
            body.appendChild(tr);
        });
    }

    function renderNewsletters(rows) {
        const body = document.getElementById('newsletter-rows');
        const empty = document.getElementById('newsletters-empty');
        body.innerHTML = '';
        if (!rows.length) {
            empty.classList.remove('d-none');
            return;
        }
        empty.classList.add('d-none');
        rows.forEach(function (row) {
            const tr = document.createElement('tr');
            const recipients = Array.isArray(row.emails) && row.emails.length
                ? row.emails.join(', ')
                : row.email;
            tr.innerHTML =
                '<td><div class="fw-semibold">' + escapeHtml(row.username || row.email) + '</div>' +
                '<div class="small text-muted">' + escapeHtml(recipients || '') + '</div>' +
                '<div class="small text-muted">' + escapeHtml(row.team || '') + '</div>' +
                '<div class="small">' + escapeHtml(row.delivery_mode || 'individual') + '</div></td>' +
                '<td>' + (row.enabled ? t('Yes') : t('No')) + '</td>' +
                '<td class="small">' + escapeHtml(row.delivery_cursor || '—') + '</td>' +
                '<td class="small">' + escapeHtml(row.cve_delivery_cutoff || '—') + '</td>' +
                '<td>' + escapeHtml(row.total_delivered) + '</td>';
            body.appendChild(tr);
        });
    }

    function renderDeliveries(rows) {
        const body = document.getElementById('delivery-rows');
        const empty = document.getElementById('deliveries-empty');
        body.innerHTML = '';
        if (!rows.length) {
            empty.classList.remove('d-none');
            return;
        }
        empty.classList.add('d-none');
        rows.forEach(function (row) {
            const tr = document.createElement('tr');
            tr.innerHTML =
                '<td class="small">' + formatTime(row.sent_at) + '</td>' +
                '<td>' + escapeHtml(row.email) + '</td>' +
                '<td class="small">' + escapeHtml(row.source_collection) + '</td>' +
                '<td>' + escapeHtml(row.title || row.selection_id || '—') + '</td>';
            body.appendChild(tr);
        });
    }

    function renderSourceUrls(rows) {
        const body = document.getElementById('source-list-rows');
        const empty = document.getElementById('source-list-empty');
        body.replaceChildren();
        let rendered = 0;
        (rows || []).forEach(function (row) {
            const urls = Array.isArray(row.urls) ? row.urls : [];
            urls.forEach(function (url) {
                let parsed;
                try {
                    parsed = new URL(url);
                } catch (error) {
                    return;
                }
                if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) return;
                const tr = document.createElement('tr');
                const collection = document.createElement('td');
                collection.textContent = row.collection || '—';
                const linkCell = document.createElement('td');
                const link = document.createElement('a');
                link.href = parsed.href;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.textContent = url;
                linkCell.appendChild(link);
                tr.append(collection, linkCell);
                body.appendChild(tr);
                rendered += 1;
            });
        });
        empty.classList.toggle('d-none', rendered !== 0);
    }

    function currentRow() {
        return (editorState.data.sources || []).find(function (row) {
            return row.source_collection === editorState.currentSource;
        }) || null;
    }

    function setSaveState(text, className) {
        const state = document.getElementById('template-save-state');
        state.textContent = text || '';
        state.className = 'small ' + (className || 'text-muted');
    }

    function markEditorDirty() {
        editorState.dirty = true;
        setSaveState(t('Unsaved changes'), 'text-warning');
        updatePreview();
    }

    function renderSourceList() {
        const list = document.getElementById('template-source-list');
        list.replaceChildren();
        (editorState.data.sources || []).forEach(function (row) {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'template-source-item' + (row.source_collection === editorState.currentSource ? ' is-active' : '');
            button.innerHTML =
                '<span class="template-source-dot"><i class="bi bi-collection"></i></span>' +
                '<span class="flex-grow-1 text-start"><span class="d-block fw-semibold">' + escapeHtml(row.source_collection) + '</span>' +
                '<span class="small text-muted">' + (row.selection_id ? t('{count} fields selected', {count: row.fields.length}) : t('No recent record')) + '</span></span>' +
                '<i class="bi bi-chevron-right small text-muted"></i>';
            button.addEventListener('click', function () {
                editorState.currentSource = row.source_collection;
                renderSourceList();
                renderFieldEditor();
                updatePreview();
            });
            list.appendChild(button);
        });
    }

    function renderFieldEditor() {
        const row = currentRow();
        const available = document.getElementById('template-available-fields');
        const selected = document.getElementById('template-selected-fields');
        available.replaceChildren();
        selected.replaceChildren();
        if (!row) return;
        document.getElementById('template-source-title').textContent = row.source_collection;
        document.getElementById('template-source-meta').textContent = row.source_timestamp
            ? t('Previewing newest record from {time}', {time: formatTime(row.source_timestamp)})
            : t('There is no recent record for this source yet.');
        document.getElementById('template-field-count').textContent = t('{count} selected', {count: row.fields.length});
        const catalog = row.field_catalog || editorState.data.field_catalog || [];
        catalog.filter(function (field) { return row.fields.indexOf(field.id) === -1; }).forEach(function (field) {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'template-field-option';
            button.innerHTML = '<span><span class="d-block fw-semibold">' + escapeHtml(field.label) + '</span>' +
                '<span class="small text-muted">' + escapeHtml(field.description) + '</span></span>' +
                '<i class="bi bi-plus-circle text-primary"></i>';
            button.addEventListener('click', function () {
                row.fields.push(field.id);
                renderFieldEditor();
                renderSourceList();
                markEditorDirty();
            });
            available.appendChild(button);
        });
        if (!available.children.length) {
            available.innerHTML = '<div class="template-list-empty"><i class="bi bi-check2-circle"></i><span>' + t('All available fields are in the email.') + '</span></div>';
        }
        row.fields.forEach(function (fieldId, index) {
            const field = catalog.find(function (item) { return item.id === fieldId; }) || {id: fieldId, label: fieldId, description: ''};
            const item = document.createElement('div');
            item.className = 'template-selected-item';
            item.innerHTML = '<span class="template-drag-handle"><i class="bi bi-grip-vertical"></i></span>' +
                '<span class="flex-grow-1"><span class="d-block fw-semibold">' + escapeHtml(field.label) + '</span>' +
                '<span class="small text-muted">' + escapeHtml(field.description) + '</span></span>' +
                '<span class="template-order-actions">' +
                '<button type="button" class="btn btn-sm btn-light" data-move="up" title="' + t('Move up') + '" ' + (index === 0 ? 'disabled' : '') + '><i class="bi bi-arrow-up"></i></button>' +
                '<button type="button" class="btn btn-sm btn-light" data-move="down" title="' + t('Move down') + '" ' + (index === row.fields.length - 1 ? 'disabled' : '') + '><i class="bi bi-arrow-down"></i></button>' +
                '<button type="button" class="btn btn-sm btn-light text-danger" data-move="remove" title="' + t('Remove') + '"><i class="bi bi-x-lg"></i></button>' +
                '</span>';
            item.querySelectorAll('[data-move]').forEach(function (button) {
                button.addEventListener('click', function () {
                    const action = button.dataset.move;
                    if (action === 'remove') row.fields.splice(index, 1);
                    if (action === 'up' && index > 0) [row.fields[index - 1], row.fields[index]] = [row.fields[index], row.fields[index - 1]];
                    if (action === 'down' && index < row.fields.length - 1) [row.fields[index + 1], row.fields[index]] = [row.fields[index], row.fields[index + 1]];
                    renderFieldEditor();
                    renderSourceList();
                    markEditorDirty();
                });
            });
            selected.appendChild(item);
        });
        if (!selected.children.length) {
            selected.innerHTML = '<div class="template-list-empty"><i class="bi bi-layout-text-sidebar-reverse"></i><span>' + t('Add fields from the left to build the email.') + '</span></div>';
        }
    }

    function syncCommonSettings() {
        editorState.data.common.subject = document.getElementById('template-subject').value.trim();
        editorState.data.common.extra = document.getElementById('template-extra').value;
        editorState.data.common.footer = document.getElementById('template-footer').value;
    }

    function editorConfig() {
        syncCommonSettings();
        return {
            common: editorState.data.common,
            sources: (editorState.data.sources || []).reduce(function (result, row) {
                result[row.source_collection] = {fields: row.fields};
                return result;
            }, {}),
        };
    }

    function updatePreview() {
        const row = currentRow();
        const frame = document.getElementById('template-editor-preview');
        const empty = document.getElementById('template-preview-empty');
        const subject = document.getElementById('template-preview-subject');
        if (!row || !row.selection_id) {
            frame.classList.add('d-none');
            empty.classList.remove('d-none');
            subject.textContent = '';
            return;
        }
        frame.classList.remove('d-none');
        empty.classList.add('d-none');
        const token = ++editorState.previewToken;
        requestJson(pageConfig.editorPreviewUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                source_collection: row.source_collection,
                selection_id: row.selection_id,
                config: editorConfig(),
            }),
        }).then(function (body) {
            if (token !== editorState.previewToken) return;
            frame.srcdoc = body.html || '';
            subject.textContent = body.subject ? t('Subject: {subject}', {subject: body.subject}) : '';
        }).catch(function (error) {
            if (token === editorState.previewToken) showMessage(error.message || t('Unable to render generated newsletter.'), 'danger');
        });
    }

    function renderEditor(data) {
        editorState.data = data || {common: {}, sources: [], field_catalog: []};
        editorState.data.common = editorState.data.common || {};
        document.getElementById('template-subject').value = editorState.data.common.subject || '';
        document.getElementById('template-extra').value = editorState.data.common.extra || '';
        document.getElementById('template-footer').value = editorState.data.common.footer || '';
        editorState.currentSource = (editorState.data.sources[0] || {}).source_collection || '';
        document.getElementById('template-editor').classList.remove('d-none');
        renderSourceList();
        renderFieldEditor();
        updatePreview();
        setSaveState(t('All changes saved'), 'text-success');
        if (!editorState.commonBound) {
            ['template-subject', 'template-extra', 'template-footer'].forEach(function (id) {
                document.getElementById(id).addEventListener('input', markEditorDirty);
            });
            editorState.commonBound = true;
        }
    }

    function saveEditor() {
        const button = document.getElementById('save-template-btn');
        button.disabled = true;
        setSaveState(t('Saving...'), 'text-muted');
        requestJson(pageConfig.editorUrl, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(editorConfig()),
        }).then(function (body) {
            editorState.data.common = body.data.common;
            editorState.dirty = false;
            setSaveState(t('All changes saved'), 'text-success');
            showMessage(t('Email template saved.'), 'success');
        }).catch(function (error) {
            editorState.dirty = true;
            setSaveState(t('Could not save'), 'text-danger');
            showMessage(error.message || t('Unable to save email templates.'), 'danger');
        }).finally(function () {
            button.disabled = false;
        });
    }

    function renderTemplates(data) {
        const empty = document.getElementById('templates-empty');
        empty.classList.toggle('d-none', (data.sources || []).length !== 0);
        if (data.sources && data.sources.length) renderEditor(data);
    }

    function loadHealth() {
        return requestJson(pageConfig.healthUrl)
            .then(function (body) {
                clearMessage();
                renderScheduler(body.scheduler || {});
                renderReports(body.reports || []);
                renderNewsletters(body.newsletters || []);
                renderDeliveries(body.recent_newsletter_deliveries || []);
            })
            .catch(function (error) {
                showMessage(error.message || t('Unable to load scheduler health.'), 'danger');
            });
    }

    function loadTemplates() {
        const loading = document.getElementById('templates-loading');
        loading.classList.remove('d-none');
        return requestJson(pageConfig.editorUrl)
            .then(function (body) {
                clearMessage();
                renderTemplates(body.data || []);
                templatesLoaded = true;
            })
            .catch(function (error) {
                showMessage(error.message || t('Unable to load email templates.'), 'danger');
            })
            .finally(function () {
                loading.classList.add('d-none');
        });
    }

    function loadSourceList() {
        const loading = document.getElementById('source-list-loading');
        loading.classList.remove('d-none');
        return requestJson(pageConfig.sourceListUrl)
            .then(function (body) {
                clearMessage();
                renderSourceUrls(body.data || []);
                sourceListLoaded = true;
            })
            .catch(function (error) {
                showMessage(error.message || t('Unable to load source URLs.'), 'danger');
            })
            .finally(function () {
                loading.classList.add('d-none');
            });
    }

    document.getElementById('templates-tab').addEventListener('shown.bs.tab', function () {
        if (!templatesLoaded) loadTemplates();
    });
    document.getElementById('source-list-tab').addEventListener('shown.bs.tab', function () {
        if (!sourceListLoaded) loadSourceList();
    });
    document.getElementById('refresh-btn').addEventListener('click', function () {
        if (document.getElementById('templates-tab').classList.contains('active')) {
            loadTemplates();
        } else if (document.getElementById('source-list-tab').classList.contains('active')) {
            loadSourceList();
        } else {
            loadHealth();
        }
    });
    document.getElementById('save-template-btn').addEventListener('click', saveEditor);
    loadHealth();
    setInterval(loadHealth, refreshMs);
})();
