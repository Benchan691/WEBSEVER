(function () {
    const {
        jobsUrl,
        purgeEvidenceCacheUrl,
        purgeSearchCacheUrl,
        cancelUrlTemplate,
        deleteUrlTemplate,
        logsUrlTemplate,
        translationsUrlTemplate,
    } = JSON.parse(document.getElementById('page-config').textContent);
    const selectionStorageKey = 'vulnerabilityReviewSelections';
    const reportModeStorageKey = 'vulnerabilityReportGenerationMode';
    const rows = document.getElementById('job-rows');
    const empty = document.getElementById('empty');
    const message = document.getElementById('message');
    const previewModal = new bootstrap.Modal(document.getElementById('preview-modal'));
    const logModal = new bootstrap.Modal(document.getElementById('log-modal'));
    const translateModal = new bootstrap.Modal(document.getElementById('translate-modal'));
    const translateLanguage = document.getElementById('translate-language');
    const translateStatus = document.getElementById('translate-status');
    const translateConfirmButton = document.getElementById('translate-confirm-btn');
    const generationMode = document.getElementById('generation-mode');
    const purgeEvidenceCacheButton = document.getElementById('purge-evidence-cache-btn');
    const purgeSearchCacheButton = document.getElementById('purge-search-cache-btn');
    const enrichedCacheHelp = document.getElementById('enriched-cache-help');
    let pollTimer = null;
    let selectedTranslateJob = null;

    function selections() {
        try { const value = JSON.parse(localStorage.getItem(selectionStorageKey) || '[]'); return Array.isArray(value) ? value : []; }
        catch (error) { return []; }
    }
    function updateSelectionCount() {
        const count = selections().length;
        document.getElementById('selection-count').textContent = count === 1
            ? t('{count} review selection available', {count: count})
            : t('{count} review selections available', {count: count});
    }
    function showMessage(text, kind) {
        message.textContent = text;
        message.className = 'alert alert-' + kind;
    }
    function updateLanguageField() {
        const isEnriched = generationMode.value === 'enriched_weekly';
        purgeEvidenceCacheButton.classList.toggle('d-none', !isEnriched);
        purgeSearchCacheButton.classList.toggle('d-none', !isEnriched);
        enrichedCacheHelp.classList.toggle('d-none', !isEnriched);
        const searchPromptWrap = document.getElementById('search-prompt-wrap');
        if (searchPromptWrap) {
            searchPromptWrap.classList.toggle('d-none', !isEnriched);
        }
    }
    function purgeSearchCache() {
        if (!confirm(t('Purge all cached enriched search results? The next enriched weekly run will call Tavily again.'))) {
            return;
        }
        purgeSearchCacheButton.disabled = true;
        requestJson(purgeSearchCacheUrl, { method: 'POST' })
            .then(function (body) {
                showMessage(t('Purged {count} cached search record(s).', {count: body.deleted_count || 0}), 'success');
            })
            .catch(function (reason) {
                showMessage(reason.message, 'danger');
            })
            .finally(function () {
                purgeSearchCacheButton.disabled = false;
            });
    }
    function purgeEvidenceCache() {
        if (!confirm(t('Purge all cached enriched evidence extractions? The next enriched weekly run will re-call the LLM for evidence.'))) {
            return;
        }
        purgeEvidenceCacheButton.disabled = true;
        requestJson(purgeEvidenceCacheUrl, { method: 'POST' })
            .then(function (body) {
                showMessage(t('Purged {count} cached evidence record(s).', {count: body.deleted_count || 0}), 'success');
            })
            .catch(function (reason) {
                showMessage(reason.message, 'danger');
            })
            .finally(function () {
                purgeEvidenceCacheButton.disabled = false;
            });
    }
    function languageName(code) {
        return { en: t('English'), zh: t('Traditional Chinese'), ch: t('Simplified Chinese') }[code] || code;
    }
    function requestJson(url, options) {
        return fetch(url, options).then(function (response) {
            return response.json().then(function (body) {
                if (!response.ok) throw new Error(body.error || t('Request failed.'));
                return body;
            });
        });
    }
    function parseJobDate(value) {
        if (!value) return null;
        if (value.$date) return new Date(value.$date);
        return new Date(value);
    }
    function jobProgressPercent(job) {
        if (typeof job.progress_percent === 'number') return Math.max(0, Math.min(100, job.progress_percent));
        if (!job.source_count) return 0;
        return Math.round(((job.processed_count || 0) / job.source_count) * 100);
    }
    function formatDuration(seconds) {
        if (seconds === null || seconds === undefined || seconds < 0) return null;
        if (seconds < 60) return t('<1 min');
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        if (hours > 0) return t('{hours}h {minutes}m', {hours: hours, minutes: minutes});
        return t('{minutes} min', {minutes: minutes});
    }
    function jobEtaText(job) {
        if (job.status === 'queued') return t('Estimating…');
        if (job.status !== 'running') return null;
        const percent = jobProgressPercent(job);
        if (percent >= 100) return null;
        if (!percent) return t('Estimating…');
        const duration = formatDuration(job.estimated_seconds_remaining);
        if (!duration) return t('Estimating…');
        return t('~{duration} left', {duration: duration});
    }
    function jobFinishTimeText(job) {
        if (job.status !== 'running' || !job.estimated_seconds_remaining) return null;
        const finish = new Date(Date.now() + (job.estimated_seconds_remaining * 1000));
        return t('Est. finish {time}', {time: finish.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })});
    }
    function truncateText(text, maxLength) {
        if (!text) return '';
        return text.length > maxLength ? text.slice(0, maxLength - 1) + '\u2026' : text;
    }
    function openJobLog(job) {
        const target = document.getElementById('log-content');
        target.textContent = t('Loading log…');
        logModal.show();
        requestJson(logsUrlTemplate.replace('__JOB_ID__', job.id))
            .then(function (body) {
                const lines = body.logs || [];
                target.textContent = lines.length ? lines.join('\n') : t('No log entries yet.');
            })
            .catch(function (reason) {
                target.textContent = reason.message;
            });
    }
    function appendViewLogButton(container, job) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-outline-secondary btn-sm view-log-btn ms-1';
        button.textContent = t('View log');
        button.addEventListener('click', function () { openJobLog(job); });
        container.append(button);
    }
    function buildStatusCell(job) {
        const cell = document.createElement('td');
        const primary = document.createElement('div');
        const statusLabel = t(job.status.charAt(0).toUpperCase() + job.status.slice(1));
        const percent = jobProgressPercent(job);
        const eta = jobEtaText(job);
        let primaryText = statusLabel;
        if (job.status === 'queued' || job.status === 'running') {
            primaryText = statusLabel + ' ' + percent + '%';
            if (eta) primaryText += ' \u00b7 ' + eta;
        }
        primary.textContent = primaryText;
        cell.append(primary);
        if (job.progress_label && (job.status === 'queued' || job.status === 'running')) {
            const label = document.createElement('div');
            label.className = 'text-muted small';
            label.textContent = job.progress_label;
            cell.append(label);
        }
        const finish = jobFinishTimeText(job);
        if (finish) {
            const finishLine = document.createElement('div');
            finishLine.className = 'text-muted small';
            finishLine.textContent = finish;
            cell.append(finishLine);
        }
        if (job.status_message) {
            const logLine = document.createElement('div');
            logLine.className = 'text-muted small text-truncate';
            logLine.style.maxWidth = '280px';
            logLine.title = job.status_message;
            logLine.textContent = truncateText(job.status_message, 80);
            cell.append(logLine);
        }
        if (job.status === 'failed' && job.error) {
            const error = document.createElement('div');
            error.className = 'text-danger small';
            error.style.whiteSpace = 'pre-wrap';
            error.title = job.error;
            error.textContent = job.error;
            cell.append(error);
        }
        if (job.status === 'queued' || job.status === 'running' || job.status === 'failed' || job.status === 'skipped') {
            const logButton = document.createElement('button');
            logButton.type = 'button';
            logButton.className = 'btn btn-link btn-sm p-0 mt-1';
            logButton.textContent = t('View log');
            logButton.addEventListener('click', function () { openJobLog(job); });
            cell.append(logButton);
        }
        return cell;
    }
    function appendDeleteButton(container, job) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-outline-danger btn-sm delete-btn ms-1';
        button.textContent = t('Delete');
        button.addEventListener('click', function () {
            if (!confirm(t('Delete this report job?'))) return;
            button.disabled = true;
            requestJson(deleteUrlTemplate.replace('__JOB_ID__', job.id), { method: 'DELETE' })
                .then(function () {
                    showMessage(t('Report job deleted.'), 'success');
                    loadJobs();
                })
                .catch(function (reason) {
                    showMessage(reason.message, 'danger');
                    button.disabled = false;
                });
        });
        container.append(button);
    }
    function isEnglishReportJob(job) {
        const language = job.effective_report_language || job.report_language || 'en';
        return language === 'en' && job.input_source !== 'translation';
    }
    function updateTranslateModalState() {
        if (!selectedTranslateJob) return;
        translateConfirmButton.disabled = false;
        translateStatus.textContent = t('A new report history row will be created for the translation.');
    }
    function openTranslateDialog(job) {
        selectedTranslateJob = job;
        translateLanguage.value = 'zh';
        updateTranslateModalState();
        translateModal.show();
    }
    function startTranslation(job, language) {
        translateConfirmButton.disabled = true;
        requestJson(translationsUrlTemplate.replace('__JOB_ID__', job.id), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ language: language })
        })
            .then(function (body) {
                const messageText = body.status === 'running'
                    ? t('Translation already in progress.')
                    : t('Translation job started for {language}.', {language: languageName(language)});
                translateModal.hide();
                showMessage(messageText, 'success');
                loadJobs();
            })
            .catch(function (reason) {
                showMessage(reason.message, 'danger');
                translateConfirmButton.disabled = false;
            });
    }
    function appendTranslateButton(container, job) {
        if (!isEnglishReportJob(job)) return;
        const translateButton = document.createElement('button');
        translateButton.type = 'button';
        translateButton.className = 'btn btn-outline-secondary btn-sm ms-1';
        translateButton.textContent = t('Translate');
        translateButton.addEventListener('click', function () { openTranslateDialog(job); });
        container.append(translateButton);
    }
    function renderJobs(jobs) {
        rows.replaceChildren();
        empty.classList.toggle('d-none', jobs.length !== 0);
        let active = false;
        jobs.forEach(function (job) {
            active = active || job.status === 'queued' || job.status === 'running';
            const row = document.createElement('tr');
            const created = job.created_at && job.created_at.$date ? job.created_at.$date : job.created_at;
            const legacyModes = { ai: 'enriched_weekly', company_ai: 'enriched_weekly' };
            const requested = legacyModes[job.generation_mode] || job.generation_mode || 'enriched_weekly';
            const effective = legacyModes[job.effective_generation_mode] || job.effective_generation_mode || requested;
            let generator = requested === 'template' ? t('Fixed Template') : t('Enriched Weekly');
            if (requested === 'enriched_weekly' && effective === 'template') generator = t('Enriched Weekly → Fixed Template');
            if (job.input_source === 'translation' || job.job_type === 'translation') {
                generator += ' ' + t('(Translation)');
            }
            const requestedLanguage = job.report_language || 'en';
            const effectiveLanguage = job.effective_report_language || requestedLanguage;
            let language = languageName(requestedLanguage);
            if (requestedLanguage !== effectiveLanguage) language += ' \u2192 ' + languageName(effectiveLanguage);
            [new Date(created).toLocaleString(), language, job.source_count].forEach(function (value) {
                const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
            });
            const generatorCell = document.createElement('td');
            generatorCell.textContent = generator;
            if (job.fallback_reason) {
                const reason = document.createElement('div');
                reason.className = 'text-warning-emphasis small';
                reason.textContent = t('Fallback: {reason}', {reason: job.fallback_reason});
                generatorCell.append(reason);
            }
            if (job.translated_from_job_id) {
                const source = document.createElement('div');
                source.className = 'text-muted small';
                source.textContent = t('From report {id}', {id: job.translated_from_job_id.slice(-6)});
                generatorCell.append(source);
            }
            row.append(generatorCell);
            row.append(buildStatusCell(job));
            const action = document.createElement('td');
            if (job.status === 'completed') {
                action.innerHTML = '<button class="btn btn-outline-primary btn-sm me-1 preview-btn">' + t('Preview') + '</button>' +
                    '<a class="btn btn-outline-success btn-sm" href="/reports/' + job.id + '/download">' + t('Download') + '</a>';
                action.querySelector('.preview-btn').addEventListener('click', function () {
                    document.getElementById('preview-frame').src = '/reports/' + job.id + '/preview';
                    previewModal.show();
                });
                appendTranslateButton(action, job);
                appendDeleteButton(action, job);
            } else if (job.status === 'failed') {
                const error = document.createElement('span');
                error.className = 'text-danger small me-1';
                error.style.whiteSpace = 'pre-wrap';
                error.title = job.error || t('Generation failed.');
                error.textContent = job.error || t('Generation failed.');
                action.append(error);
                appendViewLogButton(action, job);
                appendDeleteButton(action, job);
            } else if (job.status === 'cancelled') {
                if ((job.processed_count || 0) > 0) {
                    action.innerHTML = '<button class="btn btn-outline-primary btn-sm preview-btn">' + t('Preview Partial') + '</button>';
                    action.querySelector('.preview-btn').addEventListener('click', function () {
                        document.getElementById('preview-frame').src = '/reports/' + job.id + '/preview';
                        previewModal.show();
                    });
                    appendDeleteButton(action, job);
                } else {
                    const cancelled = document.createElement('span');
                    cancelled.className = 'text-muted small me-1';
                    cancelled.textContent = t('Cancelled.');
                    action.append(cancelled);
                    appendDeleteButton(action, job);
                }
            } else if (job.status === 'skipped') {
                const skipped = document.createElement('span');
                skipped.className = 'text-muted small me-1';
                skipped.textContent = t('No matching CVEs; no report was generated.');
                action.append(skipped);
                appendViewLogButton(action, job);
                appendDeleteButton(action, job);
            } else {
                action.innerHTML = '<button class="btn btn-outline-danger btn-sm cancel-btn me-1">' + t('Cancel') + '</button>';
                if ((job.processed_count || 0) > 0) {
                    action.innerHTML += '<button class="btn btn-outline-primary btn-sm preview-btn">' + t('Preview Progress') + '</button>';
                    action.querySelector('.preview-btn').addEventListener('click', function () {
                        document.getElementById('preview-frame').src = '/reports/' + job.id + '/preview';
                        previewModal.show();
                    });
                } else {
                    const waiting = document.createElement('span');
                    waiting.className = 'text-muted small';
                    waiting.textContent = t('Waiting for worker...');
                    action.append(waiting);
                }
                action.querySelector('.cancel-btn').addEventListener('click', function () {
                    const button = action.querySelector('.cancel-btn');
                    button.disabled = true;
                    requestJson(cancelUrlTemplate.replace('__JOB_ID__', job.id), { method: 'POST' })
                        .then(function () { showMessage(t('Report generation cancelled.'), 'success'); loadJobs(); })
                        .catch(function (reason) {
                            showMessage(reason.message, 'danger');
                            button.disabled = false;
                        });
                });
            }
            row.append(action); rows.append(row);
        });
        if (active && !pollTimer) pollTimer = setTimeout(function () { pollTimer = null; loadJobs(); }, 2000);
    }
    function loadJobs() {
        requestJson(jobsUrl).then(function (body) { renderJobs(body.data); })
            .catch(function (reason) { showMessage(reason.message, 'danger'); });
    }
    function applyStoredReportPreferences() {
        const storedMode = localStorage.getItem(reportModeStorageKey);
        if (storedMode && Array.from(generationMode.options).some(function (option) { return option.value === storedMode; })) {
            generationMode.value = storedMode;
        }
    }
    document.getElementById('generate-form').addEventListener('submit', function (event) {
        event.preventDefault();
        const file = document.getElementById('json-file').files[0];
        const button = document.getElementById('generate-btn');
        const mode = document.getElementById('generation-mode').value;
        const selected = selections();
        if (mode === 'enriched_weekly') {
            if (file) {
                showMessage(t('Enriched Weekly reports require cve_review selections, not uploaded JSON.'), 'danger');
                return;
            }
            if (!selected.length || selected.some(function (item) { return item.collection !== 'cve_review'; })) {
                showMessage(t('Enriched Weekly reports only support cve_review selections.'), 'danger');
                return;
            }
        }
        button.disabled = true;
        const searchPrompt = (document.getElementById('search-prompt') || {}).value || '';
        let options;
        if (file) {
            const form = new FormData();
            form.append('generation_mode', mode);
            form.append('json_file', file);
            if (mode === 'enriched_weekly' && searchPrompt.trim()) {
                form.append('search_prompt', searchPrompt.trim());
            }
            options = { method: 'POST', body: form };
        } else {
            const payload = {
                generation_mode: mode,
                selections: selected
            };
            if (mode === 'enriched_weekly' && searchPrompt.trim()) {
                payload.search_prompt = searchPrompt.trim();
            }
            options = {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            };
        }
        requestJson(jobsUrl, options)
            .then(function (body) {
                const text = body.status === 'running'
                    ? t('Fixed Template report generation started.')
                    : t('Company AI report job queued.');
                showMessage(text, 'success');
                loadJobs();
            })
            .catch(function (reason) { showMessage(reason.message, 'danger'); })
            .finally(function () { button.disabled = false; });
    });
    applyStoredReportPreferences();
    generationMode.addEventListener('change', updateLanguageField);
    purgeSearchCacheButton.addEventListener('click', purgeSearchCache);
    purgeEvidenceCacheButton.addEventListener('click', purgeEvidenceCache);
    translateLanguage.addEventListener('change', updateTranslateModalState);
    translateConfirmButton.addEventListener('click', function () {
        if (!selectedTranslateJob) return;
        startTranslation(selectedTranslateJob, translateLanguage.value);
    });
    updateLanguageField();
    updateSelectionCount();
    loadJobs();
})();
