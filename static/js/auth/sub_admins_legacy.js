(function () {
    const config = JSON.parse(document.getElementById('sub-admin-page-config').textContent);
    const modal = new bootstrap.Modal(document.getElementById('sub-admin-modal'));
    const form = document.getElementById('sub-admin-form');
    const rows = document.getElementById('sub-admin-rows');
    const message = document.getElementById('message');
    const modalMessage = document.getElementById('modal-message');
    let subAdmins = [];
    let editingId = null;

    function requestJson(url, options) {
        return fetch(url, options || {headers: {'Accept': 'application/json'}}).then(function (response) {
            return response.json().then(function (body) {
                if (!response.ok) throw new Error(body.error || t('Request failed.'));
                return body;
            });
        });
    }
    function setMessage(target, text, kind) {
        target.textContent = text || '';
        target.className = text ? 'alert alert-' + kind : 'alert d-none';
    }
    function button(label, className) {
        const item = document.createElement('button');
        item.type = 'button'; item.className = className; item.textContent = label;
        return item;
    }
    function renderRows() {
        rows.replaceChildren();
        document.getElementById('empty').classList.toggle('d-none', subAdmins.length !== 0);
        subAdmins.forEach(function (item) {
            const row = document.createElement('tr');
            const username = document.createElement('td'); username.textContent = item.username || '';
            const email = document.createElement('td'); email.textContent = item.email || t('Not provided');
            const status = document.createElement('td'); status.textContent = item.disabled ? t('Disabled') : t('Enabled');
            status.className = item.disabled ? 'text-danger' : 'text-success';
            const delivery = document.createElement('td'); delivery.textContent = item.disabled && item.pause_managed_subscriptions_when_disabled
                ? t('Paused while disabled') : t('Continues while disabled');
            const actions = document.createElement('td'); actions.className = 'd-flex flex-wrap gap-1';
            const edit = button(t('Edit'), 'btn btn-outline-primary btn-sm'); edit.onclick = function () { openEditor(item); };
            const toggle = button(item.disabled ? t('Enable') : t('Disable'), 'btn btn-outline-secondary btn-sm');
            toggle.onclick = function () { requestJson(config.subAdminsUrl + '/' + encodeURIComponent(item.id), {
                method: 'PUT', headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
                body: JSON.stringify({disabled: !item.disabled})
            }).then(load).catch(function (error) { setMessage(message, error.message, 'danger'); }); };
            const remove = button(t('Delete'), 'btn btn-outline-danger btn-sm');
            remove.onclick = function () {
                if (!confirm(t('Delete sub-admin {username}?', {username: item.username}))) return;
                requestJson(config.subAdminsUrl + '/' + encodeURIComponent(item.id), {method: 'DELETE', headers: {'Accept': 'application/json'}})
                    .then(load).catch(function (error) { setMessage(message, error.message, 'danger'); });
            };
            actions.append(edit, toggle, remove); row.append(username, email, status, delivery, actions); rows.append(row);
        });
    }
    function openEditor(item) {
        editingId = item ? item.id : null;
        document.getElementById('modal-title').textContent = item ? t('Edit sub-admin') : t('Add sub-admin');
        document.getElementById('sub-admin-username').value = item ? item.username : '';
        document.getElementById('sub-admin-username').readOnly = Boolean(item);
        document.getElementById('sub-admin-email').value = item ? (item.email || '') : '';
        document.getElementById('sub-admin-password').value = '';
        document.getElementById('sub-admin-password').required = !item;
        document.getElementById('sub-admin-disabled').checked = Boolean(item && item.disabled);
        document.getElementById('sub-admin-pause').checked = Boolean(item && item.pause_managed_subscriptions_when_disabled);
        setMessage(modalMessage, '', ''); modal.show();
    }
    function load() {
        return requestJson(config.subAdminsUrl).then(function (body) { subAdmins = body.data || []; renderRows(); })
            .catch(function (error) { setMessage(message, error.message, 'danger'); })
            .finally(function () { document.getElementById('loading').classList.add('d-none'); });
    }
    document.getElementById('add-sub-admin').onclick = function () { openEditor(null); };
    form.onsubmit = function (event) {
        event.preventDefault();
        const payload = {
            email: document.getElementById('sub-admin-email').value.trim(),
            disabled: document.getElementById('sub-admin-disabled').checked,
            pause_managed_subscriptions_when_disabled: document.getElementById('sub-admin-pause').checked,
        };
        const password = document.getElementById('sub-admin-password').value;
        if (!editingId) { payload.username = document.getElementById('sub-admin-username').value.trim(); payload.password = password; }
        else if (password) payload.password = password;
        setMessage(modalMessage, '', '');
        requestJson(editingId ? config.subAdminsUrl + '/' + encodeURIComponent(editingId) : config.subAdminsUrl, {
            method: editingId ? 'PUT' : 'POST', headers: {'Content-Type': 'application/json', 'Accept': 'application/json'}, body: JSON.stringify(payload)
        }).then(function () { modal.hide(); setMessage(message, t('Sub-admin saved.'), 'success'); return load(); })
          .catch(function (error) { setMessage(modalMessage, error.message, 'danger'); });
    };
    load();
}());
