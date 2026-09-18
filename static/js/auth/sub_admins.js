(function () {
    const config = JSON.parse(document.getElementById('sub-admin-page-config').textContent);
    const modal = new bootstrap.Modal(document.getElementById('sub-admin-modal'));
    const form = document.getElementById('account-user-form');
    const rows = document.getElementById('sub-admin-rows');
    const message = document.getElementById('message');
    const modalMessage = document.getElementById('modal-message');
    let users = [];
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
        item.type = 'button';
        item.className = className;
        item.textContent = label;
        return item;
    }

    function renderRows() {
        rows.replaceChildren();
        document.getElementById('empty').classList.toggle('d-none', users.length !== 0);
        users.forEach(function (item) {
            const row = document.createElement('tr');
            const username = document.createElement('td');
            username.textContent = item.username || '';
            const role = document.createElement('td');
            const roleLabels = {admin: t('Administrator'), sub_admin: t('Sub-admin'), user: t('User')};
            role.textContent = roleLabels[item.role] || t('User');
            const email = document.createElement('td');
            email.textContent = item.email || t('Not provided');
            const status = document.createElement('td');
            status.textContent = item.disabled ? t('Disabled') : t('Enabled');
            status.className = item.disabled ? 'text-danger' : 'text-success';
            const delivery = document.createElement('td');
            delivery.textContent = item.disabled && item.pause_managed_subscriptions_when_disabled
                ? t('Paused while disabled')
                : t('Continues while disabled');
            const actions = document.createElement('td');
            actions.className = 'd-flex flex-wrap gap-1';
            const edit = button(t('Edit'), 'btn btn-outline-primary btn-sm');
            edit.onclick = function () { openEditor(item); };
            const toggle = button(item.disabled ? t('Enable') : t('Disable'), 'btn btn-outline-secondary btn-sm');
            toggle.onclick = function () {
                requestJson(config.accountUsersUrl + '/' + encodeURIComponent(item.id), {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
                    body: JSON.stringify({disabled: !item.disabled})
                }).then(load).catch(function (error) { setMessage(message, error.message, 'danger'); });
            };
            actions.append(edit, toggle);
            row.append(username, role, email, status, delivery, actions);
            rows.append(row);
        });
    }

    function openEditor(item) {
        editingId = item ? item.id : null;
        document.getElementById('modal-title').textContent = item ? t('Edit Account Hub user') : t('Add Account Hub user');
        const username = document.getElementById('account-user-username');
        username.value = item ? item.username : '';
        username.readOnly = Boolean(item);
        document.getElementById('account-user-email').value = item ? (item.email || '') : '';
        document.getElementById('account-user-role-group').classList.toggle('d-none', !item);
        document.getElementById('account-user-role').value = item ? item.role : 'user';
        document.getElementById('account-user-disabled').checked = Boolean(item && item.disabled);
        document.getElementById('account-user-pause').checked = Boolean(item && item.pause_managed_subscriptions_when_disabled);
        setMessage(modalMessage, '', '');
        modal.show();
    }

    function load() {
        return requestJson(config.accountUsersUrl).then(function (body) {
            users = body.data || [];
            renderRows();
        }).catch(function (error) {
            setMessage(message, error.message, 'danger');
        }).finally(function () {
            document.getElementById('loading').classList.add('d-none');
        });
    }

    document.getElementById('add-account-user').onclick = function () { openEditor(null); };
    form.onsubmit = function (event) {
        event.preventDefault();
        const payload = {
            email: document.getElementById('account-user-email').value.trim(),
            disabled: document.getElementById('account-user-disabled').checked,
            pause_managed_subscriptions_when_disabled: document.getElementById('account-user-pause').checked,
        };
        if (!editingId) payload.username = document.getElementById('account-user-username').value.trim();
        if (editingId) payload.role = document.getElementById('account-user-role').value;
        setMessage(modalMessage, '', '');
        requestJson(editingId
            ? config.accountUsersUrl + '/' + encodeURIComponent(editingId)
            : config.accountUsersUrl, {
                method: editingId ? 'PUT' : 'POST',
                headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
                body: JSON.stringify(payload)
            }).then(function () {
                modal.hide();
                setMessage(message, t('Account Hub user saved.'), 'success');
                return load();
            }).catch(function (error) {
                setMessage(modalMessage, error.message, 'danger');
            });
    };
    load();
}());
