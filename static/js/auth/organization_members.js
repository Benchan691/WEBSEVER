(function () {
    const config = JSON.parse(document.getElementById('organization-members-page-config').textContent);
    const modal = new bootstrap.Modal(document.getElementById('organization-member-modal'));
    const form = document.getElementById('organization-member-form');
    const rows = document.getElementById('organization-member-rows');
    const message = document.getElementById('message');
    const modalMessage = document.getElementById('modal-message');
    let members = [];
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
        document.getElementById('empty').classList.toggle('d-none', members.length !== 0);
        members.forEach(function (item) {
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
            const edit = button(t('Edit'), 'btn btn-outline-primary btn-sm');
            edit.onclick = function () { openEditor(item); };
            actions.append(edit);
            row.append(username, role, email, status, delivery, actions);
            rows.append(row);
        });
    }

    function openEditor(item) {
        editingId = item.id;
        document.getElementById('organization-member-username').value = item.username || '';
        document.getElementById('organization-member-email').value = item.email || '';
        document.getElementById('organization-member-disabled').checked = Boolean(item.disabled);
        document.getElementById('organization-member-pause').checked = Boolean(item.pause_managed_subscriptions_when_disabled);
        setMessage(modalMessage, '', '');
        modal.show();
    }

    function load() {
        return requestJson(config.membersUrl).then(function (body) {
            members = body.data || [];
            renderRows();
        }).catch(function (error) {
            setMessage(message, error.message, 'danger');
        }).finally(function () {
            document.getElementById('loading').classList.add('d-none');
        });
    }

    form.onsubmit = function (event) {
        event.preventDefault();
        if (!editingId) return;
        const payload = {
            email: document.getElementById('organization-member-email').value.trim(),
            disabled: document.getElementById('organization-member-disabled').checked,
            pause_managed_subscriptions_when_disabled: document.getElementById('organization-member-pause').checked,
        };
        setMessage(modalMessage, '', '');
        requestJson(config.membersUrl + '/' + encodeURIComponent(editingId), {
            method: 'PUT',
            headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
            body: JSON.stringify(payload)
        }).then(function () {
            modal.hide();
            setMessage(message, t('Organization member saved.'), 'success');
            return load();
        }).catch(function (error) {
            setMessage(modalMessage, error.message, 'danger');
        });
    };
    load();
}());
