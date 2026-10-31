(function () {
    'use strict';
    const config = JSON.parse(document.getElementById('management-config').textContent);
    const can = id => Boolean(config.permissions[id]);
    const byId = id => document.getElementById(id);
    let organizations = [], users = [], roles = [], editingRole = null;
    let showDeletedUsers = false, showDeletedRoles = false;
    const selection = byId('management-organization');
    const userOrganization = byId('new-user-organization');
    const orgId = () => selection.value;
    function message(text, danger = false) {
        const node = byId('management-message');
        node.textContent = text; node.className = 'alert ' + (danger ? 'alert-danger' : 'alert-success');
    }
    async function request(path, method = 'GET', body) {
        return window.portalRequest(path, {method, headers: {'Content-Type': 'application/json'}, body: body === undefined ? undefined : JSON.stringify(body)});
    }
    function option(value, text) { const item = document.createElement('option'); item.value = value; item.textContent = text; return item; }
    function button(text, action, danger = false) {
        const item = document.createElement('button'); item.type = 'button'; item.className = 'btn btn-sm me-1 mb-1 btn-outline-' + (danger ? 'danger' : 'primary'); item.textContent = text;
        item.onclick = () => { item.disabled = true; Promise.resolve().then(action).catch(error => message(error.message, true)).finally(() => { item.disabled = false; }); };
        return item;
    }
    function customRoles(organization = orgId()) { return roles.filter(role => role.organization_id === organization && role.type === 'custom' && !role.disabled); }
    function roleOptions(select, selected, organization = orgId()) {
        select.replaceChildren(option('', 'No access role (Settings only)'));
        customRoles(organization).forEach(role => select.append(option(role.id, role.name)));
        select.value = selected || '';
    }
    function draw() {
        const selected = organizations.find(org => org.id === orgId());
        byId('organization-id').textContent = 'Organization ID: ' + (orgId() || 'Select an organization') + (selected && selected.disabled ? ' — disabled' : '');
        if (userOrganization) {
            const previous = userOrganization.value || orgId() || config.user.organization_id;
            userOrganization.replaceChildren(option('', 'Select an organization'));
            organizations.filter(org => !org.disabled).forEach(org => userOrganization.append(option(org.id, org.name)));
            userOrganization.value = organizations.some(org => org.id === previous && !org.disabled) ? previous : '';
            userOrganization.disabled = !config.superadmin;
            roleOptions(byId('new-user-role'), '', userOrganization.value);
            byId('new-user-role').disabled = !can('users.assign_roles');
        }
        const userRows = byId('user-rows');
        if (userRows) {
            userRows.replaceChildren();
            users.filter(user => user.organization_id === orgId() || user.reserved || (config.superadmin && user.migration_required)).forEach(user => {
                const row = userRows.insertRow(); row.insertCell().textContent = user.username;
                row.insertCell().textContent = user.email || 'Email required before password reset';
                row.insertCell().textContent = organizations.find(org => org.id === user.organization_id)?.name || user.organization || 'Global';
                row.insertCell().textContent = user.role || 'No access role';
                row.insertCell().textContent = user.migration_required ? 'Migration required (offline)' : user.reserved ? 'Reserved superadmin' : user.deleted ? 'Deleted' : user.disabled ? 'Disabled' : 'Active';
                const actions = row.insertCell();
                if (user.reserved || user.id === config.user.id || user.migration_required) return;
                if (user.deleted) {
                    if (can('users.delete')) {
                        actions.append(button('Restore', async () => { if (!confirm('Restore this account? It will become active again with its previous role.')) return; await request('/api/users/' + user.id + '/restore', 'POST', {}); await reload(); message('Account restored.'); }));
                        actions.append(button('Delete forever', async () => { if (!confirm('Permanently delete this retired account? The login is removed forever and this cannot be undone.')) return; await request('/api/users/' + user.id + '/purge', 'DELETE'); await reload(); message('Account permanently deleted.'); }, true));
                    }
                    return;
                }
                if (can('users.edit')) {
                    actions.append(button(user.disabled ? 'Enable' : 'Disable', async () => { await request('/api/users/' + user.id, 'PUT', {disabled: !user.disabled}); await reload(); }));
                    actions.append(button('Edit email', async () => { const email = prompt('Account email address (required for temporary passwords)', user.email || ''); if (email !== null) { await request('/api/users/' + user.id, 'PUT', {email: email.trim()}); await reload(); message('Account email updated.'); } }));
                }
                if (can('users.reset_password')) actions.append(button('Email temporary password', async () => {
                    if (!user.email) throw new Error('Set an account email address before resetting the password.');
                    if (!confirm('Email a temporary password to ' + user.email + '? Existing sessions will be invalidated after delivery succeeds.')) return;
                    const data = await request('/api/users/' + user.id + '/password-reset', 'POST', {});
                    message('Temporary password emailed to ' + data.email + '. It expires in 24 hours.');
                }));
                if (can('users.assign_roles')) {
                    const select = document.createElement('select'); select.className = 'form-select form-select-sm d-inline-block w-auto me-1'; select.setAttribute('aria-label', 'Role for ' + user.username); roleOptions(select, user.role_id); actions.append(select);
                    actions.append(button('Assign role', async () => { await request('/api/users/' + user.id + '/role', 'PUT', {role_id: select.value}); await reload(); }));
                }
                if (can('organizations.manage') && user.organization_id === orgId()) actions.append(button('Appoint org administrator', async () => { if (!confirm('Grant organization administrator permissions to this user?')) return; await request('/api/organizations/' + orgId() + '/administrators', 'POST', {user_id: user.id}); await reload(); }));
                if (can('users.delete')) actions.append(button('Retire', async () => { if (!confirm('Retire this account? Data and subscriptions are preserved.')) return; await request('/api/users/' + user.id, 'DELETE'); await reload(); }, true));
            });
        }
        const roleRows = byId('role-rows');
        if (roleRows) {
            roleRows.replaceChildren();
            roles.filter(role => role.organization_id === orgId()).forEach(role => {
                const row = roleRows.insertRow(); row.insertCell().textContent = role.name; row.insertCell().textContent = role.type + (role.disabled ? ' (deleted)' : ''); const actions = row.insertCell();
                if (role.type !== 'custom') return;
                if (role.disabled) {
                    if (can('roles.delete')) {
                        actions.append(button('Restore', async () => { if (!confirm('Restore this role? Its permissions and delegations become active again.')) return; await request('/api/roles/' + role.id + '/restore', 'POST', {}); await reload(); message('Role restored.'); }));
                        actions.append(button('Delete forever', async () => { if (!confirm('Permanently delete this retired role? Accounts assigned to it revert to the no-access default. This cannot be undone.')) return; await request('/api/roles/' + role.id + '/purge', 'DELETE'); await reload(); message('Role permanently deleted.'); }, true));
                    }
                    return;
                }
                if (can('roles.edit')) actions.append(button('Edit', () => { editingRole = role.id; byId('role-name').value = role.name; byId('role-form-title').textContent = 'Edit custom role'; document.querySelectorAll('[data-permission]').forEach(input => { input.checked = role.permissions.includes(input.value); }); byId('role-form').scrollIntoView(); }));
                if (can('roles.delete')) actions.append(button('Retire', async () => { if (!confirm('Revoke this role and all delegations depending on it?')) return; await request('/api/roles/' + role.id, 'DELETE'); await reload(); }, true));
            });
        }
    }
    async function reload() {
        const reads = await Promise.all([
            can('users.view') ? request('/api/users' + (showDeletedUsers ? '?include_deleted=1' : '')) : Promise.resolve({data: []}),
            can('roles.view') ? request('/api/roles' + (showDeletedRoles ? '?include_deleted=1' : '')) : Promise.resolve({data: []}),
            can('organizations.view') ? request('/api/organizations') : Promise.resolve({data: [{id: config.user.organization_id, name: config.user.organization}]})
        ]);
        users = reads[0].data; roles = reads[1].data; organizations = reads[2].data;
        const previous = orgId() || config.user.organization_id;
        selection.replaceChildren(option('', 'Select an organization'));
        organizations.forEach(org => selection.append(option(org.id, org.name + (org.disabled ? ' (disabled)' : ''))));
        selection.value = previous || (organizations[0] && organizations[0].id) || '';
        if (!config.superadmin) selection.disabled = true;
        draw();
    }
    selection.onchange = () => { editingRole = null; if (byId('role-form')) byId('role-form').reset(); draw(); };
    if (userOrganization) userOrganization.onchange = () => roleOptions(byId('new-user-role'), '', userOrganization.value);
    const showDeletedUsersBox = byId('show-deleted-users');
    if (showDeletedUsersBox) showDeletedUsersBox.onchange = () => { showDeletedUsers = showDeletedUsersBox.checked; reload().catch(error => message(error.message, true)); };
    const showDeletedRolesBox = byId('show-deleted-roles');
    if (showDeletedRolesBox) showDeletedRolesBox.onchange = () => { showDeletedRoles = showDeletedRolesBox.checked; reload().catch(error => message(error.message, true)); };
    const checkboxContainer = byId('permission-checkboxes');
    if (checkboxContainer) {
        let previousGroup, column;
        config.catalog.forEach(permission => {
            if (permission.group !== previousGroup) { column = document.createElement('fieldset'); column.className = 'col-md-6'; const legend = document.createElement('legend'); legend.className = 'h6'; legend.textContent = permission.group; column.append(legend); checkboxContainer.append(column); previousGroup = permission.group; }
            const wrap = document.createElement('label'); wrap.className = 'form-check d-block'; const input = document.createElement('input'); input.type = 'checkbox'; input.className = 'form-check-input'; input.value = permission.id; input.dataset.permission = permission.id; input.disabled = permission.global || !can(permission.id);
            const label = document.createElement('span'); label.className = 'form-check-label'; label.textContent = permission.label + (permission.global ? ' (superadmin only)' : ''); wrap.append(input, label); column.append(wrap);
        });
    }
    function submit(id, action) {
        const form = byId(id); if (!form) return;
        form.onsubmit = event => { event.preventDefault(); const submit = form.querySelector('button'); submit.disabled = true; Promise.resolve().then(action).catch(error => message(error.message, true)).finally(() => { submit.disabled = false; }); };
    }
    submit('organization-form', async () => { const data = await request('/api/organizations', 'POST', {name: byId('organization-name').value}); selection.replaceChildren(option(data.data.id, data.data.name)); byId('organization-form').reset(); await reload(); message('Organization created. Provision an account, then appoint its organization administrator.'); });
    if (byId('rename-organization')) byId('rename-organization').onclick = async () => { try { if (!orgId()) throw new Error('Select an organization.'); const name = prompt('New organization name'); if (name) { await request('/api/organizations/' + orgId(), 'PUT', {name}); await reload(); } } catch (error) { message(error.message, true); } };
    if (byId('toggle-organization')) byId('toggle-organization').onclick = async () => { try { const org = organizations.find(item => item.id === orgId()); if (!org) throw new Error('Select an organization.'); if (confirm((org.disabled ? 'Enable' : 'Disable') + ' this organization? Disabled organizations cannot sign in or deliver scheduled mail.')) { await request('/api/organizations/' + org.id, 'PUT', {disabled: !org.disabled}); await reload(); } } catch (error) { message(error.message, true); } };
    submit('user-form', async () => {
        const organization = userOrganization.value;
        if (!organization) throw new Error('Select an organization for the new account.');
        let data;
        try {
            data = await request('/api/users', 'POST', {username: byId('new-username').value.trim(), email: byId('new-email').value.trim(), organization_id: organization, role_id: byId('new-user-role').value});
        } catch (error) {
            // A delivery failure can leave a concurrently modified account;
            // refresh the list so administrators can retry from that record.
            await reload().catch(() => {});
            throw error;
        }
        byId('user-form').reset();
        selection.value = organization;
        await reload();
        message('Account created. Temporary password emailed to ' + data.email + '; expires in 24 hours.');
    });
    submit('role-form', async () => { const body = {name: byId('role-name').value, permissions: Array.from(document.querySelectorAll('[data-permission]:checked')).map(input => input.value)}; if (!editingRole) body.organization_id = orgId(); await request(editingRole ? '/api/roles/' + editingRole : '/api/roles', editingRole ? 'PUT' : 'POST', body); editingRole = null; byId('role-form').reset(); byId('role-form-title').textContent = 'Create custom role'; await reload(); message('Role saved.'); });
    if (byId('cancel-role-edit')) byId('cancel-role-edit').onclick = () => { editingRole = null; byId('role-form').reset(); byId('role-form-title').textContent = 'Create custom role'; };
    reload().catch(error => message(error.message, true));
})();
