(function () {
    'use strict';
    const byId = id => document.getElementById(id);
    const config = JSON.parse(byId('settings-config').textContent);
    const message = byId('message');
    const signIn = byId('settings-sign-in');
    function show(text, danger = false, error) {
        message.textContent = text;
        message.className = 'alert ' + (danger ? 'alert-danger' : 'alert-success');
        signIn.classList.toggle('d-none', !error || !['authentication_required', 'unexpected_response'].includes(error.code));
    }
    function submit(id, action) {
        const form = byId(id);
        if (!form) return;
        let pending = false;
        form.addEventListener('submit', async function (event) {
            event.preventDefault();
            if (pending) return;
            pending = true;
            const button = form.querySelector('button[type="submit"]');
            button.disabled = true;
            message.className = 'alert d-none';
            signIn.classList.add('d-none');
            try {
                await action(form);
            } catch (error) {
                show(error.message, true, error);
            } finally {
                pending = false;
                button.disabled = false;
            }
        });
    }
    submit('profile-form', async () => {
        await window.portalRequest(config.profileUrl, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email: byId('profile-email').value.trim()})
        });
        show('Profile saved successfully.');
    });
    submit('password-form', async form => {
        const data = await window.portalRequest(config.passwordUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                current_password: byId('current-password').value,
                new_password: byId('new-password').value,
                new_password_confirmation: byId('new-password-confirmation').value
            })
        });
        if (data.success !== true) throw new Error('The password change was not confirmed. Please retry.');
        form.reset();
        show('Password changed successfully.');
        window.location.assign('/');
    });
}());
