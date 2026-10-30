const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.join(__dirname, '..');
const api = fs.readFileSync(path.join(root, 'static/js/shared/api.js'), 'utf8');
const settings = fs.readFileSync(path.join(root, 'static/js/auth/settings.js'), 'utf8');

function browser(fetch) {
    const window = {};
    const context = vm.createContext({window, fetch});
    vm.runInContext(api, context);
    return {window, context};
}
const json = (data, status = 200) => new Response(JSON.stringify(data), {status, headers: {'Content-Type': 'application/json'}});

test('HTML and login redirects never produce a JSON SyntaxError', async () => {
    for (const redirected of [true, false]) {
        let parsed = false;
        const {window} = browser(async () => ({
            status: 200, ok: true, redirected,
            headers: new Headers({'Content-Type': 'text/html'}),
            json: () => { parsed = true; throw new SyntaxError('Unexpected token <'); }
        }));
        await assert.rejects(window.portalRequest('/api/auth/password'), error => {
            assert.ok(['authentication_required', 'unexpected_response'].includes(error.code));
            assert.match(error.message, /Sign in again/);
            return true;
        });
        assert.equal(parsed, false);
    }
});

test('missing sessions and validation errors retain usable messages', async () => {
    let {window} = browser(async () => json({error: 'Authentication required'}, 401));
    await assert.rejects(window.portalRequest('/api/auth/password'), error => error.code === 'authentication_required');
    ({window} = browser(async () => json({error: 'Current password is incorrect.'}, 400)));
    await assert.rejects(window.portalRequest('/api/auth/password'), /Current password is incorrect/);
});

function settingsPage(fetch) {
    const {window, context} = browser(fetch);
    function node(value = '') {
        const classes = new Set(['d-none']);
        return {
            value, textContent: '', className: '', disabled: false, listeners: {},
            classList: {
                add: name => classes.add(name),
                contains: name => classes.has(name),
                toggle: (name, hide) => hide ? classes.add(name) : classes.delete(name)
            },
            addEventListener(event, listener) { this.listeners[event] = listener; },
            querySelector() { return this.button; },
            reset() { this.resetCalled = true; }
        };
    }
    const nodes = Object.fromEntries(['settings-config', 'message', 'settings-sign-in', 'password-form', 'current-password', 'new-password', 'new-password-confirmation'].map(id => [id, node()]));
    nodes['settings-config'].textContent = JSON.stringify({passwordUrl: '/api/auth/password', profileUrl: '/api/auth/profile'});
    nodes['password-form'].button = node();
    nodes['current-password'].value = 'temporary-password';
    nodes['new-password'].value = nodes['new-password-confirmation'].value = 'replacement-password';
    let destination;
    window.location = {assign: url => { destination = url; }};
    context.document = {getElementById: id => nodes[id] || null};
    vm.runInContext(settings, context);
    return {nodes, destination: () => destination, submit: () => nodes['password-form'].listeners.submit({preventDefault() {}})};
}

test('first-login page works without an editable profile and changes password before navigating', async () => {
    let request;
    const page = settingsPage(async (url, options) => {
        request = {url, ...options};
        return json({success: true});
    });
    await page.submit();
    assert.equal(request.url, '/api/auth/password');
    assert.equal(request.method, 'POST');
    assert.equal(request.credentials, 'same-origin');
    assert.equal(request.headers.Accept, 'application/json');
    assert.deepEqual(JSON.parse(request.body), {
        current_password: 'temporary-password', new_password: 'replacement-password',
        new_password_confirmation: 'replacement-password'
    });
    assert.equal(page.destination(), '/');
    assert.equal(page.nodes['password-form'].resetCalled, true);
    assert.equal(page.nodes['password-form'].button.disabled, false);
});

test('failed password changes stay on Settings and can be retried', async () => {
    let attempts = 0;
    const page = settingsPage(async () => ++attempts === 1 ? json({error: 'Current password is incorrect.'}, 400) : json({success: true}));
    await page.submit();
    assert.equal(page.destination(), undefined);
    assert.match(page.nodes.message.textContent, /Current password is incorrect/);
    assert.equal(page.nodes['password-form'].button.disabled, false);
    await page.submit();
    assert.equal(page.destination(), '/');
});

test('HTML response shows a sign-in action instead of the raw parser error', async () => {
    const page = settingsPage(async () => new Response('<!DOCTYPE html><title>Login</title>', {headers: {'Content-Type': 'text/html'}}));
    await page.submit();
    assert.equal(page.destination(), undefined);
    assert.match(page.nodes.message.textContent, /API response/);
    assert.equal(page.nodes['settings-sign-in'].classList.contains('d-none'), false);
});
