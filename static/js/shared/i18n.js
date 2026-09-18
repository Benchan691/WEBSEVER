(function () {
    function t(key, vars) {
        if (key == null) return '';
        var catalog = window.I18N || {};
        var text = Object.prototype.hasOwnProperty.call(catalog, key) ? catalog[key] : String(key);
        if (vars && typeof vars === 'object') {
            Object.keys(vars).forEach(function (name) {
                text = text.split('{' + name + '}').join(String(vars[name]));
            });
        }
        return text;
    }

    window.t = t;
})();
