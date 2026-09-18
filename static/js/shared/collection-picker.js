(function () {
    class CollectionPicker {
        constructor(prefix, options) {
            this.prefix = prefix;
            options = options || {};
            this.emptySelectionMeansAll = options.emptySelectionMeansAll === true;
            this.allMode = false;
        }

        element(suffix) {
            return document.getElementById(this.prefix + '-collections-' + suffix);
        }

        checkboxes() {
            return Array.from(this.element('options').querySelectorAll('input[type="checkbox"]'));
        }

        selectedValues() {
            if (this.allMode) return [];
            return this.checkboxes()
                .filter(function (input) { return input.checked; })
                .map(function (input) { return input.value; });
        }

        filter() {
            const query = this.element('search').value.trim().toLowerCase();
            this.element('options').querySelectorAll('.form-check').forEach(function (wrap) {
                const name = wrap.querySelector('input').value.toLowerCase();
                wrap.classList.toggle('d-none', query !== '' && !name.includes(query));
            });
        }

        clearSearch() {
            this.element('search').value = '';
            this.filter();
        }

        updateLabel() {
            const checked = this.checkboxes().filter(function (input) { return input.checked; });
            const toggle = this.element('toggle');
            toggle.textContent = this.allMode || checked.length === 0
                ? t('All collections')
                : checked.length === 1 ? checked[0].value : t('{count} collections', {count: checked.length});
        }

        render(collections, selected) {
            selected = Array.isArray(selected) ? selected : [];
            this.allMode = this.emptySelectionMeansAll && selected.length === 0;
            const options = this.element('options');
            options.replaceChildren();
            collections.forEach((name) => {
                const wrap = document.createElement('div');
                wrap.className = 'form-check mb-1';
                const input = document.createElement('input');
                input.type = 'checkbox';
                input.className = 'form-check-input collection-picker-checkbox';
                input.id = this.prefix + '-collection-' + name.replace(/[^a-zA-Z0-9_-]/g, '_');
                input.value = name;
                input.checked = !this.allMode && selected.includes(name);
                const label = document.createElement('label');
                label.className = 'form-check-label small';
                label.htmlFor = input.id;
                label.textContent = name;
                wrap.append(input, label);
                options.append(wrap);
            });
            this.clearSearch();
            this.updateLabel();
        }

        wire() {
            const search = this.element('search');
            const options = this.element('options');
            search.addEventListener('input', () => this.filter());
            search.addEventListener('click', function (event) { event.stopPropagation(); });
            search.addEventListener('keydown', function (event) { event.stopPropagation(); });
            options.addEventListener('change', () => {
                // Leaving the dynamic all mode makes the visible checkboxes an explicit list.
                this.allMode = false;
                this.updateLabel();
            });
            this.element('menu').addEventListener('click', (event) => {
                const action = event.target.closest('.collections-action');
                if (!action) return;
                event.preventDefault();
                if (this.emptySelectionMeansAll && action.dataset.action === 'reset') {
                    this.allMode = true;
                    this.checkboxes().forEach(function (input) { input.checked = false; });
                    this.updateLabel();
                    return;
                }
                const checkboxes = action.dataset.action === 'all'
                    ? this.checkboxes().filter(function (input) {
                        return !input.closest('.form-check').classList.contains('d-none');
                    })
                    : this.checkboxes();
                this.allMode = false;
                checkboxes.forEach(function (input) {
                    input.checked = action.dataset.action === 'all';
                });
                this.updateLabel();
            });
            this.element('toggle').addEventListener('shown.bs.dropdown', () => {
                this.clearSearch();
                search.focus();
            });
        }
    }

    window.CollectionPicker = CollectionPicker;
})();
