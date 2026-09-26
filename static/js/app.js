    function setupPageLoader() {
      const loader = document.querySelector('[data-page-loader]');
      let showTimer;
      let safetyTimer;

      function hideLoader() {
        clearTimeout(showTimer);
        clearTimeout(safetyTimer);
        loader.hidden = true;
      }

      function showLoader() {
        clearTimeout(showTimer);
        showTimer = setTimeout(() => {
          loader.hidden = false;
          safetyTimer = setTimeout(hideLoader, 15000);
        }, 140);
      }

      document.addEventListener('click', (event) => {
        const link = event.target.closest('a[href]');
        if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        if (link.hasAttribute('download') || link.target && link.target !== '_self') return;
        const url = new URL(link.href, window.location.href);
        if (url.origin !== window.location.origin || !['http:', 'https:'].includes(url.protocol)) return;
        if (url.pathname === window.location.pathname && url.search === window.location.search && url.hash) return;
        if (/\/(import\/(template|sample))\/$/.test(url.pathname)) return;
        showLoader();
      });

      document.addEventListener('submit', (event) => {
        if (!event.defaultPrevented) showLoader();
      });
      window.addEventListener('pageshow', hideLoader);
    }

    function setupDatePickers() {
      if (!window.jQuery || !jQuery.fn.datepicker) return;

      jQuery('.date-picker').datepicker({
        dateFormat: 'yy-mm-dd',
        maxDate: 0,
        changeMonth: true,
        changeYear: true,
        yearRange: 'c-120:c',
        showButtonPanel: true,
        constrainInput: true,
      });

      jQuery('form').each(function () {
        const birthDate = jQuery(this).find('[name="date_of_birth"]');
        const deathDate = jQuery(this).find('[name="date_of_death"]');
        if (!birthDate.length || !deathDate.length) return;

        function syncDateRange() {
          deathDate.datepicker('option', 'minDate', birthDate.val() || null);
          birthDate.datepicker('option', 'maxDate', deathDate.val() || 0);
        }

        birthDate.on('change', syncDateRange);
        deathDate.on('change', syncDateRange);
        syncDateRange();
      });
    }

    function setupSearchableSelects() {
      if (!window.jQuery || !jQuery.fn.select2) return;
      jQuery('select:not(.select2-hidden-accessible)').each(function () {
        const select = jQuery(this);
        const emptyOption = select.find('option[value=""]').first();
        select.select2({
          width: '100%',
          placeholder: emptyOption.text() || 'Search and select',
          allowClear: Boolean(emptyOption.length),
          minimumResultsForSearch: 0,
        });
      });
    }

    function setupPhoneInputs() {
      document.querySelectorAll('select[name$="phone_number_0"]').forEach((countrySelect) => {
        countrySelect.closest('div')?.classList.add('phone-input-group');
      });
    }

    function setupLivingStatusControls() {
      document.querySelectorAll('form').forEach((form) => {
        const livingField = form.querySelector('[name="is_living"]');
        if (!livingField) return;

        const deathFieldNames = [
          'date_of_death',
          'place_of_death',
          'burial_location',
          'memorial_information',
        ];

        function syncDeathFields() {
          const personIsLiving = livingField.checked;
          deathFieldNames.forEach((name) => {
            const field = form.querySelector(`[name="${name}"]`);
            if (!field) return;
            const wrapper = field.closest('div');
            if (!wrapper) return;
            wrapper.classList.toggle('hidden-field', personIsLiving);
            if (personIsLiving) {
              field.value = '';
            }
          });
        }

        livingField.addEventListener('change', syncDeathFields);
        syncDeathFields();
      });
    }

    function setupLocationControls() {
      document.querySelectorAll('form').forEach((form) => {
        const residence = form.querySelector('[name="current_residence"]');
        const country = form.querySelector('[name="country"]');
        if (!country || !residence) return;

        const countryWrapper = country.closest('div');
        const outsideValue = 'Other (Nje ya Tanzania)';
        function syncCountry() {
          const isOutside = residence.value === outsideValue;
          countryWrapper?.classList.toggle('hidden-field', !isOutside);
          country.required = isOutside;
          if (!isOutside) {
            country.value = 'Tanzania';
          } else if (country.value === 'Tanzania') {
            country.value = '';
          }
        }
        residence.addEventListener('change', syncCountry);
        if (window.jQuery) {
          jQuery(residence).on('change.location select2:select.location select2:clear.location', syncCountry);
        }
        syncCountry();
      });
    }

    function setupAccountMenu() {
      const menu = document.querySelector('[data-account-menu]');
      if (!menu) return;

      const button = menu.querySelector('[data-account-menu-button]');
      const dropdown = menu.querySelector('[data-account-dropdown]');

      function setMenuOpen(isOpen) {
        menu.classList.toggle('is-open', isOpen);
        button.setAttribute('aria-expanded', String(isOpen));
        if (isOpen) dropdown.querySelector('a, button')?.focus();
      }

      button.addEventListener('click', () => {
        setMenuOpen(!menu.classList.contains('is-open'));
      });
      document.addEventListener('click', (event) => {
        if (!menu.contains(event.target)) setMenuOpen(false);
      });
      menu.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
          setMenuOpen(false);
          button.focus();
        }
      });
    }

    function setupSidebarSections() {
      document.querySelectorAll('[data-sidebar-section]').forEach((section) => {
        const sectionName = section.dataset.sidebarSection;
        const button = section.querySelector('.sidebar-heading');
        const links = section.querySelector('.sidebar-links');
        const storageKey = `moshi-sidebar-${sectionName}`;
        let isOpen = true;

        try {
          isOpen = localStorage.getItem(storageKey) !== 'closed';
        } catch (error) {
          isOpen = true;
        }

        function setOpen(open) {
          isOpen = open;
          button.setAttribute('aria-expanded', String(open));
          links.hidden = !open;
          try {
            localStorage.setItem(storageKey, open ? 'open' : 'closed');
          } catch (error) {
            // The menu still works when browser storage is unavailable.
          }
        }

        button.addEventListener('click', () => setOpen(!isOpen));
        setOpen(isOpen);
      });
    }

    function setupNavigation() {
      const sidebar = document.querySelector('.sidebar');
      const toggle = document.querySelector('[data-mobile-nav-toggle]');
      const currentPath = window.location.pathname.replace(/\/$/, '') || '/';

      let activeLink = null;
      let activeLength = -1;
      document.querySelectorAll('.sidebar a').forEach((link) => {
        const linkPath = new URL(link.href, window.location.origin).pathname.replace(/\/$/, '') || '/';
        const exactMatch = linkPath === currentPath;
        const nestedMatch = linkPath !== '/' && currentPath.startsWith(`${linkPath}/`);
        if ((exactMatch || nestedMatch) && linkPath.length > activeLength) {
          activeLink = link;
          activeLength = linkPath.length;
        }
      });
      if (activeLink) {
        activeLink.classList.add('is-active');
        activeLink.setAttribute('aria-current', 'page');
      }

      if (!sidebar || !toggle) return;
      toggle.addEventListener('click', () => {
        const isOpen = sidebar.classList.toggle('is-open');
        toggle.setAttribute('aria-expanded', String(isOpen));
        toggle.setAttribute('aria-label', isOpen ? 'Close navigation' : 'Open navigation');
        const icon = toggle.querySelector('svg');
        if (icon) icon.setAttribute('data-lucide', isOpen ? 'x' : 'menu');
        if (window.lucide) lucide.createIcons();
      });
      sidebar.addEventListener('click', (event) => {
        if (event.target.closest('a') && window.innerWidth <= 760) {
          sidebar.classList.remove('is-open');
          toggle.setAttribute('aria-expanded', 'false');
        }
      });
    }

    function setupResponsiveTables() {
      document.querySelectorAll('table').forEach((table) => {
        if (table.parentElement?.classList.contains('table-scroll')) return;
        const wrapper = document.createElement('div');
        wrapper.className = 'table-scroll';
        table.parentNode.insertBefore(wrapper, table);
        wrapper.appendChild(table);
      });
    }

    function setupPrintButtons() {
      document.querySelectorAll('[data-print-report]').forEach((button) => {
        button.addEventListener('click', () => window.print());
      });
    }

    function setupMemberImportPanel() {
      const toggle = document.querySelector('[data-import-toggle]');
      const panel = document.querySelector('[data-import-panel]');
      if (!toggle || !panel) return;
      toggle.addEventListener('click', () => {
        const willOpen = panel.hidden;
        panel.hidden = !willOpen;
        toggle.setAttribute('aria-expanded', String(willOpen));
        if (willOpen) panel.querySelector('input[type="file"]')?.focus();
      });
    }

    document.addEventListener('DOMContentLoaded', () => {
      setupPageLoader();
      setupDatePickers();
      setupPhoneInputs();
      setupSearchableSelects();
      setupLivingStatusControls();
      setupLocationControls();
      setupAccountMenu();
      setupSidebarSections();
      setupNavigation();
      setupResponsiveTables();
      setupPrintButtons();
      setupMemberImportPanel();
      if (window.lucide) lucide.createIcons();
    });
