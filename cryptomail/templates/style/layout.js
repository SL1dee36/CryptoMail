
(function () {
    const STORAGE_KEY = 'cryptomail_layout';
    const STARRED_KEY = 'cryptomail_starred_msgs';

    function getStoredLayout() {
        const local = localStorage.getItem(STORAGE_KEY);
        if (local === 'gmail' || local === 'classic') return local;

        const match = document.cookie.match(new RegExp('(^| )' + STORAGE_KEY + '=([^;]+)'));
        if (match && (match[2] === 'gmail' || match[2] === 'classic')) {
            return match[2];
        }
        return 'classic';
    }

    function updateViewportScrollLock(layout) {
        const isGmail = (layout || document.documentElement.getAttribute('data-layout')) === 'gmail';
        const hasMailView = !!document.querySelector('.gm-mail-view');
        if (isGmail && hasMailView) {
            document.documentElement.classList.add('gm-has-mail-view');
            if (document.body) document.body.classList.add('gm-has-mail-view');
        } else {
            document.documentElement.classList.remove('gm-has-mail-view');
            if (document.body) document.body.classList.remove('gm-has-mail-view');
        }
    }

    function initMailViewScroll() {
        const mailView = document.querySelector('.gm-mail-view');
        if (!mailView || mailView.dataset.scrollBound) return;
        mailView.dataset.scrollBound = 'true';

        mailView.addEventListener('wheel', function (e) {
            const activeContainer = getActiveContainer();
            if (activeContainer && !activeContainer.contains(e.target)) {
                activeContainer.scrollTop += e.deltaY;
            }
        }, { passive: true });
    }

    function applyLayout(layout) {
        document.documentElement.setAttribute('data-layout', layout);
        localStorage.setItem(STORAGE_KEY, layout);
        document.cookie = STORAGE_KEY + '=' + layout + '; path=/; max-age=31536000; SameSite=Lax';

        const classicLabel = document.getElementById('layout-toggle-label');
        if (classicLabel) {
            classicLabel.innerText = layout === 'gmail' ? 'Классический' : 'Gmail стиль';
        }

        const gmailBtnText = document.getElementById('gm-layout-text');
        if (gmailBtnText) {
            gmailBtnText.innerText = layout === 'gmail' ? 'Классический вид' : 'Gmail вид';
        }

        updateViewportScrollLock(layout);
        window.dispatchEvent(new CustomEvent('cryptomail:layoutchange', { detail: { layout } }));
    }

    const currentLayout = getStoredLayout();
    applyLayout(currentLayout);

    window.toggleLayout = function () {
        const current = document.documentElement.getAttribute('data-layout') || 'classic';
        const next = current === 'gmail' ? 'classic' : 'gmail';
        applyLayout(next);
    };

    window.setLayout = function (layout) {
        if (layout === 'gmail' || layout === 'classic') {
            applyLayout(layout);
        }
    };

    window.toggleGmailSidebar = function () {
        const sidebar = document.getElementById('gm-sidebar');
        if (!sidebar) return;
        if (window.innerWidth <= 768) {
            sidebar.classList.toggle('mobile-open');
        } else {
            sidebar.classList.toggle('collapsed');
        }
    };

    function getActiveTabName() {
        if (document.getElementById('gm-tab-all')?.classList.contains('active')) return 'all';
        if (document.getElementById('gm-tab-sent')?.classList.contains('active')) return 'sent';
        return 'inbox';
    }

    function getActiveContainer() {
        const name = getActiveTabName();
        if (name === 'all') return document.getElementById('gm-all-list');
        if (name === 'sent') return document.getElementById('gm-sent-list');
        return document.getElementById('gm-inbox-list');
    }

    window.switchGmailTab = function (tabName) {
        const inboxTab = document.getElementById('gm-tab-inbox');
        const sentTab = document.getElementById('gm-tab-sent');
        const allTab = document.getElementById('gm-tab-all');

        const inboxList = document.getElementById('gm-inbox-list');
        const sentList = document.getElementById('gm-sent-list');
        const allList = document.getElementById('gm-all-list');

        const navInbox = document.getElementById('gm-nav-inbox');
        const navSent = document.getElementById('gm-nav-sent');
        const navAll = document.getElementById('gm-nav-all');

        if (inboxTab) inboxTab.classList.remove('active');
        if (sentTab) sentTab.classList.remove('active');
        if (allTab) allTab.classList.remove('active');

        if (navInbox) navInbox.classList.remove('active');
        if (navSent) navSent.classList.remove('active');
        if (navAll) navAll.classList.remove('active');

        if (inboxList) inboxList.style.display = 'none';
        if (sentList) sentList.style.display = 'none';
        if (allList) allList.style.display = 'none';

        if (tabName === 'all' && allList) {
            if (allTab) allTab.classList.add('active');
            if (navAll) navAll.classList.add('active');
            allList.style.display = 'block';
        } else if (tabName === 'sent' && sentList) {
            if (sentTab) sentTab.classList.add('active');
            if (navSent) navSent.classList.add('active');
            sentList.style.display = 'block';
        } else {
            if (inboxTab) inboxTab.classList.add('active');
            if (navInbox) navInbox.classList.add('active');
            if (inboxList) inboxList.style.display = 'block';
        }

        const searchInput = document.getElementById('gm-search-input');
        if (searchInput && searchInput.value) {
            filterGmailMessages(searchInput.value);
        } else {
            const container = getActiveContainer();
            if (container) {
                const count = container.querySelectorAll('.gm-message-row').length;
                const countIndicator = document.getElementById('gm-list-count');
                if (countIndicator) {
                    countIndicator.innerText = `${count} писем`;
                }
            }
        }
        if (typeof syncMasterCheckbox === 'function') {
            syncMasterCheckbox();
        }
    };

    window.filterGmailMessages = function (query) {
        const q = (query || '').toLowerCase().trim();
        const activeContainer = getActiveContainer();
        if (!activeContainer) return;

        const rows = activeContainer.querySelectorAll('.gm-message-row');
        let visibleCount = 0;

        rows.forEach(row => {
            const text = (row.getAttribute('data-search') || row.innerText || '').toLowerCase();
            if (!q || text.includes(q)) {
                row.style.display = 'flex';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });

        const countIndicator = document.getElementById('gm-list-count');
        if (countIndicator) {
            countIndicator.innerText = `${visibleCount} писем`;
        }
    };

    function getStarredMessages() {
        try {
            return JSON.parse(localStorage.getItem(STARRED_KEY) || '[]');
        } catch {
            return [];
        }
    }

    window.toggleStar = function (msgId, event) {
        if (event) {
            event.preventDefault();
            event.stopPropagation();
        }
        let starred = getStarredMessages();
        const starBtn = document.getElementById(`star-${msgId}`);
        const idNum = Number(msgId);

        if (starred.includes(idNum)) {
            starred = starred.filter(id => id !== idNum);
            if (starBtn) {
                starBtn.classList.remove('starred');
                starBtn.querySelector('i').className = 'fa-regular fa-star';
            }
        } else {
            starred.push(idNum);
            if (starBtn) {
                starBtn.classList.add('starred');
                starBtn.querySelector('i').className = 'fa-solid fa-star';
            }
        }
        localStorage.setItem(STARRED_KEY, JSON.stringify(starred));
    };

    window.openGmailCompose = function () {
        const modal = document.getElementById('gm-docked-compose');
        if (modal) {
            modal.style.display = 'flex';
            modal.classList.remove('minimized');
            const subj = modal.querySelector('input[name="subject"]');
            if (subj) subj.focus();
        }
    };

    window.closeGmailCompose = function () {
        const modal = document.getElementById('gm-docked-compose');
        if (modal) {
            modal.style.display = 'none';
        }
    };

    window.minimizeGmailCompose = function () {
        const modal = document.getElementById('gm-docked-compose');
        if (modal) {
            modal.classList.toggle('minimized');
        }
    };

    window.toggleUserDropdown = function (event) {
        if (event) {
            event.stopPropagation();
        }
        const dd = document.getElementById('gm-user-dropdown');
        if (dd) {
            dd.classList.toggle('open');
        }
    };

    document.addEventListener('click', function (e) {
        const dd = document.getElementById('gm-user-dropdown');
        const avatar = document.getElementById('gm-user-avatar');
        if (dd && dd.classList.contains('open')) {
            if (!dd.contains(e.target) && e.target !== avatar && !avatar?.contains(e.target)) {
                dd.classList.remove('open');
            }
        }
    });

    function syncMasterCheckbox() {
        const activeContainer = getActiveContainer();
        const master = document.getElementById('gm-master-checkbox') || document.querySelector('.gm-master-checkbox');
        if (!activeContainer || !master) return;

        const boxes = Array.from(activeContainer.querySelectorAll('.gm-row-checkbox'));
        if (boxes.length === 0) {
            master.checked = false;
            master.indeterminate = false;
            return;
        }

        const checkedBoxes = boxes.filter(b => b.checked);
        if (checkedBoxes.length === 0) {
            master.checked = false;
            master.indeterminate = false;
        } else if (checkedBoxes.length === boxes.length) {
            master.checked = true;
            master.indeterminate = false;
        } else {
            master.checked = false;
            master.indeterminate = true;
        }
    }
    window.syncMasterCheckbox = syncMasterCheckbox;

    window.toggleSelectAllGmail = function (masterCheckbox) {
        const activeContainer = getActiveContainer();
        if (!activeContainer) return;
        const boxes = activeContainer.querySelectorAll('.gm-row-checkbox');
        boxes.forEach(b => {
            b.checked = masterCheckbox.checked;
            const row = b.closest('.gm-message-row');
            if (row) row.classList.toggle('selected', b.checked);
        });
        masterCheckbox.indeterminate = false;
    };

    document.addEventListener('change', (e) => {
        if (e.target && e.target.classList.contains('gm-row-checkbox')) {
            const row = e.target.closest('.gm-message-row');
            if (row) {
                row.classList.toggle('selected', e.target.checked);
            }
            syncMasterCheckbox();
        }
    });

    document.addEventListener('DOMContentLoaded', () => {
        const starred = getStarredMessages();
        starred.forEach(id => {
            const starBtn = document.getElementById(`star-${id}`);
            if (starBtn) {
                starBtn.classList.add('starred');
                const i = starBtn.querySelector('i');
                if (i) i.className = 'fa-solid fa-star';
            }
        });

        // Initialize row selected states and master checkbox
        document.querySelectorAll('.gm-row-checkbox').forEach(b => {
            const row = b.closest('.gm-message-row');
            if (row) row.classList.toggle('selected', b.checked);
        });
        syncMasterCheckbox();
        updateViewportScrollLock();
        initMailViewScroll();
    });

    // Brand Logo Glint Sweep Animation (Ultra-smooth 60fps, no layout thrashing, completes on cursor leave)
    function initBrandLogoGlint() {
        const targets = document.querySelectorAll('.gm-logo, .m3-appbar a[href="/"], .cm-ecp-logo-badge');
        targets.forEach(el => {
            el.addEventListener('mouseenter', () => {
                const icon = el.classList.contains('cm-ecp-gradient-icon')
                    ? el
                    : el.querySelector('.cm-ecp-gradient-icon');
                if (!icon || icon.classList.contains('cm-glint-animating')) return;

                icon.classList.add('cm-glint-animating');

                let timer;
                const onEnd = () => {
                    icon.classList.remove('cm-glint-animating');
                    icon.removeEventListener('animationend', onEnd);
                    if (timer) clearTimeout(timer);
                };

                icon.addEventListener('animationend', onEnd, { once: true });
                timer = setTimeout(onEnd, 1500);
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initBrandLogoGlint);
    } else {
        initBrandLogoGlint();
    }
})();

