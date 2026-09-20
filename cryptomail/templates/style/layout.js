
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

    window.switchGmailTab = function (tabName) {
        const inboxTab = document.getElementById('gm-tab-inbox');
        const sentTab = document.getElementById('gm-tab-sent');
        const inboxList = document.getElementById('gm-inbox-list');
        const sentList = document.getElementById('gm-sent-list');
        const navInbox = document.getElementById('gm-nav-inbox');
        const navSent = document.getElementById('gm-nav-sent');

        if (!inboxTab || !sentTab || !inboxList || !sentList) return;

        if (tabName === 'inbox') {
            inboxTab.classList.add('active');
            sentTab.classList.remove('active');
            if (navInbox) navInbox.classList.add('active');
            if (navSent) navSent.classList.remove('active');

            inboxList.style.display = 'block';
            sentList.style.display = 'none';
        } else {
            sentTab.classList.add('active');
            inboxTab.classList.remove('active');
            if (navSent) navSent.classList.add('active');
            if (navInbox) navInbox.classList.remove('active');

            sentList.style.display = 'block';
            inboxList.style.display = 'none';
        }

        const searchInput = document.getElementById('gm-search-input');
        if (searchInput && searchInput.value) {
            filterGmailMessages(searchInput.value);
        }
    };

    window.filterGmailMessages = function (query) {
        const q = (query || '').toLowerCase().trim();
        const activeTab = document.getElementById('gm-tab-inbox')?.classList.contains('active') ? 'inbox' : 'sent';
        const activeContainer = activeTab === 'inbox' ? document.getElementById('gm-inbox-list') : document.getElementById('gm-sent-list');

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

    window.toggleSelectAllGmail = function (masterCheckbox) {
        const activeTab = document.getElementById('gm-tab-inbox')?.classList.contains('active') ? 'inbox' : 'sent';
        const activeContainer = activeTab === 'inbox' ? document.getElementById('gm-inbox-list') : document.getElementById('gm-sent-list');
        if (!activeContainer) return;
        const boxes = activeContainer.querySelectorAll('.gm-row-checkbox');
        boxes.forEach(b => b.checked = masterCheckbox.checked);
    };

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
    });
})();
