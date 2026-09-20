(function() {
    const savedTheme = localStorage.getItem('cryptomail_theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const initialTheme = savedTheme || (prefersDark ? 'dark' : 'light');

    document.documentElement.setAttribute('data-theme', initialTheme);
    if (initialTheme === 'dark') {
        document.documentElement.classList.add('dark');
    } else {
        document.documentElement.classList.remove('dark');
    }

    window.toggleTheme = function() {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        if (next === 'dark') {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
        localStorage.setItem('cryptomail_theme', next);
        updateThemeIcon(next);
    };

    function updateThemeIcon(theme) {
        const icon = document.getElementById('theme-icon');
        const text = document.getElementById('theme-text');
        const gmIcon = document.getElementById('gm-theme-icon');

        if (gmIcon) {
            gmIcon.className = theme === 'dark' ? 'fa-solid fa-moon text-indigo-400' : 'fa-solid fa-sun text-amber-500';
        }

        if (!icon) return;
        if (theme === 'dark') {
            icon.className = 'fa-solid fa-moon text-indigo-400';
            if (text) text.innerText = 'Тёмная';
        } else {
            icon.className = 'fa-solid fa-sun text-amber-500';
            if (text) text.innerText = 'Светлая';
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        updateThemeIcon(current);
    });
})();
