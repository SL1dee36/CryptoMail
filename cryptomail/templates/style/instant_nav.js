/**
 * InstantNav: High-Speed Instant Page Transitions for CryptoMail.
 * Provides SPA-like instant navigation, link prefetching on hover/touch,
 * and seamless main content replacement without full page reload.
 */
(function () {
    const pageCache = new Map();
    const MAX_CACHE_SIZE = 25;

    function isInternalLink(a) {
        if (!a || !a.href || a.target === '_blank' || a.hasAttribute('download')) return false;
        try {
            const url = new URL(a.href, window.location.origin);
            if (url.origin !== window.location.origin) return false;
            const p = url.pathname;
            // Exclude exports, downloads, auth actions, or raw file routes
            if (
                p.startsWith('/export') ||
                p.includes('/export/') ||
                p.startsWith('/ecp/download') ||
                p.startsWith('/ecp/rsa/download') ||
                p.startsWith('/logout') ||
                p.startsWith('/api/') ||
                p.endsWith('.pdf') ||
                p.endsWith('.json') ||
                p.endsWith('.sig')
            ) {
                return false;
            }
            if (url.pathname === window.location.pathname && url.search === window.location.search) {
                return false;
            }
            return true;
        } catch (e) {
            return false;
        }
    }

    async function fetchPage(url) {
        const cleanUrl = url.split('#')[0];
        if (pageCache.has(cleanUrl)) {
            return pageCache.get(cleanUrl);
        }
        const promise = fetch(cleanUrl, {
            headers: { 'X-Requested-With': 'CryptoMail-Instant' }
        }).then(async res => {
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return await res.text();
        }).catch(err => {
            pageCache.delete(cleanUrl);
            throw err;
        });

        if (pageCache.size >= MAX_CACHE_SIZE) {
            const firstKey = pageCache.keys().next().value;
            pageCache.delete(firstKey);
        }
        pageCache.set(cleanUrl, promise);
        return promise;
    }

    function prefetchLink(a) {
        if (!isInternalLink(a)) return;
        const cleanUrl = a.href.split('#')[0];
        if (!pageCache.has(cleanUrl)) {
            fetchPage(a.href).catch(() => {});
        }
    }

    function reinitializePageScripts(container) {
        // Execute scripts inside swapped container
        const scripts = container.querySelectorAll('script');
        scripts.forEach(oldScript => {
            const newScript = document.createElement('script');
            Array.from(oldScript.attributes).forEach(attr => newScript.setAttribute(attr.name, attr.value));
            newScript.appendChild(document.createTextNode(oldScript.innerHTML));
            oldScript.parentNode.replaceChild(newScript, oldScript);
        });

        // Trigger custom event so page-specific JS can bind
        window.dispatchEvent(new CustomEvent('cryptomail:page-swapped', {
            detail: { path: window.location.pathname }
        }));
    }

    async function navigateTo(url, push = true) {
        const targetMain = document.getElementById('main-content-wrapper');
        if (!targetMain) {
            window.location.href = url;
            return;
        }

        try {
            targetMain.style.opacity = '0.85';
            targetMain.style.transition = 'opacity 0.08s ease';

            const html = await fetchPage(url);
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');

            const newMain = doc.getElementById('main-content-wrapper');
            if (!newMain) {
                // If target page doesn't have standard main wrapper, full reload
                window.location.href = url;
                return;
            }

            // Update title
            if (doc.title) {
                document.title = doc.title;
            }

            // Swap main content
            targetMain.innerHTML = newMain.innerHTML;
            targetMain.className = newMain.className;
            targetMain.style.opacity = '1';

            // Sync layout attribute if needed
            const newLayout = doc.documentElement.getAttribute('data-layout');
            if (newLayout) {
                document.documentElement.setAttribute('data-layout', newLayout);
            }

            // Update active navbar styles if any
            syncActiveNavLinks(url);

            // Update URL in browser history
            if (push) {
                window.history.pushState({ url }, '', url);
            }

            // Scroll to top
            window.scrollTo({ top: 0, behavior: 'instant' });

            // Re-run dynamic scripts
            reinitializePageScripts(targetMain);
        } catch (e) {
            window.location.href = url;
        }
    }

    function syncActiveNavLinks(url) {
        try {
            const targetPath = new URL(url, window.location.origin).pathname;
            document.querySelectorAll('a[href]').forEach(a => {
                const hrefPath = new URL(a.href, window.location.origin).pathname;
                if (hrefPath === targetPath) {
                    a.classList.add('active');
                } else if (hrefPath !== '/') {
                    a.classList.remove('active');
                }
            });
        } catch (e) {}
    }

    // Prefetch on hover or touch
    document.addEventListener('mouseover', function (e) {
        const a = e.target.closest('a');
        if (a) prefetchLink(a);
    }, { passive: true });

    document.addEventListener('touchstart', function (e) {
        const a = e.target.closest('a');
        if (a) prefetchLink(a);
    }, { passive: true });

    // Intercept clicks on links
    document.addEventListener('click', function (e) {
        const a = e.target.closest('a');
        if (!a || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || e.button !== 0) return;
        if (!isInternalLink(a)) return;

        e.preventDefault();
        navigateTo(a.href, true);
    });

    // Invalidate cache on form submits
    document.addEventListener('submit', function () {
        pageCache.clear();
    });

    window.addEventListener('popstate', function () {
        navigateTo(window.location.href, false);
    });

    window.InstantNav = {
        navigateTo,
        prefetch: fetchPage,
        clearCache: () => pageCache.clear(),
    };
})();

