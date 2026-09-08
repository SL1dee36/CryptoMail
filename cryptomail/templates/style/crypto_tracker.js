/**
 * CryptoTaskTracker: Real-time progress monitoring for encryption and decryption.
 * Displays live iterations, candidates, elapsed time, and stages.
 * Shows top notification toast upon completion with direct link to the message.
 */

const CryptoTaskTracker = (function () {
    let currentTaskId = null;
    let pollInterval = null;
    let timerInterval = null;
    let toastTimeout = null;
    let taskStartTime = null;
    let isExpanded = true;
    let completionCallback = null;

    function formatTime(seconds) {
        const m = Math.floor(seconds / 60);
        const s = Math.floor(seconds % 60);
        const ds = Math.floor((seconds * 10) % 10);
        return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}.${ds}`;
    }

    function formatNumber(num) {
        if (num === null || num === undefined) return '0';
        return Number(num).toLocaleString('ru-RU');
    }

    function getElements() {
        return {
            dock: document.getElementById('crypto-dock'),
            header: document.getElementById('crypto-dock-header'),
            body: document.getElementById('crypto-dock-body'),
            icon: document.getElementById('crypto-dock-icon'),
            title: document.getElementById('crypto-dock-title'),
            subtitle: document.getElementById('crypto-dock-subtitle'),
            chevron: document.getElementById('crypto-dock-chevron'),
            closeBtn: document.getElementById('crypto-dock-close-btn'),
            stageLabel: document.getElementById('crypto-stage-label'),
            percentLabel: document.getElementById('crypto-percent-label'),
            progressBar: document.getElementById('crypto-progress-bar'),
            statIterations: document.getElementById('crypto-stat-iterations'),
            statMaxIterations: document.getElementById('crypto-stat-max-iterations'),
            statCandidates: document.getElementById('crypto-stat-candidates'),
            statTime: document.getElementById('crypto-stat-time'),
            statAlgorithm: document.getElementById('crypto-stat-algorithm'),
            actions: document.getElementById('crypto-dock-actions'),
            btnGotoMessage: document.getElementById('crypto-btn-goto-message'),
            btnCloseDock: document.getElementById('crypto-btn-close-dock'),
            topToast: document.getElementById('crypto-top-toast'),
            toastTitle: document.getElementById('crypto-toast-title'),
            toastSubtitle: document.getElementById('crypto-toast-subtitle'),
        };
    }

    function toggleExpand() {
        const el = getElements();
        if (!el.dock) return;
        isExpanded = !isExpanded;
        if (isExpanded) {
            el.body.style.display = 'block';
            if (el.chevron) {
                el.chevron.classList.remove('fa-chevron-up');
                el.chevron.classList.add('fa-chevron-down');
            }
        } else {
            el.body.style.display = 'none';
            if (el.chevron) {
                el.chevron.classList.remove('fa-chevron-down');
                el.chevron.classList.add('fa-chevron-up');
            }
        }
    }

    function setExpanded(expanded) {
        isExpanded = expanded;
        const el = getElements();
        if (!el.body) return;
        if (isExpanded) {
            el.body.style.display = 'block';
            if (el.chevron) {
                el.chevron.classList.remove('fa-chevron-up');
                el.chevron.classList.add('fa-chevron-down');
            }
        } else {
            el.body.style.display = 'none';
            if (el.chevron) {
                el.chevron.classList.remove('fa-chevron-down');
                el.chevron.classList.add('fa-chevron-up');
            }
        }
    }

    function closeWidget() {
        const el = getElements();
        if (el.dock) {
            el.dock.style.opacity = '0';
            el.dock.style.transform = 'translateY(16px)';
            setTimeout(() => {
                el.dock.style.display = 'none';
            }, 250);
        }
        clearInterval(pollInterval);
        clearInterval(timerInterval);
        sessionStorage.removeItem('crypto_active_task_id');
        currentTaskId = null;
    }

    function showTopToast(title, subtitle, durationMs = 3200) {
        const el = getElements();
        if (!el.topToast) return;

        if (toastTimeout) {
            clearTimeout(toastTimeout);
        }

        if (el.toastTitle) el.toastTitle.textContent = title;
        if (el.toastSubtitle) el.toastSubtitle.textContent = subtitle || '';

        el.topToast.style.display = 'flex';
        // Force reflow for animation
        void el.topToast.offsetWidth;
        el.topToast.classList.remove('opacity-0', '-translate-y-4');
        el.topToast.classList.add('opacity-100', 'translate-y-0');

        toastTimeout = setTimeout(() => {
            hideTopToast();
        }, durationMs);
    }

    function hideTopToast() {
        const el = getElements();
        if (!el.topToast) return;
        el.topToast.classList.remove('opacity-100', 'translate-y-0');
        el.topToast.classList.add('opacity-0', '-translate-y-4');
        setTimeout(() => {
            el.topToast.style.display = 'none';
        }, 300);
    }

    function startLiveStopwatch() {
        clearInterval(timerInterval);
        const el = getElements();
        timerInterval = setInterval(() => {
            if (!taskStartTime) return;
            const elapsed = (Date.now() - taskStartTime) / 1000;
            if (el.statTime) {
                el.statTime.textContent = formatTime(elapsed);
            }
        }, 50);
    }

    function trackTask(taskId, options = {}) {
        currentTaskId = taskId;
        completionCallback = options.onComplete || null;
        sessionStorage.setItem('crypto_active_task_id', taskId);

        const el = getElements();
        if (!el.dock) return;

        taskStartTime = Date.now();
        setExpanded(true);

        // Reset display state
        el.dock.style.display = 'block';
        void el.dock.offsetWidth;
        el.dock.style.opacity = '1';
        el.dock.style.transform = 'translateY(0)';

        // Initial labels
        const isEncrypt = options.type !== 'decryption';
        el.title.textContent = isEncrypt ? 'Шифрование сообщения' : 'Дешифрование сообщения';
        el.subtitle.textContent = options.subject || 'Выполняется криптографическая операция...';
        el.icon.innerHTML = '<i class="fa-solid fa-spinner fa-spin text-xs"></i>';
        el.icon.className = 'w-7 h-7 rounded-lg flex items-center justify-center m3-badge-primary flex-shrink-0';
        el.progressBar.style.width = '5%';
        el.progressBar.className = 'h-2 rounded-full bg-[var(--md-color-primary)] transition-all duration-200';
        el.stageLabel.textContent = 'Инициализация параметров...';
        el.percentLabel.textContent = '5%';
        el.statIterations.textContent = '0';
        el.statMaxIterations.textContent = isEncrypt ? '256' : '256';
        el.statCandidates.textContent = '0';
        el.statAlgorithm.textContent = options.algorithm || (isEncrypt ? 'RSA-32K' : 'Определение...');
        el.actions.style.display = 'none';

        startLiveStopwatch();

        // Polling task state
        clearInterval(pollInterval);
        pollInterval = setInterval(async () => {
            try {
                const res = await fetch(`/api/crypto/tasks/${taskId}`);
                if (!res.ok) {
                    if (res.status === 404) {
                        clearInterval(pollInterval);
                        clearInterval(timerInterval);
                    }
                    return;
                }
                const task = await res.json();
                updateTaskView(task);
            } catch (err) {
                console.warn('Crypto tracker poll error:', err);
            }
        }, 120);
    }

    function updateTaskView(task) {
        const el = getElements();
        if (!el.dock) return;

        const isEncrypt = task.type === 'encryption';

        // Update Algorithm and Stage
        if (el.statAlgorithm && task.algorithm) {
            el.statAlgorithm.textContent = task.algorithm;
        }
        if (el.stageLabel && task.stage) {
            el.stageLabel.textContent = task.stage;
        }
        if (el.subtitle && task.subject) {
            el.subtitle.textContent = task.subject;
        }

        // Iterations & Candidates
        if (el.statIterations) {
            el.statIterations.textContent = formatNumber(task.iterations);
        }
        if (el.statMaxIterations && task.max_iterations) {
            el.statMaxIterations.textContent = formatNumber(task.max_iterations);
        }
        if (el.statCandidates) {
            el.statCandidates.textContent = formatNumber(task.candidates);
        }

        // Progress percentage
        const pct = Math.min(100, Math.max(0, task.progress_percent || 0));
        if (el.progressBar) {
            el.progressBar.style.width = `${pct}%`;
        }
        if (el.percentLabel) {
            el.percentLabel.textContent = `${pct}%`;
        }

        // Handle Completed state
        if (task.status === 'completed') {
            clearInterval(pollInterval);
            clearInterval(timerInterval);
            sessionStorage.removeItem('crypto_active_task_id');

            if (el.statTime) {
                el.statTime.textContent = formatTime(task.elapsed_seconds || 0);
            }

            // Green success styles
            el.icon.innerHTML = '<i class="fa-solid fa-check text-xs"></i>';
            el.icon.className = 'w-7 h-7 rounded-lg flex items-center justify-center m3-badge-success flex-shrink-0';
            el.title.textContent = isEncrypt ? 'Шифрование завершено' : 'Дешифрование завершено';
            el.subtitle.textContent = isEncrypt ? 'Сообщение подписано и запечатано' : 'Содержимое успешно расшифровано';
            el.progressBar.style.width = '100%';
            el.progressBar.className = 'h-2 rounded-full bg-emerald-500 transition-all duration-200';
            el.percentLabel.textContent = '100%';
            el.stageLabel.textContent = 'Операция успешно завершена';

            // Reveal action buttons in bottom-right panel
            if (el.actions) {
                el.actions.style.display = 'flex';
            }
            if (el.btnGotoMessage) {
                const targetMsgId = task.message_id || task.result?.message_id;
                if (targetMsgId) {
                    el.btnGotoMessage.href = `/messages/${targetMsgId}`;
                    el.btnGotoMessage.style.display = 'flex';
                } else {
                    el.btnGotoMessage.style.display = 'none';
                }
            }

            // Trigger Top Floating Notification Toast for a couple of seconds
            const toastTitleText = isEncrypt
                ? 'Шифрование успешно завершено!'
                : 'Дешифрование успешно завершено!';
            const toastSubtitleText = isEncrypt
                ? 'Сообщение подписано ЭЦП и готово к отправке / просмотру'
                : 'Содержимое расшифровано, подпись ЭЦП проверена';
            showTopToast(toastTitleText, toastSubtitleText, 3000);

            // Execute custom callback if provided
            if (typeof completionCallback === 'function') {
                try {
                    completionCallback(task);
                } catch (e) {
                    console.error('Completion callback error:', e);
                }
            }
        } else if (task.status === 'error') {
            // Handle Error state
            clearInterval(pollInterval);
            clearInterval(timerInterval);
            sessionStorage.removeItem('crypto_active_task_id');

            el.icon.innerHTML = '<i class="fa-solid fa-triangle-exclamation text-xs"></i>';
            el.icon.className = 'w-7 h-7 rounded-lg flex items-center justify-center m3-badge-error flex-shrink-0';
            el.title.textContent = 'Ошибка операции';
            el.subtitle.textContent = task.error || 'Произошла ошибка при обработке';
            el.progressBar.className = 'h-2 rounded-full bg-red-500';
            el.stageLabel.textContent = task.error || 'Ошибка';

            if (el.actions) {
                el.actions.style.display = 'flex';
            }
            if (el.btnGotoMessage) {
                el.btnGotoMessage.style.display = 'none';
            }
        }
    }

    // Start Decryption task for a specific message ID
    function startDecryption(messageId, onComplete) {
        fetch(`/api/crypto/decrypt_task/${messageId}`, {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
            .then(res => {
                if (!res.ok) throw new Error('Ошибка запуска дешифрования');
                return res.json();
            })
            .then(data => {
                if (data.task_id) {
                    trackTask(data.task_id, {
                        type: 'decryption',
                        messageId: messageId,
                        onComplete: onComplete
                    });
                }
            })
            .catch(err => {
                alert('Не удалось запустить расшифрование: ' + err.message);
            });
    }

    // Intercept compose form submission to run in background with dock tracker
    function initComposeForm() {
        const form = document.getElementById('compose-form');
        if (!form) return;

        form.addEventListener('submit', async function (e) {
            e.preventDefault();

            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i><span>Шифрование и отправка...</span>';
            }

            const formData = new FormData(form);
            const encType = formData.get('encryption_type') || 'RSA';
            const subject = formData.get('subject') || 'Новое сообщение';

            try {
                const res = await fetch('/api/crypto/encrypt_task', {
                    method: 'POST',
                    body: formData,
                });

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    throw new Error(errData.detail || 'Ошибка отправки запроса');
                }

                const data = await res.json();
                if (data.task_id) {
                    // Start progress tracking in the bottom-right dock
                    trackTask(data.task_id, {
                        type: 'encryption',
                        algorithm: encType,
                        subject: subject,
                        onComplete: function (task) {
                            if (submitBtn) {
                                submitBtn.disabled = false;
                                submitBtn.innerHTML = '<i class="fa-solid fa-circle-check mr-2"></i><span>Сообщение отправлено!</span>';
                            }
                            const msgId = (task && task.result && task.result.message_id) || (task && task.message_id);
                            if (msgId) {
                                setTimeout(() => {
                                    window.location.href = `/messages/${msgId}`;
                                }, 600);
                            } else {
                                setTimeout(() => {
                                    window.location.href = '/';
                                }, 600);
                            }
                        }
                    });
                }
            } catch (err) {
                alert('Ошибка при отправке: ' + err.message);
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="fa-solid fa-paper-plane mr-2"></i><span>Отправить</span>';
                }
            }
        });
    }

    // Check for saved active task on page load (smooth cross-page persistence)
    function checkActiveTask() {
        const savedTaskId = sessionStorage.getItem('crypto_active_task_id');
        if (savedTaskId) {
            fetch(`/api/crypto/tasks/${savedTaskId}`)
                .then(r => r.ok ? r.json() : null)
                .then(task => {
                    if (task && task.status === 'running') {
                        trackTask(savedTaskId, {
                            type: task.type,
                            algorithm: task.algorithm,
                            subject: task.subject
                        });
                    } else if (task && task.status === 'completed') {
                        // If it completed recently, show completed state
                        updateTaskView(task);
                        const el = getElements();
                        if (el.dock) el.dock.style.display = 'block';
                    } else {
                        sessionStorage.removeItem('crypto_active_task_id');
                    }
                })
                .catch(() => {
                    sessionStorage.removeItem('crypto_active_task_id');
                });
        }
    }

    // Initialization on DOMContentLoaded
    function init() {
        const el = getElements();
        if (el.header) {
            el.header.addEventListener('click', function (e) {
                // Ignore if clicked on close button
                if (e.target.closest('#crypto-dock-close-btn')) return;
                toggleExpand();
            });
        }
        if (el.closeBtn) {
            el.closeBtn.addEventListener('click', function (e) {
                e.stopPropagation();
                closeWidget();
            });
        }
        if (el.btnCloseDock) {
            el.btnCloseDock.addEventListener('click', function () {
                closeWidget();
            });
        }

        initComposeForm();
        checkActiveTask();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    return {
        trackTask,
        startDecryption,
        closeWidget,
        toggleExpand,
        showTopToast,
        hideTopToast,
    };
})();

// Export globally
window.CryptoTaskTracker = CryptoTaskTracker;
