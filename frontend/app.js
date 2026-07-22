// Global fetch interceptor for unauthorized responses
        const originalFetch = window.fetch;
        window.fetch = async (...args) => {
            const response = await originalFetch(...args);
            if (response.status === 401) {
                // If unauthorized, redirect to admin page which will show login
                window.location.href = '/admin';
            }
            return response;
        };

        // New JavaScript for Logs
        const loadLogsBtn = document.getElementById('loadLogsBtn');
        const refreshLogsBtn = document.getElementById('refreshLogsBtn');
        const clearAllLogsBtn = document.getElementById('clearAllLogsBtn');
        const logsLimit = document.getElementById('logsLimit');
        const logsTableContainer = document.getElementById('logsTableContainer');
        const logsTableBody = document.getElementById('logsTableBody');
        const prevPageBtn = document.getElementById('prevPageBtn');
        const nextPageBtn = document.getElementById('nextPageBtn');
        const pageInfo = document.getElementById('pageInfo');
        const systemModal = document.getElementById('systemModal');
        const systemModalContent = document.getElementById('systemModalContent');
        const closeSystemModalBtn = document.getElementById('closeSystemModalBtn');

        if (closeSystemModalBtn) {
            closeSystemModalBtn.addEventListener('click', () => {
                if (systemModal) systemModal.style.display = 'none';
            });
        }

        function escapeHtml(text) {
            if (typeof text !== 'string') return text;
            return text
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        function showSystemModal(title, contentHtml) {
            const systemModal = document.getElementById('systemModal');
            const systemModalContent = document.getElementById('systemModalContent');
            const titleEl = systemModal ? systemModal.querySelector('h3') : null;
            if (!systemModal || !systemModalContent) return;

            if (titleEl) {
                titleEl.textContent = title;
            }
            systemModalContent.innerHTML = contentHtml;
            systemModal.style.display = 'flex';
        }

        function showAlert(title, message, type = 'info') {
            let contentHtml = '';
            if (type === 'success') {
                contentHtml = `<div style="color: var(--success-color); font-weight: bold; display: flex; align-items: center; gap: 0.5rem; font-size: 1.1rem; margin-bottom: 0.5rem;"><span>✔</span> <span>${title}</span></div>
                               <div style="color: var(--text-primary);">${message}</div>`;
            } else if (type === 'error') {
                contentHtml = `<div style="color: var(--danger-color); font-weight: bold; display: flex; align-items: center; gap: 0.5rem; font-size: 1.1rem; margin-bottom: 0.5rem;"><span>✘</span> <span>${title}</span></div>
                               <div style="color: var(--text-secondary);">${message}</div>`;
            } else {
                contentHtml = `<div style="color: var(--text-primary); font-weight: bold; font-size: 1.1rem; margin-bottom: 0.5rem;">${title}</div>
                               <div style="color: var(--text-secondary);">${message}</div>`;
            }
            showSystemModal(title, contentHtml);
        }

        function showConfirm(title, message) {
            return new Promise((resolve) => {
                const systemModal = document.getElementById('systemModal');
                const systemModalContent = document.getElementById('systemModalContent');
                const titleEl = systemModal ? systemModal.querySelector('h3') : null;
                if (!systemModal || !systemModalContent) {
                    resolve(false);
                    return;
                }

                if (titleEl) {
                    titleEl.textContent = title;
                }

                systemModalContent.innerHTML = `
                    <div style="color: var(--text-secondary); font-size: 1.05rem; margin-bottom: 1.5rem; text-align: left; line-height: 1.4;">
                        ${message}
                    </div>
                    <div style="display: flex; gap: 0.75rem; justify-content: flex-end;">
                        <button id="confirmCancelBtn" class="btn-secondary-outline" style="margin: 0; padding: 8px 16px;">Cancel</button>
                        <button id="confirmOkBtn" class="btn-danger-outline" style="margin: 0; padding: 8px 16px; background-color: var(--danger-color); color: white;">Confirm</button>
                    </div>
                `;

                const closeBtn = document.getElementById('closeSystemModalBtn');
                if (closeBtn) closeBtn.style.display = 'none';

                systemModal.style.display = 'flex';

                const cleanupAndResolve = (val) => {
                    systemModal.style.display = 'none';
                    if (closeBtn) closeBtn.style.display = 'inline-block';
                    resolve(val);
                };

                document.getElementById('confirmCancelBtn').addEventListener('click', () => cleanupAndResolve(false));
                document.getElementById('confirmOkBtn').addEventListener('click', () => cleanupAndResolve(true));

                // Optional: handle ESC and outside click as Cancel
                const handleEsc = (e) => {
                    if (e.key === 'Escape') {
                        window.removeEventListener('keydown', handleEsc);
                        cleanupAndResolve(false);
                    }
                };
                window.addEventListener('keydown', handleEsc);

                const handleOutsideClick = (e) => {
                    if (e.target === systemModal) {
                        systemModal.removeEventListener('click', handleOutsideClick);
                        cleanupAndResolve(false);
                    }
                };
                systemModal.addEventListener('click', handleOutsideClick);
            });
        }

        let currentPage = 1;
        let totalPages = 0;

        loadLogsBtn.addEventListener('click', () => {
            loadLogs(1);
        });

        refreshLogsBtn.addEventListener('click', () => {
            loadLogs(currentPage);
        });

        clearAllLogsBtn.addEventListener('click', () => {
            clearAllLogs();
        });

        prevPageBtn.addEventListener('click', () => {
            if (currentPage > 1) {
                loadLogs(currentPage - 1);
            }
        });

        nextPageBtn.addEventListener('click', () => {
            if (currentPage < totalPages) {
                loadLogs(currentPage + 1);
            }
        });

        async function loadLogs(page) {
            const limit = logsLimit.value;
            const showAllToggle = document.getElementById('logsShowAllToggle');
            const showAll = showAllToggle ? showAllToggle.checked : false;
            try {
                const response = await fetch(`/api/logs?page=${page}&limit=${limit}&show_all=${showAll}`);
                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`HTTP ${response.status}: ${errorText}`);
                }
                const data = await response.json();
                renderLogs(data.logs, data.page, data.total, parseInt(limit));
                loadLogsBtn.style.display = 'none';
                refreshLogsBtn.style.display = 'inline-block';
                clearAllLogsBtn.style.display = 'inline-block';
                clearAllLogsBtn.textContent = showAll ? "Clear All Admins' Logs" : 'Clear My Logs';
                logsTableContainer.style.display = 'block';
            } catch (error) {
                showAlert('Error', 'Error loading logs: ' + error.message, 'error');
            }
        }

        function renderLogs(logs, page, total, limit) {
            logsTableBody.innerHTML = '';
            logs.forEach(log => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${log.id}</td>
                    <td>${new Date(log.timestamp).toLocaleString()}</td>
                    <td>${log.request_method}</td>
                    <td>${log.request_url.substring(0, 50)}...</td>
                    <td>${log.response_status || 'Pending'}</td>
                    <td>${log.duration_ms || '-'}</td>
                    <td style="white-space: nowrap; text-align: center; vertical-align: middle;">
                        <div style="display: inline-flex; gap: 0.5rem; justify-content: center; align-items: center;">
                            <button data-log-id="${log.id}" class="viewLogBtn" style="margin: 0; padding: 4px 10px; font-size: 0.85rem;">View</button>
                            <button data-log-id="${log.id}" class="deleteLogBtn" style="background-color: var(--danger-color); color: white; margin: 0; padding: 4px 10px; font-size: 0.85rem;">Delete</button>
                        </div>
                    </td>
                `;
                logsTableBody.appendChild(row);
            });

            currentPage = page;
            totalPages = Math.ceil(total / limit);
            pageInfo.textContent = `Page ${page} of ${totalPages} (${total} total)`;
            prevPageBtn.disabled = page <= 1;
            nextPageBtn.disabled = page >= totalPages;

            // Add event listeners to buttons
            document.querySelectorAll('.viewLogBtn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const logId = e.target.getAttribute('data-log-id');
                    viewLogDetails(logId, logs);
                });
            });

            document.querySelectorAll('.deleteLogBtn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const logId = e.target.getAttribute('data-log-id');
                    deleteLog(logId);
                });
            });
        }

        function viewLogDetails(logId, logs) {
            const log = logs.find(l => l.id == logId);
            if (log) {
                const jsonStr = JSON.stringify(log, null, 2);
                const escapedJsonStr = escapeHtml(jsonStr);
                const html = `<pre style="margin: 0; white-space: pre-wrap; font-family: monospace; font-size: 0.85rem; color: var(--text-primary); line-height: 1.4;">${escapedJsonStr}</pre>`;
                showSystemModal('Log Details', html);
            }
        }

        async function deleteLog(logId) {
            const confirmed = await showConfirm('Delete Log', `Are you sure you want to delete log ID ${logId}?`);
            if (!confirmed) return;
            try {
                const response = await fetch(`/api/logs/${logId}`, {
                    method: 'DELETE'
                });
                if (response.ok) {
                    showAlert('Success', 'Log deleted successfully', 'success');
                    loadLogs(currentPage); // Refresh
                } else {
                    const data = await response.json();
                    showAlert('Error', 'Error deleting log: ' + (data.message || data.error), 'error');
                }
            } catch (error) {
                showAlert('Error', 'Error deleting log: ' + error.message, 'error');
            }
        }

        async function clearAllLogs() {
            const showAllToggle = document.getElementById('logsShowAllToggle');
            const showAll = showAllToggle ? showAllToggle.checked : false;
            const confirmMsg = showAll 
                ? `Are you sure you want to delete ALL logs for ALL admins? This action cannot be undone.`
                : `Are you sure you want to delete ALL of your own logs? This action cannot be undone.`;
            const confirmed = await showConfirm('Clear All Logs', confirmMsg);
            if (!confirmed) return;
            try {
                const response = await fetch(`/api/logs?show_all=${showAll}`, {
                    method: 'DELETE'
                });
                if (response.ok) {
                    const data = await response.json();
                    showAlert('Success', data.message + ' (' + data.deletedCount + ' logs cleared)', 'success');
                    loadLogs(1); // Reload from page 1 after clearing
                } else {
                    const data = await response.json();
                    showAlert('Error', 'Error clearing logs: ' + (data.message || data.error), 'error');
                }
            } catch (error) {
                showAlert('Error', 'Error clearing logs: ' + error.message, 'error');
            }
        }

        // Auto-reload when Super Admin toggles between "Only Mine" and "Show All"
        const logsShowAllToggle = document.getElementById('logsShowAllToggle');
        if (logsShowAllToggle) {
            logsShowAllToggle.addEventListener('change', () => {
                if (logsTableContainer.style.display === 'block') {
                    loadLogs(1);
                }
            });
        }

        // Statistics Handling
        const loadStatsBtn = document.getElementById('loadStatsBtn');
        const clearStatsBtn = document.getElementById('clearStatsBtn');
        const statsContainer = document.getElementById('statsContainer');
        const statsDimensionButtons = document.getElementById('statsDimensionButtons');
        const apiKeyStatsBody = document.getElementById('apiKeyStatsBody');
        const antigravityStatsBody = document.getElementById('antigravityStatsBody');
        const oauthStatsBody = document.getElementById('oauthStatsBody');
        const userApiStatsBody = document.getElementById('userApiStatsBody');
        const userAntigravityStatsBody = document.getElementById('userAntigravityStatsBody');
        const userOauthStatsBody = document.getElementById('userOauthStatsBody');
        const modelApiStatsBody = document.getElementById('modelApiStatsBody');
        const modelAntigravityStatsBody = document.getElementById('modelAntigravityStatsBody');
        const modelOauthStatsBody = document.getElementById('modelOauthStatsBody');
        const statsSearch = document.getElementById('statsSearch');
        const statsDateFilter = document.getElementById('statsDateFilter');
        const downloadCsvBtn = document.getElementById('downloadCsvBtn');
        const statsFilterArea = document.getElementById('statsFilterArea');
        const statsSummary = document.getElementById('statsSummary');
        const cardErrors429 = document.getElementById('cardErrors429');

        let allLoadedStats = [];
        let showOnly429 = false;
        let showOnlyZeroSuccess = false;

        loadStatsBtn.addEventListener('click', loadStatistics);
        clearStatsBtn.addEventListener('click', clearStatistics);

        const statsShowAllToggle = document.getElementById('statsShowAllToggle');
        const trendsShowAllToggle = document.getElementById('trendsShowAllToggle');

        statsShowAllToggle.addEventListener('change', (e) => {
            trendsShowAllToggle.checked = e.target.checked;
            loadStatistics();
        });

        trendsShowAllToggle.addEventListener('change', (e) => {
            statsShowAllToggle.checked = e.target.checked;
            loadTrends();
        });

        // Trends Handling
        let requestsChart = null;
        let errorsChart = null;

        async function loadTrends() {
            try {
                const showAll = document.getElementById('trendsShowAllToggle').checked;
                const url = showAll ? `/api/statistics/trends?all=true&t=${Date.now()}` : `/api/statistics/trends?t=${Date.now()}`;
                const response = await fetch(url);
                if (!response.ok) throw new Error('Failed to load trends');
                const data = await response.json();
                renderTrends(data);
            } catch (error) {
                console.error('Error loading trends:', error);
            }
        }

        function renderTrends(data) {
            const labels = data.map(d => d.usage_date);
            const totalRequests = data.map(d => d.total_requests);
            const totalSuccess = data.map(d => d.total_success);
            const total429 = data.map(d => d.total_429);

            if (requestsChart) requestsChart.destroy();
            if (errorsChart) errorsChart.destroy();

            const ctxReq = document.getElementById('requestsChart').getContext('2d');
            requestsChart = new Chart(ctxReq, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Total Requests',
                            data: totalRequests,
                            borderColor: '#4299e1',
                            backgroundColor: 'rgba(66, 153, 225, 0.1)',
                            fill: true,
                            tension: 0.3
                        },
                        {
                            label: 'Successful Requests',
                            data: totalSuccess,
                            borderColor: '#48bb78',
                            backgroundColor: 'transparent',
                            tension: 0.3
                        }
                    ]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: { display: true, text: 'Request Volume (30 Days)' }
                    },
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });

            const ctxErr = document.getElementById('errorsChart').getContext('2d');
            errorsChart = new Chart(ctxErr, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: '429 Errors',
                            data: total429,
                            backgroundColor: '#f56565'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: { display: true, text: 'Rate Limit Errors (429)' }
                    },
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        }

        // Dimension switching logic
        document.querySelectorAll('.dimension-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation(); // Prevent bubble up to main tab logic
                const dim = btn.getAttribute('data-dim');
                document.querySelectorAll('.dimension-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                document.querySelectorAll('.stats-dimension-content').forEach(content => {
                    content.style.display = 'none';
                });
                document.getElementById(`stats-${dim}`).style.display = 'block';
            });
        });

        function maskKey(key) {
            if (!key) return '-';
            if (key.includes(':')) {
                const parts = key.split(':');
                const email = parts[4] || '';
                const refreshToken = parts[2] || '';
                const maskedToken = refreshToken ? refreshToken.substring(0, 4) + '...' + refreshToken.substring(refreshToken.length - 4) : '';
                return email ? `${email} (${maskedToken})` : `OAuth Key (${maskedToken})`;
            }
            if (key.length <= 12) return key;
            return key.substring(0, 6) + '...' + key.substring(key.length - 6);
        }

        async function loadStatistics() {
            try {
                const showAll = document.getElementById('statsShowAllToggle').checked;
                const url = showAll ? `/api/statistics?all=true&t=${Date.now()}` : `/api/statistics?t=${Date.now()}`;
                const response = await fetch(url);
                if (!response.ok) throw new Error('Failed to load statistics');
                allLoadedStats = await response.json();
                applyFiltersAndRender();
                statsContainer.style.display = 'block';
                statsDimensionButtons.style.display = 'flex';
                statsFilterArea.style.display = 'block';
                statsSummary.style.display = 'grid';
            } catch (error) {
                showAlert('Error', 'Error loading statistics: ' + error.message, 'error');
            }
        }

        function applyFiltersAndRender() {
            const searchTerm = statsSearch.value.toLowerCase();
            const dateRange = statsDateFilter.value;
            
            let filtered = allLoadedStats;

            // Date Filter
            if (dateRange !== 'all') {
                const now = new Date();
                const todayStr = now.toLocaleDateString('en-CA', { timeZone: 'Asia/Hong_Kong' });
                
                if (dateRange === 'today') {
                    filtered = filtered.filter(s => s.usage_date === todayStr);
                } else {
                    const days = dateRange === '7d' ? 7 : 30;
                    const cutoff = new Date();
                    cutoff.setDate(cutoff.getDate() - days);
                    const cutoffStr = cutoff.toLocaleDateString('en-CA', { timeZone: 'Asia/Hong_Kong' });
                    filtered = filtered.filter(s => s.usage_date >= cutoffStr);
                }
            }

            // Search Filter
            if (searchTerm) {
                filtered = filtered.filter(s => 
                    (s.user_access_token && s.user_access_token.toLowerCase().includes(searchTerm)) ||
                    (s.model && s.model.toLowerCase().includes(searchTerm)) ||
                    (s.raw_key && s.raw_key.toLowerCase().includes(searchTerm))
                );
            }

            // The summary cards should reflect the base "filtered by date/search" data
            updateSummaryCards(filtered);

            // Pass the base filtered data to renderStatistics. 
            // Aggregated views (By Key) will handle UI toggles after aggregation.
            // Row-based views (By User, By Model) will handle them during row generation.
            renderStatistics(filtered);
        }

        function updateSummaryCards(stats) {
            const totalRequests = stats.reduce((sum, s) => sum + s.request_count, 0);
            const totalSuccess = stats.reduce((sum, s) => sum + s.success_count, 0);
            const total429 = stats.reduce((sum, s) => sum + s.error_429_count, 0);
            const totalPromptTokens = stats.reduce((sum, s) => sum + (s.prompt_tokens || 0), 0);
            const totalCompletionTokens = stats.reduce((sum, s) => sum + (s.completion_tokens || 0), 0);
            const totalCachedTokens = stats.reduce((sum, s) => sum + (s.cached_tokens || 0), 0);
            const totalSavedTokens = stats.reduce((sum, s) => sum + (s.saved_tokens || 0), 0);
            const totalSaved = totalCachedTokens + totalSavedTokens;
            
            const successRate = totalRequests > 0 
                ? ((totalSuccess / totalRequests) * 100).toFixed(1) + '%' 
                : '0%';

            // Calculate zero success keys (aggregated combinations)
            // We need to re-aggregate briefly to count correctly based on current filters
            const keyCombinations = {};
            stats.forEach(s => {
                const id = `${s.raw_key}|${s.mode}|${s.model}`;
                if (!keyCombinations[id]) keyCombinations[id] = { requests: 0, success: 0 };
                keyCombinations[id].requests += s.request_count;
                keyCombinations[id].success += s.success_count;
            });
            const zeroSuccessCount = Object.values(keyCombinations).filter(k => k.requests > 0 && k.success === 0).length;

            document.getElementById('sumTotalRequests').textContent = totalRequests.toLocaleString();
            document.getElementById('sumSuccessRate').textContent = successRate;
            document.getElementById('sumErrors429').textContent = total429.toLocaleString();
            document.getElementById('sumZeroSuccess').textContent = zeroSuccessCount.toLocaleString();
            document.getElementById('sumPromptTokensCard').textContent = formatTokens(totalPromptTokens);
            document.getElementById('sumCompletionTokensCard').textContent = formatTokens(totalCompletionTokens);
            document.getElementById('sumCachedTokensCard').textContent = formatTokens(totalCachedTokens);
            document.getElementById('sumPrunedTokensCard').textContent = formatTokens(totalSavedTokens);
            
            const errEl = document.getElementById('sumErrors429');
            if (total429 > 0) errEl.classList.add('danger');
            else errEl.classList.remove('danger');

            const zeroEl = document.getElementById('sumZeroSuccess');
            if (zeroSuccessCount > 0) zeroEl.classList.add('danger');
            else zeroEl.classList.remove('danger');
        }

        statsSearch.addEventListener('input', applyFiltersAndRender);
        statsDateFilter.addEventListener('change', applyFiltersAndRender);

        cardErrors429.addEventListener('click', () => {
            showOnly429 = !showOnly429;
            // Clear other filter for clarity
            if (showOnly429) {
                showOnlyZeroSuccess = false;
                document.getElementById('cardZeroSuccess').classList.remove('active-filter');
                cardErrors429.classList.add('active-filter');
            } else {
                cardErrors429.classList.remove('active-filter');
            }
            applyFiltersAndRender();
        });

        document.getElementById('cardZeroSuccess').addEventListener('click', () => {
            showOnlyZeroSuccess = !showOnlyZeroSuccess;
            // Clear other filter for clarity
            if (showOnlyZeroSuccess) {
                showOnly429 = false;
                cardErrors429.classList.remove('active-filter');
                document.getElementById('cardZeroSuccess').classList.add('active-filter');
            } else {
                document.getElementById('cardZeroSuccess').classList.remove('active-filter');
            }
            applyFiltersAndRender();
        });

        downloadCsvBtn.addEventListener('click', () => {
            if (allLoadedStats.length === 0) return;
            
            const headers = ['Key Type', 'Key', 'Date', 'User Token', 'Mode', 'Model', 'Requests', 'Success', '429 Errors'];
            const rows = allLoadedStats.map(s => [
                s.key_type,
                s.raw_key,
                s.usage_date,
                s.user_access_token,
                s.mode,
                s.model,
                s.request_count,
                s.success_count,
                s.error_429_count
            ]);

            const csvContent = [
                headers.join(','),
                ...rows.map(r => r.map(v => `"${v}"`).join(','))
            ].join('\n');

            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', `gemini_stats_${new Date().toISOString().split('T')[0]}.csv`);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });

        function formatTokens(num) {
            if (!num) return '0';
            if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
            if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
            return num.toString();
        }

        function renderStatistics(stats) {
            apiKeyStatsBody.innerHTML = '';
            antigravityStatsBody.innerHTML = '';
            oauthStatsBody.innerHTML = '';
            userApiStatsBody.innerHTML = '';
            userAntigravityStatsBody.innerHTML = '';
            userOauthStatsBody.innerHTML = '';
            modelApiStatsBody.innerHTML = '';
            modelAntigravityStatsBody.innerHTML = '';
            modelOauthStatsBody.innerHTML = '';

            // Cleaner aggregation logic
            const buildAgg = (type) => {
                const agg = {};
                stats.forEach(s => {
                    const kType = s.key_type || 'api_key';
                    if (kType === type) {
                        const key = s.raw_key;
                        const mode = s.mode || 'unknown';
                        const model = s.model || 'unknown';
                        const id = `${key}|${mode}|${model}`;
                        if (!agg[id]) agg[id] = { requests: 0, success: 0, errors429: 0, promptTokens: 0, completionTokens: 0, cachedTokens: 0, savedTokens: 0, raw_key: key, mode, model, token: s.user_access_token };
                        agg[id].requests += s.request_count;
                        agg[id].success += s.success_count;
                        agg[id].errors429 += s.error_429_count;
                        agg[id].promptTokens += (s.prompt_tokens || 0);
                        agg[id].completionTokens += (s.completion_tokens || 0);
                        agg[id].cachedTokens += (s.cached_tokens || 0);
                        agg[id].savedTokens += (s.saved_tokens || 0);
                    }
                });
                let list = Object.values(agg);
                if (showOnly429) list = list.filter(item => item.errors429 > 0);
                if (showOnlyZeroSuccess) list = list.filter(item => item.requests > 0 && item.success === 0);
                return list;
            };

            const apiKeyAggListFinal = buildAgg('api_key');
            const antigravityKeyAggListFinal = buildAgg('antigravity');
            const oauthKeyAggListFinal = buildAgg('oauth');

            const createKeyRow = (data, keyType) => {
                const isZeroSuccess = data.requests > 0 && data.success === 0;
                const successRate = data.requests > 0 
                    ? ((data.success / data.requests) * 100).toFixed(1) + '%' 
                    : '0%';
                const modelName = (data.model || 'Unknown').replace(/^models\//, '');
                
                const rowStyle = isZeroSuccess ? 'background-color: var(--danger-color-light);' : '';
                const rateStyle = isZeroSuccess ? 'color: var(--danger-color); font-weight: bold;' : '';
                
                const tokenParam = data.token ? `'${data.token}'` : 'null';
                const keyParam = `'${data.raw_key}'`;
                const modelParam = `'${data.model}'`;

                const isOAuth = keyType === 'oauth' ? 'true' : 'false';
                const isAntigravity = keyType === 'antigravity' ? 'true' : 'false';

                // Badge colors for mode
                const badgeBg = 'var(--code-bg)'; // Use theme-aware code background
                const badgeColor = 'var(--text-primary)';

                return `
                    <tr style="${rowStyle}">
                        <td style="padding: 8px; border: 1px solid var(--border-color); font-family: monospace; word-break: break-all;">${data.raw_key}</td>
                        <td style="padding: 8px; border: 1px solid var(--border-color); text-align: center;"><span style="padding: 2px 6px; border-radius: 4px; background: ${badgeBg}; color: ${badgeColor}; font-size: 0.8rem; border: 1px solid var(--border-color);">${data.mode}</span></td>
                        <td style="padding: 8px; border: 1px solid var(--border-color); font-size: 0.9rem;">${modelName}</td>
                        <td style="padding: 8px; border: 1px solid var(--border-color); text-align: center;">${data.requests}</td>
                        <td style="padding: 8px; border: 1px solid var(--border-color); text-align: center; ${rateStyle}">${successRate}</td>
                        <td style="padding: 8px; border: 1px solid var(--border-color); text-align: center; color: ${data.errors429 > 0 ? 'var(--danger-color)' : 'inherit'}">${data.errors429}</td>
                        <td style="padding: 8px; border: 1px solid var(--border-color); text-align: center;">${formatTokens(data.promptTokens)} / ${formatTokens(data.completionTokens)}</td>
                        <td style="padding: 8px; border: 1px solid var(--border-color); text-align: center; color: #2f855a; font-weight: 600;">
                            ⚡️ ${formatTokens(data.cachedTokens || 0)} <span style="color: #805ad5; font-size: 0.85rem;">/ ✨ ${formatTokens(data.savedTokens || 0)}</span>
                        </td>
                        <td style="padding: 8px; border: 1px solid var(--border-color); text-align: center;">
                            <button class="btn-secondary-outline" onclick="diagnoseKeyFromStats(${tokenParam}, ${keyParam}, ${isOAuth}, ${isAntigravity}, ${modelParam}, this)">Test Key</button>
                        </td>
                    </tr>
                `;
            };

            // Sorting Logic
            const sortStats = (list, primaryKey = 'displayName') => {
                return list.sort((a, b) => {
                    // 1. Date Descending (if available)
                    if (a.usage_date && b.usage_date && a.usage_date !== b.usage_date) {
                        return b.usage_date.localeCompare(a.usage_date);
                    }
                    // 2. DisplayName / Key Ascending
                    const valA = a[primaryKey] || '';
                    const valB = b[primaryKey] || '';
                    if (valA !== valB) {
                        return valA.localeCompare(valB);
                    }
                    // 3. Model Ascending (if applicable)
                    const modA = a.model || '';
                    const modB = b.model || '';
                    return modA.localeCompare(modB);
                });
            };

            const apiKeyStatsSorted = sortStats(apiKeyAggListFinal, 'raw_key');
            const antigravityKeyStatsSorted = sortStats(antigravityKeyAggListFinal, 'raw_key');
            const oauthKeyStatsSorted = sortStats(oauthKeyAggListFinal, 'raw_key');

            apiKeyStatsSorted.forEach(s => { apiKeyStatsBody.innerHTML += createKeyRow(s, 'api_key'); });
            antigravityKeyStatsSorted.forEach(s => { antigravityStatsBody.innerHTML += createKeyRow(s, 'antigravity'); });
            oauthKeyStatsSorted.forEach(s => { oauthStatsBody.innerHTML += createKeyRow(s, 'oauth'); });

            if (apiKeyStatsSorted.length === 0) apiKeyStatsBody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 20px;">No API Key statistics found.</td></tr>';
            if (antigravityKeyStatsSorted.length === 0) antigravityStatsBody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 20px;">No Antigravity statistics found.</td></tr>';
            if (oauthKeyStatsSorted.length === 0) oauthStatsBody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 20px;">No OAuth statistics found.</td></tr>';

            document.getElementById('apiKeyCount').textContent = apiKeyStatsSorted.length;
            const antigravityCountEl = document.getElementById('antigravityCount');
            if (antigravityCountEl) antigravityCountEl.textContent = antigravityKeyStatsSorted.length;
            document.getElementById('oauthCount').textContent = oauthKeyStatsSorted.length;

            // Helper to render aggregate tables
            const renderAggTable = (aggData, targetBody, countElId, emptyMsg, extraCols = []) => {
                const list = sortStats(Object.values(aggData));
                const countEl = document.getElementById(countElId);
                if (countEl) countEl.textContent = list.length;

                const colSpan = 6 + extraCols.length;
                if (list.length === 0) {
                    targetBody.innerHTML = `<tr><td colspan="${colSpan}" style="text-align: center; padding: 20px;">${emptyMsg}</td></tr>`;
                    return;
                }
                list.forEach((data) => {
                    const rate = data.requests > 0 ? ((data.success / data.requests) * 100).toFixed(1) + '%' : '0%';
                    
                    let cells = '';
                    // First column is always displayName (User token or Model name)
                    cells += `<td style="padding: 8px; border: 1px solid var(--border-color); font-family: monospace; word-break: break-all; font-size: 0.9rem;">${(data.displayName || '').replace(/^models\//, '')}</td>`;
                    
                    // Middle dynamic columns
                    extraCols.forEach(col => {
                        const rawVal = (data[col] || '');
                        const displayVal = rawVal.replace(/^models\//, '');
                        
                        if (col === 'mode') {
                            cells += `<td style="padding: 8px; border: 1px solid var(--border-color); text-align: center;"><span style="padding: 2px 6px; border-radius: 4px; background: var(--code-bg); color: var(--text-primary); font-size: 0.8rem; border: 1px solid var(--border-color);">${displayVal}</span></td>`;
                        } else if (col === 'usage_date') {
                            cells += `<td style="padding: 8px; border: 1px solid var(--border-color); white-space: nowrap;">${displayVal}</td>`;
                        } else {
                            cells += `<td style="padding: 8px; border: 1px solid var(--border-color); text-align: left; font-size: 0.9rem;">${displayVal}</td>`;
                        }
                    });

                    // Final metrics columns
                    cells += `<td style="padding: 8px; border: 1px solid var(--border-color); text-align: center;">${data.requests}</td>`;
                    cells += `<td style="padding: 8px; border: 1px solid var(--border-color); text-align: center;">${rate}</td>`;
                    cells += `<td style="padding: 8px; border: 1px solid var(--border-color); text-align: center; color: ${data.errors429 > 0 ? 'var(--danger-color)' : 'inherit'}">${data.errors429}</td>`;
                    cells += `<td style="padding: 8px; border: 1px solid var(--border-color); text-align: center;">${formatTokens(data.promptTokens)} / ${formatTokens(data.completionTokens)}</td>`;
                    cells += `<td style="padding: 8px; border: 1px solid var(--border-color); text-align: center; color: #2f855a; font-weight: 600;">
                        ⚡ ${formatTokens(data.cachedTokens || 0)} <span style="color: #805ad5; font-size: 0.85rem;">/ ✨ ${formatTokens(data.savedTokens || 0)}</span>
                    </td>`;

                    targetBody.innerHTML += `<tr>${cells}</tr>`;
                });
            };

            // --- By User (Aggregate Split) ---
            const userApiAgg = {};
            const userAntigravityAgg = {};
            const userOauthAgg = {};
            
            let userStats = stats;
            if (showOnly429) userStats = userStats.filter(s => s.error_429_count > 0);
            if (showOnlyZeroSuccess) userStats = userStats.filter(s => s.request_count > 0 && s.success_count === 0);

            userStats.forEach(s => {
                const user = s.user_access_token;
                const mode = s.mode || 'unknown';
                const model = s.model || 'unknown';
                const date = s.usage_date;
                const compositeKey = `${user}|${mode}|${model}|${date}`;
                
                let agg = userApiAgg;
                const kType = s.key_type || 'api_key';
                if (kType === 'antigravity') {
                    agg = userAntigravityAgg;
                } else if (kType === 'oauth') {
                    agg = userOauthAgg;
                }

                if (!agg[compositeKey]) {
                    agg[compositeKey] = { 
                        requests: 0, success: 0, errors429: 0, promptTokens: 0, completionTokens: 0, cachedTokens: 0, savedTokens: 0,
                        displayName: user, mode: mode, model: model, usage_date: date
                    };
                }
                agg[compositeKey].requests += s.request_count;
                agg[compositeKey].success += s.success_count;
                agg[compositeKey].errors429 += s.error_429_count;
                agg[compositeKey].promptTokens += (s.prompt_tokens || 0);
                agg[compositeKey].completionTokens += (s.completion_tokens || 0);
                agg[compositeKey].cachedTokens += (s.cached_tokens || 0);
                agg[compositeKey].savedTokens += (s.saved_tokens || 0);
            });

            renderAggTable(userApiAgg, userApiStatsBody, 'userApiKeyCount', 'No user API Key usage found.', ['usage_date', 'mode', 'model']);
            renderAggTable(userAntigravityAgg, userAntigravityStatsBody, 'userAntigravityCount', 'No user Antigravity usage found.', ['usage_date', 'mode', 'model']);
            renderAggTable(userOauthAgg, userOauthStatsBody, 'userOauthCount', 'No user OAuth usage found.', ['usage_date', 'mode', 'model']);

            // --- By Model (Aggregate Split) ---
            const modelApiAgg = {};
            const modelAntigravityAgg = {};
            const modelOauthAgg = {};

            let modelStats = stats;
            if (showOnly429) modelStats = modelStats.filter(s => s.error_429_count > 0);
            if (showOnlyZeroSuccess) modelStats = modelStats.filter(s => s.request_count > 0 && s.success_count === 0);

            modelStats.forEach(s => {
                const model = s.model || 'Unknown';
                const mode = s.mode || 'unknown';
                const date = s.usage_date;
                const compositeKey = `${model}|${mode}|${date}`;

                let agg = modelApiAgg;
                const kType = s.key_type || 'api_key';
                if (kType === 'antigravity') {
                    agg = modelAntigravityAgg;
                } else if (kType === 'oauth') {
                    agg = modelOauthAgg;
                }

                if (!agg[compositeKey]) {
                    agg[compositeKey] = { 
                        requests: 0, success: 0, errors429: 0, promptTokens: 0, completionTokens: 0, cachedTokens: 0, savedTokens: 0,
                        displayName: model, mode: mode, usage_date: date
                    };
                }
                agg[compositeKey].requests += s.request_count;
                agg[compositeKey].success += s.success_count;
                agg[compositeKey].errors429 += s.error_429_count;
                agg[compositeKey].promptTokens += (s.prompt_tokens || 0);
                agg[compositeKey].completionTokens += (s.completion_tokens || 0);
                agg[compositeKey].cachedTokens += (s.cached_tokens || 0);
                agg[compositeKey].savedTokens += (s.saved_tokens || 0);
            });

            renderAggTable(modelApiAgg, modelApiStatsBody, 'modelApiKeyCount', 'No API Key usage found by model.', ['usage_date', 'mode']);
            renderAggTable(modelAntigravityAgg, modelAntigravityStatsBody, 'modelAntigravityCount', 'No Antigravity usage found by model.', ['usage_date', 'mode']);
            renderAggTable(modelOauthAgg, modelOauthStatsBody, 'modelOauthCount', 'No OAuth usage found by model.', ['usage_date', 'mode']);
        }

        async function clearStatistics() {
            const showAll = document.getElementById('statsShowAllToggle').checked;
            const msg = showAll 
                ? 'Are you sure you want to clear ALL usage statistics for ALL admins?' 
                : 'Are you sure you want to clear YOUR usage statistics?';
            const confirmed = await showConfirm('Clear Statistics', msg);
            if (!confirmed) return;
            try {
                const url = showAll ? '/api/statistics?all=true' : '/api/statistics';
                const response = await fetch(url, { method: 'DELETE' });
                if (!response.ok) throw new Error('Failed to clear statistics');
                showAlert('Success', 'Statistics cleared successfully', 'success');
                loadStatistics();
            } catch (error) {
                showAlert('Error', 'Error clearing statistics: ' + error.message, 'error');
            }
        }
        // Button state helpers for loading feedback
        function setButtonLoading(button, isLoading, text) {
            if (!button) return;
            if (isLoading) {
                button.disabled = true;
                button.dataset.originalText = button.innerHTML;
                button.innerHTML = `<span class="spinner"></span> ` + text;
            } else {
                button.disabled = false;
                if (button.dataset.originalText) {
                    button.innerHTML = button.dataset.originalText;
                }
            }
        }

        // Tab Switching with hash-persistence and dynamic container widening
        const tabButtons = document.querySelectorAll('.tab-button');
        const tabContents = document.querySelectorAll('.tab-content');

        function switchTab(tabId) {
            // Hide all tab contents
            tabContents.forEach(content => content.classList.remove('active'));

            // Remove active class from all buttons
            tabButtons.forEach(btn => btn.classList.remove('active'));

            // Show the selected tab and activate button
            const targetEl = document.getElementById(tabId);
            if (targetEl) {
                targetEl.classList.add('active');
            }
            
            const btnEl = document.querySelector(`.tab-button[data-tab="${tabId}"]`);
            if (btnEl) {
                btnEl.classList.add('active');
            }

            // Update URL hash without jumping
            history.replaceState(null, null, '#' + tabId);

            // Widen container for wide data-heavy tabs
            const container = document.querySelector('.container');
            if (['logs-tab', 'stats-tab', 'trends-tab', 'admins-tab'].includes(tabId)) {
                container.classList.add('wide');
            } else {
                container.classList.remove('wide');
            }

            // Load tab-specific data
            if (tabId === 'trends-tab') {
                loadTrends();
            } else if (tabId === 'stats-tab') {
                loadStatistics();
            } else if (tabId === 'admins-tab') {
                loadAdmins();
            } else if (tabId === 'antigravity-tab') {
                loadTokenDropdown('antigravity');
            } else if (tabId === 'oauth-tab') {
                loadTokenDropdown('oauth');
            } else if (tabId === 'credentials-tab') {
                loadTokenDropdown('api');
            }
        }

        tabButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                const targetTab = button.getAttribute('data-tab');
                switchTab(targetTab);
            });
        });

        // Handle initial tab based on URL hash
        window.addEventListener('DOMContentLoaded', () => {
            const hash = window.location.hash.replace('#', '');
            const defaultTab = 'credentials-tab';
            let activeTabId = defaultTab;

            if (hash) {
                const matchingButton = document.querySelector(`.tab-button[data-tab="${hash}"]`);
                if (matchingButton) {
                    activeTabId = hash;
                }
            }
            switchTab(activeTabId);
        });

        // Modal accessibility (Escape key & Click outside)
        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (systemModal && systemModal.style.display === 'flex') {
                    systemModal.style.display = 'none';
                }
            }
        });

        if (systemModal) {
            systemModal.addEventListener('click', (e) => {
                if (e.target === systemModal) {
                    systemModal.style.display = 'none';
                }
            });
        }

        const form = document.getElementById('keyForm');
        const resultDiv = document.getElementById('result');
        const accessTokenInput = document.getElementById('accessToken');
        const apiKeysTextarea = document.getElementById('apiKeys');

        async function resetKeyHealth(token, key, isOAuth) {
            const confirmed = await showConfirm('Reset Key Health', `Reset health status for this ${isOAuth ? 'OAuth credential' : 'API key'}?`);
            if (!confirmed) return;
            try {
                const response = await fetch('/api/reset-key-health', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ access_token: token, key, isOAuth })
                });
                if (response.ok) {
                    updateKeyHealth(token, isOAuth ? 'oauth' : 'api');
                    showAlert('Success', 'Key health status reset successfully!', 'success');
                } else {
                    const data = await response.json();
                    showAlert('Reset Failed', data.error || 'Failed to reset health', 'error');
                }
            } catch (e) {
                showAlert('Error', e.message, 'error');
            }
        }

        async function diagnoseKey(token, key, isOAuth, button, isAntigravity = false) {
            const originalText = button.textContent;
            button.textContent = 'Testing...';
            button.disabled = true;

            showSystemModal('Key Diagnostics', '<div style="color: var(--text-secondary);">Running diagnostics...</div>');
            
            try {
                const response = await fetch('/api/key-diagnose', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ access_token: token, key, isOAuth, isAntigravity })
                });
                const data = await response.json();
                
                if (response.ok && data.success) {
                    let html = `<div style="color: var(--success-color); font-weight: bold; margin-bottom: 8px;">Diagnosis Success!</div>
                                <div style="color: var(--text-secondary);">Latency: ${data.latency}ms<br>Status: ${data.status} (Healthy)</div>`;
                    if (data.greeting) {
                        const displayName = data.model ? data.model.replace(/^models\//, '') : 'Gemini 3.5 Flash';
                        html += `<div style="margin-top: 12px; padding: 8px; background: var(--code-bg); border-radius: 4px; font-family: monospace;">${displayName} Response:<br>"${data.greeting}"</div>`;
                    }
                    showSystemModal('Key Diagnostics', html);
                    updateKeyHealth(token, isAntigravity ? 'antigravity' : (isOAuth ? 'oauth' : 'api'));
                } else {
                    const html = `<div style="color: var(--danger-color); font-weight: bold;">Diagnosis Failed!</div>
                                  <div style="color: var(--text-secondary); margin-top: 4px;">Status: ${data.status || 'Error'}</div>
                                  <div style="color: var(--text-secondary); margin-top: 4px;">Details: ${data.error || 'Connection failed'}</div>`;
                    showSystemModal('Diagnosis Failed', html);
                    updateKeyHealth(token, isAntigravity ? 'antigravity' : (isOAuth ? 'oauth' : 'api'));
                }
            } catch (e) {
                showSystemModal('Diagnosis Failed', `<div style="color: var(--danger-color); font-weight: bold;">Error:</div><div style="color: var(--text-secondary); margin-top: 4px;">${e.message}</div>`);
            } finally {
                button.textContent = originalText;
                button.disabled = false;
            }
        }

        async function showModels(token, key, isOAuth, button, isAntigravity = false) {
            const originalText = button.textContent;
            button.textContent = 'Querying...';
            button.disabled = true;

            showSystemModal('Supported Google Models', '<div style="color: var(--text-secondary);">Querying Google API for available models...</div>');

            try {
                const response = await fetch('/api/key-models', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ access_token: token, key, isOAuth, isAntigravity })
                });
                const data = await response.json();
                
                if (response.ok && data.models) {
                    const models = data.models || [];
                    if (models.length === 0) {
                        showSystemModal('Supported Google Models', `<div style="color: var(--danger-color);">No supported models found.${data.debug ? `<br><small>${data.debug}</small>` : ''}</div>`);
                    } else {
                        const html = models.map(m => {
                            return `<div style="padding: 6px 0; border-bottom: 1px solid var(--border-color); color: var(--success-color); display: flex; align-items: center; gap: 0.5rem;"><span>✔</span> <span>${m}</span></div>`;
                        }).join('');
                        showSystemModal('Supported Google Models', html);
                    }
                } else {
                    showSystemModal('Query Failed', `<div style="color: var(--danger-color); font-weight: bold;">Query Failed:</div><div style="color: var(--text-secondary); margin-top: 4px;">${data.error || 'Connection failed'}</div>`);
                }
            } catch (e) {
                showSystemModal('Query Failed', `<div style="color: var(--danger-color); font-weight: bold;">Error querying models:</div><div style="color: var(--text-secondary); margin-top: 4px;">${e.message}</div>`);
            } finally {
                button.textContent = originalText;
                button.disabled = false;
            }
        }

        async function diagnoseKeyFromStats(token, key, isOAuth, model, button) {
            if (!token) {
                showAlert('Diagnosis Failed', 'Missing user access token for this key.', 'error');
                return;
            }
            const modelsModal = document.getElementById('modelsModal');
            const modelsModalContent = document.getElementById('modelsModalContent');
            if (!modelsModal || !modelsModalContent) return;

            const originalText = button.textContent;
            button.textContent = 'Testing...';
            button.disabled = true;

            const displayModel = model ? model.replace(/^models\//, '') : 'Default Model';
            modelsModalContent.innerHTML = `<div style="color: var(--text-secondary);">Running diagnostics for model <strong>${displayModel}</strong>...</div>`;
            modelsModal.style.display = 'flex';
            
            try {
                const response = await fetch('/api/key-diagnose', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ access_token: token, key, isOAuth, model })
                });
                const data = await response.json();
                
                if (response.ok && data.success) {
                    let html = `<div style="color: var(--success-color); font-weight: bold; margin-bottom: 8px;">Diagnosis Success!</div>
                                <div style="color: var(--text-secondary); margin-bottom: 8px;">
                                    Model Tested: <strong>${displayModel}</strong><br>
                                    Latency: ${data.latency}ms<br>
                                    Status: ${data.status} (Healthy)
                                </div>`;
                    if (data.greeting) {
                        const displayName = data.model ? data.model.replace(/^models\//, '') : displayModel;
                        html += `<div style="margin-top: 12px; padding: 10px; background: var(--code-bg); border-radius: 4px; font-family: monospace;">
                                    <span style="color: var(--text-secondary); font-size: 0.85rem;">${displayName} Response:</span><br>
                                    <span style="color: var(--text-primary);">"${data.greeting}"</span>
                                 </div>`;
                    }
                    modelsModalContent.innerHTML = html;
                } else {
                    modelsModalContent.innerHTML = `<div style="color: var(--danger-color); font-weight: bold;">Diagnosis Failed!</div>
                                                   <div style="color: var(--text-secondary); margin-top: 4px;">Model Tested: <strong>${displayModel}</strong></div>
                                                   <div style="color: var(--text-secondary); margin-top: 4px;">Status: ${data.status || 'Error'}</div>
                                                   <div style="color: var(--text-secondary); margin-top: 4px;">Details: ${data.error || 'Connection failed'}</div>`;
                }
            } catch (e) {
                modelsModalContent.innerHTML = `<div style="color: var(--danger-color); font-weight: bold;">Error:</div><div style="color: var(--text-secondary); margin-top: 4px;">${e.message}</div>`;
            } finally {
                button.textContent = originalText;
                button.disabled = false;
            }
        }

        async function updateKeyHealth(token, type) {
            const isOAuth = type === 'oauth' || type === true;
            const isAntigravity = type === 'antigravity';

            let healthContainer = document.getElementById('api-key-health');
            let listContainer = document.getElementById('api-key-status-list');

            if (isAntigravity) {
                healthContainer = document.getElementById('agy-key-health');
                listContainer = document.getElementById('agy-key-status-list');
            } else if (isOAuth) {
                healthContainer = document.getElementById('oauth-key-health');
                listContainer = document.getElementById('oauth-key-status-list');
            }
            
            try {
                const res = await fetch(`/api/key-status?access_token=${encodeURIComponent(token)}`);
                if (!res.ok) {
                    if (healthContainer) healthContainer.style.display = 'none';
                    return;
                }
                const data = await res.json();
                let keys = data.api_keys;
                let states = data.key_states;

                if (isAntigravity) {
                    keys = data.antigravity_credentials;
                    states = data.antigravity_key_states;
                } else if (isOAuth) {
                    keys = data.oauth_credentials;
                    states = data.oauth_key_states;
                }

                if (!keys || keys.length === 0) {
                    if (healthContainer) healthContainer.style.display = 'none';
                    return;
                }

                if (healthContainer) healthContainer.style.display = 'block';
                listContainer.innerHTML = '';
                keys.forEach((key, idx) => {
                    const state = states[idx] || {};
                    const isInvalid = state.invalid;
                    const exhaustedUntil = state.exhaustedUntil || {};
                    const now = Date.now();
                    
                    const exhaustedModels = Object.entries(exhaustedUntil)
                        .filter(([_, until]) => until > now)
                        .map(([model, until]) => `${model.replace(/^models\//, '')} (until ${new Date(until).toLocaleTimeString()})`);

                    const item = document.createElement('div');
                    item.className = 'key-status-item';
                    
                    let statusBadge = '<span class="key-status-badge badge-healthy">Healthy</span>';
                    if (isInvalid) {
                        statusBadge = '<span class="key-status-badge badge-invalid">Invalid</span>';
                    } else if (exhaustedModels.length > 0) {
                        statusBadge = '<span class="key-status-badge badge-exhausted">Exhausted</span>';
                    }

                    const infoDiv = document.createElement('div');
                    infoDiv.className = 'key-status-info';
                    infoDiv.innerHTML = `
                        <span class="key-status-raw">${maskKey(key)}</span>
                        ${exhaustedModels.length > 0 ? `<div class="exhausted-models">Exhausted: ${exhaustedModels.join(', ')}</div>` : ''}
                    `;

                    const actionsDiv = document.createElement('div');
                    actionsDiv.style.display = 'flex';
                    actionsDiv.style.alignItems = 'center';
                    actionsDiv.style.gap = '0.5rem';
                    actionsDiv.innerHTML = statusBadge;

                    // Add Diagnose button to every key
                    const diagnoseBtn = document.createElement('button');
                    diagnoseBtn.textContent = 'Diagnose';
                    diagnoseBtn.className = 'btn-secondary-outline';
                    diagnoseBtn.onclick = () => diagnoseKey(token, key, isOAuth, diagnoseBtn, isAntigravity);
                    actionsDiv.appendChild(diagnoseBtn);

                    // Add Models button for OAuth & Antigravity keys
                    if (isOAuth || isAntigravity) {
                        const modelsBtn = document.createElement('button');
                        modelsBtn.textContent = 'Models';
                        modelsBtn.className = 'btn-secondary-outline';
                        modelsBtn.onclick = () => showModels(token, key, isOAuth, modelsBtn, isAntigravity);
                        actionsDiv.appendChild(modelsBtn);
                    }

                    if (isInvalid || exhaustedModels.length > 0) {
                        const resetBtn = document.createElement('button');
                        resetBtn.textContent = 'Reset';
                        resetBtn.className = 'btn-danger-outline';
                        resetBtn.onclick = () => resetKeyHealth(token, key, isOAuth, isAntigravity);
                        actionsDiv.appendChild(resetBtn);
                    }

                    item.appendChild(infoDiv);
                    item.appendChild(actionsDiv);
                    listContainer.appendChild(item);
                });
                if (healthContainer) healthContainer.style.display = 'block';
            } catch (e) {
                console.error('Error fetching key health:', e);
                if (healthContainer) healthContainer.style.display = 'none';
            }
        }

        async function loadTokenDropdown(type, selectToken = null) {
            const isOAuth = type === true || type === 'oauth';
            const isAntigravity = type === 'antigravity';

            let selectEl = document.getElementById('accessTokenSelect');
            let inputEl = document.getElementById('accessToken');
            let textareaEl = document.getElementById('apiKeys');
            let healthContainer = document.getElementById('api-key-health');
            let url = '/api/credentials';
            let checkboxEl = document.getElementById('enableLogging');
            let pruningCheckboxEl = document.getElementById('enablePruning');

            if (isAntigravity) {
                selectEl = document.getElementById('agyAccessTokenSelect');
                inputEl = document.getElementById('agyAccessToken');
                textareaEl = document.getElementById('antigravityCredentials');
                healthContainer = document.getElementById('agy-key-health');
                url = '/api/antigravity-credentials';
                checkboxEl = document.getElementById('agyEnableLogging');
                pruningCheckboxEl = document.getElementById('agyEnablePruning');
            } else if (isOAuth) {
                selectEl = document.getElementById('oauthAccessTokenSelect');
                inputEl = document.getElementById('oauthAccessToken');
                textareaEl = document.getElementById('oauthCredentials');
                healthContainer = document.getElementById('oauth-key-health');
                url = '/api/oauth-credentials';
                checkboxEl = document.getElementById('oauthEnableLogging');
                pruningCheckboxEl = document.getElementById('oauthEnablePruning');
            }

            try {
                const response = await fetch(url);
                if (!response.ok) throw new Error('Failed to fetch tokens');
                const data = await response.json();
                const tokens = data.tokens || [];

                selectEl.innerHTML = '';
                
                // First option is always "Create New"
                const defaultOpt = document.createElement('option');
                defaultOpt.value = 'create_new';
                defaultOpt.textContent = '➕ [ Create New Access Token... ]';
                selectEl.appendChild(defaultOpt);

                tokens.forEach(token => {
                    const opt = document.createElement('option');
                    opt.value = token;
                    opt.textContent = token;
                    selectEl.appendChild(opt);
                });

                if (selectToken && tokens.includes(selectToken)) {
                    selectEl.value = selectToken;
                    inputEl.value = selectToken;
                    inputEl.style.display = 'none';
                    // Fetch details
                    fetchTokenCredentials(selectToken, type);
                } else if (tokens.length > 0 && !selectToken) {
                    // Default to the first existing token for supreme ease of use
                    const firstToken = tokens[0];
                    selectEl.value = firstToken;
                    inputEl.value = firstToken;
                    inputEl.style.display = 'none';
                    fetchTokenCredentials(firstToken, type);
                } else {
                    // No existing tokens or explicitly creating new
                    selectEl.value = 'create_new';
                    inputEl.value = '';
                    inputEl.style.display = 'block';
                    textareaEl.value = '';
                    checkboxEl.checked = false; // Default off for new tokens
                    pruningCheckboxEl.checked = true; // Default on for new tokens
                    if (healthContainer) healthContainer.style.display = 'none';
                }
            } catch (e) {
                console.error('Failed to load token dropdown:', e);
            }
        }

        async function fetchTokenCredentials(token, type) {
            const isOAuth = type === true || type === 'oauth';
            const isAntigravity = type === 'antigravity';

            let textareaEl = document.getElementById('apiKeys');
            let healthContainer = document.getElementById('api-key-health');
            let url = '/api/credentials';
            let checkboxEl = document.getElementById('enableLogging');
            let pruningCheckboxEl = document.getElementById('enablePruning');

            if (isAntigravity) {
                textareaEl = document.getElementById('antigravityCredentials');
                healthContainer = document.getElementById('agy-key-health');
                url = '/api/antigravity-credentials';
                checkboxEl = document.getElementById('agyEnableLogging');
                pruningCheckboxEl = document.getElementById('agyEnablePruning');
            } else if (isOAuth) {
                textareaEl = document.getElementById('oauthCredentials');
                healthContainer = document.getElementById('oauth-key-health');
                url = '/api/oauth-credentials';
                checkboxEl = document.getElementById('oauthEnableLogging');
                pruningCheckboxEl = document.getElementById('oauthEnablePruning');
            }

            try {
                const response = await fetch(url, {
                    headers: { 'X-Access-Token': token }
                });
                if (response.ok) {
                    const data = await response.json();
                    checkboxEl.checked = data.enable_logging === 1;
                    pruningCheckboxEl.checked = data.enable_pruning !== 0;
                    if (isAntigravity) {
                        if (data.hasOwnProperty('antigravity_credentials')) {
                            textareaEl.value = data.antigravity_credentials ? data.antigravity_credentials.replace(/,/g, '\n') : '';
                            updateKeyHealth(token, 'antigravity');
                        }
                    } else if (isOAuth) {
                        if (data.hasOwnProperty('oauth_credentials')) {
                            textareaEl.value = data.oauth_credentials ? data.oauth_credentials.replace(/,/g, '\n') : '';
                            updateKeyHealth(token, 'oauth');
                        }
                    } else {
                        if (data.hasOwnProperty('api_keys')) {
                            textareaEl.value = data.api_keys ? data.api_keys.replace(/,/g, '\n') : '';
                            updateKeyHealth(token, 'api');
                        }
                    }
                } else {
                    if (healthContainer) healthContainer.style.display = 'none';
                }
            } catch (error) {
                console.error('Error fetching token details:', error);
            }
        }

        document.getElementById('accessTokenSelect').addEventListener('change', (e) => {
            const value = e.target.value;
            const inputEl = document.getElementById('accessToken');
            const textareaEl = document.getElementById('apiKeys');
            const healthContainer = document.getElementById('api-key-health');

            if (value === 'create_new') {
                inputEl.value = '';
                inputEl.style.display = 'block';
                textareaEl.value = '';
                document.getElementById('enableLogging').checked = false; // Reset to off
                document.getElementById('enablePruning').checked = true; // Default to on
                if (healthContainer) healthContainer.style.display = 'none';
                inputEl.focus();
            } else {
                inputEl.value = value;
                inputEl.style.display = 'none';
                fetchTokenCredentials(value, false);
            }
        });

        // Trigger loading on manual input if it reaches 10+ chars and matches an existing option
        let fetchTimeout;
        accessTokenInput.addEventListener('input', () => {
            clearTimeout(fetchTimeout);
            fetchTimeout = setTimeout(async () => {
                const token = accessTokenInput.value.trim();
                const selectEl = document.getElementById('accessTokenSelect');
                const matchingOption = Array.from(selectEl.options).find(opt => opt.value === token);
                if (matchingOption) {
                    selectEl.value = token;
                    accessTokenInput.style.display = 'none';
                    fetchTokenCredentials(token, false);
                }
            }, 500);
        });

        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            const submitBtn = form.querySelector('button[type="submit"]');
            setButtonLoading(submitBtn, true, 'Saving Credentials...');
            const accessToken = document.getElementById('accessToken').value;
            const apiKeys = document.getElementById('apiKeys').value;
            const enableLogging = document.getElementById('enableLogging').checked;
            const enablePruning = document.getElementById('enablePruning').checked;
            resultDiv.style.display = 'none';
            resultDiv.className = '';

            try {
                const response = await fetch('/api/credentials', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ 
                        access_token: accessToken, 
                        api_keys: apiKeys, 
                        enable_logging: enableLogging,
                        enable_pruning: enablePruning
                    })
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'An unknown error occurred.');
                }

                while (resultDiv.firstChild) {
                    resultDiv.removeChild(resultDiv.firstChild);
                }

                const displaySuccess = (token) => {
                    const baseUrl = window.location.origin;
                    const openAIUrl = `${baseUrl}/chat/completions`;
                    const claudeUrl = `${baseUrl}/v1/messages`;
                    const googleUrl = `${baseUrl}/v1beta/models/gemini-pro:generateContent`;
                    const googleUrlWithKey = `${googleUrl}?key=${token}`;

                    const h2 = document.createElement('h2');
                    h2.textContent = 'Success!';
                    resultDiv.appendChild(h2);

                    const p1 = document.createElement('p');
                    p1.textContent = 'Your credentials have been saved for Access Token:';
                    resultDiv.appendChild(p1);

                    const pCode = document.createElement('p');
                    const code = document.createElement('code');
                    code.textContent = token;
                    pCode.appendChild(code);
                    resultDiv.appendChild(pCode);

                    resultDiv.appendChild(document.createElement('hr'));

                    const h3 = document.createElement('h3');
                    h3.textContent = 'How to Use';
                    resultDiv.appendChild(h3);
                    
                    const p2 = document.createElement('p');
                    p2.textContent = 'You can now make requests to the Gemini API through this worker. Use your Access Token in one of the following ways.';
                    resultDiv.appendChild(p2);

                    const p3 = document.createElement('p');
                    p3.innerHTML = '<strong>Note:</strong> The OpenAI-style endpoint is a compatibility layer and only supports <code>/chat/completions</code>, <code>/embeddings</code>, and <code>/models</code>. The Claude-style endpoint supports <code>/messages</code> and <code>/models</code>.';
                    resultDiv.appendChild(p3);

                    const createCurlExample = (title, command) => {
                        const h4 = document.createElement('h4');
                        h4.textContent = title;
                        resultDiv.appendChild(h4);
                        const pre = document.createElement('pre');
                        const codeElem = document.createElement('code');
                        codeElem.style.display = 'block';
                        codeElem.style.whiteSpace = 'pre-wrap';
                        codeElem.style.wordBreak = 'break-all';
                        codeElem.textContent = command;
                        pre.appendChild(codeElem);
                        resultDiv.appendChild(pre);
                    };

                    createCurlExample('1. OpenAI-Style (Bearer Token)', `curl -X POST \\\n  -H "Authorization: Bearer ${token}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"model": "gemini-pro", "messages": [{"role": "user", "content": "Explain how a transformer model works"}]}' \\\n  "${openAIUrl}"`);
                    createCurlExample('2. Claude-Style (x-api-key Header)', `curl -X POST "${claudeUrl}" \\\n     --header "x-api-key: ${token}" \\\n     --header "anthropic-version: 2023-06-01" \\\n     --header "content-type: application/json" \\\n     --data '{\n       "model": "claude-sonnet-4-20250514",\n       "max_tokens": 16000,\n       "thinking": {\n         "type": "enabled",\n         "budget_tokens": 10000\n       },\n       "messages": [\n         {\n           "role": "user",\n           "content": "Are there an infinite number of prime numbers such that n mod 4 == 3?"\n         }\n       ],\n       "stream": true\n     }'`);
                    createCurlExample('3. Google-Style (x-goog-api-key Header)', `curl -X POST \\\n  -H "x-goog-api-key: ${token}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"contents":[{"parts":[{"text":"Explain how a transformer model works"}]}]}' \\\n  "${googleUrl}"`);
                    createCurlExample('4. Google-Style (Query Parameter)', `curl -X POST \\\n  -H "Content-Type: application/json" \\\n  -d '{"contents":[{"parts":[{"text":"Explain how a transformer model works"}]}]}' \\\n  "${googleUrlWithKey}"`);
                };
                
                displaySuccess(data.access_token);
                loadTokenDropdown(false, data.access_token);

            } catch (error) {
                resultDiv.className = 'error';
                resultDiv.innerHTML = ''; // Clear previous content
                const strong = document.createElement('strong');
                strong.textContent = 'Error: ';
                resultDiv.appendChild(strong);
                resultDiv.appendChild(document.createTextNode(error.message));
            } finally {
                setButtonLoading(submitBtn, false);
            }
            
            resultDiv.style.display = 'block';
        });

        document.getElementById('deleteButton').addEventListener('click', async () => {
            const accessToken = accessTokenInput.value.trim();
            if (!accessToken) {
                showAlert('Warning', 'Please enter an Access Token to delete.', 'error');
                return;
            }

            const confirmed = await showConfirm('Delete Credentials', `Are you sure you want to delete all credentials for the token "${accessToken}"? This action cannot be undone.`);
            if (!confirmed) {
                return;
            }

            resultDiv.style.display = 'none';
            resultDiv.className = '';

            try {
                const response = await fetch('/api/credentials', {
                    method: 'DELETE',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-Access-Token': accessToken
                    }
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || data.message || 'An unknown error occurred.');
                }
                
                while (resultDiv.firstChild) {
                    resultDiv.removeChild(resultDiv.firstChild);
                }

                const strong = document.createElement('strong');
                strong.textContent = 'Success: ';
                resultDiv.appendChild(strong);
                resultDiv.appendChild(document.createTextNode(data.message));
                
                accessTokenInput.value = '';
                apiKeysTextarea.value = '';
                loadTokenDropdown(false);

            } catch (error) {
                resultDiv.className = 'error';
                while (resultDiv.firstChild) {
                    resultDiv.removeChild(resultDiv.firstChild);
                }
                const strong = document.createElement('strong');
                strong.textContent = 'Error: ';
                resultDiv.appendChild(strong);
                resultDiv.appendChild(document.createTextNode(error.message));
            }

            resultDiv.style.display = 'block';
        });

        // OAuth Form Handling
        const oauthForm = document.getElementById('oauthForm');
        const oauthResultDiv = document.getElementById('oauthResult');
        const oauthAccessTokenInput = document.getElementById('oauthAccessToken');
        const oauthCredentialsTextarea = document.getElementById('oauthCredentials');
        const connectGoogleBtn = document.getElementById('connectGoogleBtn');
        const manualCodeInput = document.getElementById('manualCode');
        const manualExchangeBtn = document.getElementById('manualExchangeBtn');

        const REDIRECT_URI = `http://localhost:8085/oauth2callback`;

        document.getElementById('oauthAccessTokenSelect').addEventListener('change', (e) => {
            const value = e.target.value;
            const inputEl = document.getElementById('oauthAccessToken');
            const textareaEl = document.getElementById('oauthCredentials');
            const healthContainer = document.getElementById('oauth-key-health');

            if (value === 'create_new') {
                inputEl.value = '';
                inputEl.style.display = 'block';
                textareaEl.value = '';
                document.getElementById('oauthEnableLogging').checked = false; // Reset to off
                document.getElementById('oauthEnablePruning').checked = true; // Default to on
                if (healthContainer) healthContainer.style.display = 'none';
                inputEl.focus();
            } else {
                inputEl.value = value;
                inputEl.style.display = 'none';
                fetchTokenCredentials(value, true);
            }
        });

        // Trigger loading on manual input if it reaches 10+ chars and matches an existing option
        oauthAccessTokenInput.addEventListener('input', () => {
            clearTimeout(fetchTimeout);
            fetchTimeout = setTimeout(async () => {
                const token = oauthAccessTokenInput.value.trim();
                const selectEl = document.getElementById('oauthAccessTokenSelect');
                const matchingOption = Array.from(selectEl.options).find(opt => opt.value === token);
                if (matchingOption) {
                    selectEl.value = token;
                    oauthAccessTokenInput.style.display = 'none';
                    fetchTokenCredentials(token, true);
                }
            }, 500);
        });

        connectGoogleBtn.addEventListener('click', async () => {
            const clientId = '';
            const clientSecret = '';

            try {
                // Ensure we get a fresh authorize URL with a new PKCE verifier (stored in cookie)
                let authUrl = `/api/oauth-authorize?redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;
                if (clientId) {
                    authUrl += `&client_id=${clientId}`;
                }
                const response = await fetch(authUrl);
                const data = await response.json();
                
                const popup = window.open(data.url, 'google_oauth', 'width=600,height=700');
                
                // Wait for message from popup
                window.onmessage = async (event) => {
                    if (event.data.type === 'oauth-code') {
                        const code = event.data.code;
                        // Exchange code for credential string. The worker will use the pkce_verifier cookie.
                        const exRes = await fetch('/api/oauth-exchange', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ 
                                code, 
                                client_id: clientId, 
                                client_secret: clientSecret, 
                                redirect_uri: REDIRECT_URI 
                            })
                        });
                        const exData = await exRes.json();
                        if (exData.credential_string) {
                            const current = oauthCredentialsTextarea.value.trim();
                            const newCreds = exData.credential_string;
                            // Check if already in list
                            if (current.includes(newCreds)) {
                                showAlert('OAuth Notice', 'This account is already in your credentials list.', 'info');
                            } else {
                                oauthCredentialsTextarea.value = current ? current + '\n' + newCreds : newCreds;
                                showAlert('OAuth Success', 'Google account connected and added to credentials list!', 'success');
                            }
                        } else {
                            showAlert('OAuth Error', 'Exchange failed: ' + (exData.error || 'Unknown error'), 'error');
                        }
                    }
                };
            } catch (error) {
                showAlert('OAuth Error', 'Error starting OAuth: ' + error.message, 'error');
            }
        });

        manualExchangeBtn.addEventListener('click', async () => {
            const input = manualCodeInput.value.trim();
            if (!input) return;

            let code = input;
            if (input.includes('code=')) {
                try {
                    const url = new URL(input.startsWith('http') ? input : 'http://localhost?' + input);
                    code = url.searchParams.get('code') || input;
                } catch (e) {
                    // Fallback to raw input if URL parsing fails
                }
            }

            const clientId = '';
            const clientSecret = '';

            try {
                const exRes = await fetch('/api/oauth-exchange', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        code, 
                        client_id: clientId, 
                        client_secret: clientSecret, 
                        redirect_uri: REDIRECT_URI 
                    })
                });
                const exData = await exRes.json();
                if (exData.credential_string) {
                    const current = oauthCredentialsTextarea.value.trim();
                    const newCreds = exData.credential_string;
                    if (current.includes(newCreds)) {
                        showAlert('OAuth Notice', 'This account is already in your credentials list.', 'info');
                    } else {
                        oauthCredentialsTextarea.value = current ? current + '\n' + newCreds : newCreds;
                        showAlert('OAuth Success', 'Google account exchanged and added successfully!', 'success');
                        manualCodeInput.value = '';
                    }
                } else {
                    showAlert('OAuth Error', 'Exchange failed: ' + (exData.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                showAlert('OAuth Error', 'Error exchanging code: ' + error.message, 'error');
            }
        });

        oauthForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const submitBtn = oauthForm.querySelector('button[type="submit"]');
            setButtonLoading(submitBtn, true, 'Saving Credentials...');
            const accessToken = oauthAccessTokenInput.value.trim();
            const oauthCredentials = oauthCredentialsTextarea.value.trim();
            const enableLogging = document.getElementById('oauthEnableLogging').checked;
            const enablePruning = document.getElementById('oauthEnablePruning').checked;

            oauthResultDiv.style.display = 'none';
            oauthResultDiv.className = '';

            try {
                const response = await fetch('/api/oauth-credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        access_token: accessToken,
                        oauth_credentials: oauthCredentials,
                        enable_logging: enableLogging,
                        enable_pruning: enablePruning
                    })
                });

                const data = await response.json();
                if (!response.ok) throw new Error(data.error || 'An unknown error occurred.');

                while (oauthResultDiv.firstChild) oauthResultDiv.removeChild(oauthResultDiv.firstChild);

                const displaySuccess = (token) => {
                    const baseUrl = window.location.origin;
                    const openAIUrl = `${baseUrl}/chat/completions`;

                    const h2 = document.createElement('h2');
                    h2.textContent = 'Success!';
                    oauthResultDiv.appendChild(h2);

                    const p1 = document.createElement('p');
                    p1.textContent = 'OAuth credentials saved for Access Token:';
                    oauthResultDiv.appendChild(p1);

                    const pCode = document.createElement('p');
                    const code = document.createElement('code');
                    code.textContent = token;
                    pCode.appendChild(code);
                    oauthResultDiv.appendChild(pCode);

                    oauthResultDiv.appendChild(document.createElement('hr'));

                    const h3 = document.createElement('h3');
                    h3.textContent = 'How to Use';
                    oauthResultDiv.appendChild(h3);

                    const createCurlExample = (title, command) => {
                        const h4 = document.createElement('h4');
                        h4.textContent = title;
                        oauthResultDiv.appendChild(h4);
                        const pre = document.createElement('pre');
                        const codeElem = document.createElement('code');
                        codeElem.style.display = 'block';
                        codeElem.style.whiteSpace = 'pre-wrap';
                        codeElem.style.wordBreak = 'break-all';
                        codeElem.textContent = command;
                        pre.appendChild(codeElem);
                        oauthResultDiv.appendChild(pre);
                    };

                    createCurlExample('Gemini CLI / Antigravity Mode', `curl -X POST \\\n  -H "Authorization: Bearer ${token}" \\\n  -H "X-Auth-Mode: gemini-cli" \\\n  -H "Content-Type: application/json" \\\n  -d '{"model": "gemini-2.5-pro", "messages": [{"role": "user", "content": "Hello"}]}' \\\n  "${openAIUrl}"`);
                };

                displaySuccess(data.access_token);
                loadTokenDropdown(true, data.access_token);

            } catch (error) {
                oauthResultDiv.className = 'error';
                oauthResultDiv.innerHTML = '';
                const strong = document.createElement('strong');
                strong.textContent = 'Error: ';
                oauthResultDiv.appendChild(strong);
                oauthResultDiv.appendChild(document.createTextNode(error.message));
            } finally {
                setButtonLoading(submitBtn, false);
            }

            oauthResultDiv.style.display = 'block';
        });

        document.getElementById('oauthDeleteButton').addEventListener('click', async () => {
            const accessToken = oauthAccessTokenInput.value.trim();
            if (!accessToken) {
                showAlert('Warning', 'Please enter an Access Token to delete.', 'error');
                return;
            }

            const confirmed = await showConfirm('Delete OAuth Credentials', `Are you sure you want to delete all OAuth credentials for the token "${accessToken}"? This action cannot be undone.`);
            if (!confirmed) {
                return;
            }

            oauthResultDiv.style.display = 'none';
            oauthResultDiv.className = '';

            try {
                const response = await fetch('/api/oauth-credentials', {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Access-Token': accessToken
                    }
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || data.message || 'An unknown error occurred.');
                }

                while (oauthResultDiv.firstChild) {
                    oauthResultDiv.removeChild(oauthResultDiv.firstChild);
                }

                const strong = document.createElement('strong');
                strong.textContent = 'Success: ';
                oauthResultDiv.appendChild(strong);
                oauthResultDiv.appendChild(document.createTextNode(data.message));

                oauthAccessTokenInput.value = '';
                oauthCredentialsTextarea.value = '';
                loadTokenDropdown('oauth');

            } catch (error) {
                oauthResultDiv.className = 'error';
                while (oauthResultDiv.firstChild) {
                    oauthResultDiv.removeChild(oauthResultDiv.firstChild);
                }
                const strong = document.createElement('strong');
                strong.textContent = 'Error: ';
                oauthResultDiv.appendChild(strong);
                oauthResultDiv.appendChild(document.createTextNode(error.message));
            }

            oauthResultDiv.style.display = 'block';
        });

        // Antigravity Form Handling
        const antigravityForm = document.getElementById('antigravityForm');
        const agyResultDiv = document.getElementById('antigravityResult');
        const agyAccessTokenInput = document.getElementById('agyAccessToken');
        const agyCredentialsTextarea = document.getElementById('antigravityCredentials');
        const agyConnectGoogleBtn = document.getElementById('agyConnectGoogleBtn');
        const agyManualCodeInput = document.getElementById('agyManualCode');
        const agyManualExchangeBtn = document.getElementById('agyManualExchangeBtn');

        if (document.getElementById('agyAccessTokenSelect')) {
            document.getElementById('agyAccessTokenSelect').addEventListener('change', (e) => {
                const value = e.target.value;
                const inputEl = document.getElementById('agyAccessToken');
                const textareaEl = document.getElementById('antigravityCredentials');
                const healthContainer = document.getElementById('agy-key-health');

                if (value === 'create_new') {
                    inputEl.value = '';
                    inputEl.style.display = 'block';
                    textareaEl.value = '';
                    document.getElementById('agyEnableLogging').checked = false;
                    document.getElementById('agyEnablePruning').checked = true;
                    if (healthContainer) healthContainer.style.display = 'none';
                    inputEl.focus();
                } else {
                    inputEl.value = value;
                    inputEl.style.display = 'none';
                    fetchTokenCredentials(value, 'antigravity');
                }
            });
        }

        if (agyAccessTokenInput) {
            agyAccessTokenInput.addEventListener('input', () => {
                clearTimeout(fetchTimeout);
                fetchTimeout = setTimeout(async () => {
                    const token = agyAccessTokenInput.value.trim();
                    const selectEl = document.getElementById('agyAccessTokenSelect');
                    const matchingOption = Array.from(selectEl.options).find(opt => opt.value === token);
                    if (matchingOption) {
                        selectEl.value = token;
                        agyAccessTokenInput.style.display = 'none';
                        fetchTokenCredentials(token, 'antigravity');
                    }
                }, 500);
            });
        }

        if (agyConnectGoogleBtn) {
            agyConnectGoogleBtn.addEventListener('click', async () => {
                const clientId = [
                    '1071006060591',
                    'tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com'
                ].join('-');
                const clientSecret = [
                    'GOCSPX',
                    'K58FWR486LdLJ1mLB8sXC4z6qDAf'
                ].join('-');

                try {
                    let authUrl = `/api/oauth-authorize?redirect_uri=${encodeURIComponent(REDIRECT_URI)}&client_id=${clientId}&isAntigravity=true`;
                    const response = await fetch(authUrl);
                    const data = await response.json();
                    
                    window.open(data.url, 'antigravity_oauth', 'width=600,height=700');
                    
                    window.onmessage = async (event) => {
                        if (event.data.type === 'oauth-code') {
                            const code = event.data.code;
                            const exRes = await fetch('/api/oauth-exchange', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ 
                                    code, 
                                    client_id: clientId, 
                                    client_secret: clientSecret, 
                                    redirect_uri: REDIRECT_URI,
                                    isAntigravity: true
                                })
                            });
                            const exData = await exRes.json();
                            if (exData.credential_string) {
                                const current = agyCredentialsTextarea.value.trim();
                                const newCreds = exData.credential_string;
                                if (current.includes(newCreds)) {
                                    showAlert('Antigravity Notice', 'This account is already in your credentials list.', 'info');
                                } else {
                                    agyCredentialsTextarea.value = current ? current + '\n' + newCreds : newCreds;
                                    showAlert('Antigravity Success', 'Antigravity account connected and added to credentials list!', 'success');
                                }
                            } else {
                                showAlert('Antigravity Error', 'Exchange failed: ' + (exData.error || 'Unknown error'), 'error');
                            }
                        }
                    };
                } catch (error) {
                    showAlert('Antigravity Error', 'Error starting OAuth: ' + error.message, 'error');
                }
            });
        }

        if (agyManualExchangeBtn) {
            agyManualExchangeBtn.addEventListener('click', async () => {
                const input = agyManualCodeInput.value.trim();
                if (!input) return;

                let code = input;
                if (input.includes('code=')) {
                    try {
                        const url = new URL(input.startsWith('http') ? input : 'http://localhost?' + input);
                        code = url.searchParams.get('code') || input;
                    } catch (e) {}
                }

                const clientId = [
                    '1071006060591',
                    'tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com'
                ].join('-');
                const clientSecret = [
                    'GOCSPX',
                    'K58FWR486LdLJ1mLB8sXC4z6qDAf'
                ].join('-');

                try {
                    const exRes = await fetch('/api/oauth-exchange', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            code, 
                            client_id: clientId, 
                            client_secret: clientSecret, 
                            redirect_uri: REDIRECT_URI,
                            isAntigravity: true
                        })
                    });
                    const exData = await exRes.json();
                    if (exData.credential_string) {
                        const current = agyCredentialsTextarea.value.trim();
                        const newCreds = exData.credential_string;
                        if (current.includes(newCreds)) {
                            showAlert('Antigravity Notice', 'This account is already in your credentials list.', 'info');
                        } else {
                            agyCredentialsTextarea.value = current ? current + '\n' + newCreds : newCreds;
                            showAlert('Antigravity Success', 'Antigravity account exchanged and added successfully!', 'success');
                            agyManualCodeInput.value = '';
                        }
                    } else {
                        showAlert('Antigravity Error', 'Exchange failed: ' + (exData.error || 'Unknown error'), 'error');
                    }
                } catch (error) {
                    showAlert('Antigravity Error', 'Error exchanging code: ' + error.message, 'error');
                }
            });
        }

        if (antigravityForm) {
            antigravityForm.addEventListener('submit', async (event) => {
                event.preventDefault();
                const submitBtn = antigravityForm.querySelector('button[type="submit"]');
                setButtonLoading(submitBtn, true, 'Saving Credentials...');
                const accessToken = agyAccessTokenInput.value.trim();
                const agyCredentials = agyCredentialsTextarea.value.trim();
                const enableLogging = document.getElementById('agyEnableLogging').checked;
                const enablePruning = document.getElementById('agyEnablePruning').checked;

                agyResultDiv.style.display = 'none';
                agyResultDiv.className = '';

                try {
                    const response = await fetch('/api/antigravity-credentials', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            access_token: accessToken,
                            antigravity_credentials: agyCredentials,
                            enable_logging: enableLogging,
                            enable_pruning: enablePruning
                        })
                    });

                    const data = await response.json();
                    if (!response.ok) throw new Error(data.error || 'An unknown error occurred.');

                    while (agyResultDiv.firstChild) agyResultDiv.removeChild(agyResultDiv.firstChild);

                    const displaySuccess = (token) => {
                        const baseUrl = window.location.origin;
                        const openAIUrl = `${baseUrl}/v1/chat/completions`;

                        const h2 = document.createElement('h2');
                        h2.textContent = 'Success!';
                        agyResultDiv.appendChild(h2);

                        const p1 = document.createElement('p');
                        p1.textContent = 'Antigravity OAuth credentials saved for Access Token:';
                        agyResultDiv.appendChild(p1);

                        const pCode = document.createElement('p');
                        const code = document.createElement('code');
                        code.textContent = token;
                        pCode.appendChild(code);
                        agyResultDiv.appendChild(pCode);

                        agyResultDiv.appendChild(document.createElement('hr'));

                        const h3 = document.createElement('h3');
                        h3.textContent = 'How to Use';
                        agyResultDiv.appendChild(h3);

                        const createCurlExample = (title, command) => {
                            const h4 = document.createElement('h4');
                            h4.textContent = title;
                            agyResultDiv.appendChild(h4);
                            const pre = document.createElement('pre');
                            const codeElem = document.createElement('code');
                            codeElem.style.display = 'block';
                            codeElem.style.whiteSpace = 'pre-wrap';
                            codeElem.style.wordBreak = 'break-all';
                            codeElem.textContent = command;
                            pre.appendChild(codeElem);
                            agyResultDiv.appendChild(pre);
                        };

                        createCurlExample('Antigravity Mode (via -agy Suffix)', `curl -X POST \\\n  -H "Authorization: Bearer ${token}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"model": "gemini-2.5-pro-agy", "messages": [{"role": "user", "content": "Hello"}]}' \\\n  "${openAIUrl}"`);
                    };

                    displaySuccess(data.access_token);
                    loadTokenDropdown('antigravity', data.access_token);

                } catch (error) {
                    agyResultDiv.className = 'error';
                    agyResultDiv.innerHTML = '';
                    const strong = document.createElement('strong');
                    strong.textContent = 'Error: ';
                    agyResultDiv.appendChild(strong);
                    agyResultDiv.appendChild(document.createTextNode(error.message));
                } finally {
                    setButtonLoading(submitBtn, false);
                }

                agyResultDiv.style.display = 'block';
            });
        }

        if (document.getElementById('agyDeleteButton')) {
            document.getElementById('agyDeleteButton').addEventListener('click', async () => {
                const accessToken = agyAccessTokenInput.value.trim();
                if (!accessToken) {
                    showAlert('Warning', 'Please enter an Access Token to delete.', 'error');
                    return;
                }

                const confirmed = await showConfirm('Delete Antigravity Credentials', `Are you sure you want to delete all Antigravity credentials for the token "${accessToken}"? This action cannot be undone.`);
                if (!confirmed) return;

                agyResultDiv.style.display = 'none';
                agyResultDiv.className = '';

                try {
                    const response = await fetch('/api/antigravity-credentials', {
                        method: 'DELETE',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Access-Token': accessToken
                        }
                    });

                    const data = await response.json();
                    if (!response.ok) throw new Error(data.error || data.message || 'An unknown error occurred.');

                    while (agyResultDiv.firstChild) agyResultDiv.removeChild(agyResultDiv.firstChild);

                    const strong = document.createElement('strong');
                    strong.textContent = 'Success: ';
                    agyResultDiv.appendChild(strong);
                    agyResultDiv.appendChild(document.createTextNode(data.message));

                    agyAccessTokenInput.value = '';
                    agyCredentialsTextarea.value = '';
                    loadTokenDropdown('antigravity');

                } catch (error) {
                    agyResultDiv.className = 'error';
                    while (agyResultDiv.firstChild) agyResultDiv.removeChild(agyResultDiv.firstChild);
                    const strong = document.createElement('strong');
                    strong.textContent = 'Error: ';
                    agyResultDiv.appendChild(strong);
                    agyResultDiv.appendChild(document.createTextNode(error.message));
                }

                agyResultDiv.style.display = 'block';
            });
        }

        // Admin Management Logic
        const adminEmailSpan = document.getElementById('admin-email');
        const adminsTabBtn = document.getElementById('admins-tab-btn');
        const adminsTableBody = document.getElementById('adminsTableBody');
        const addAdminForm = document.getElementById('addAdminForm');

        async function fetchAdminInfo() {
            try {
                const res = await fetch('/api/admin-info');
                if (res.ok) {
                    const admin = await res.json();
                    adminEmailSpan.textContent = admin.email;
                    if (admin.role === 'super_admin') {
                        adminsTabBtn.style.display = 'inline-block';
                        document.getElementById('statsSuperAdminToggleLabel').style.display = 'inline-flex';
                        document.getElementById('logsSuperAdminToggleLabel').style.display = 'inline-flex';
                        document.getElementById('trendsSuperAdminToggleArea').style.display = 'block';
                    }
                }
            } catch (e) {
                console.error("Failed to fetch admin info", e);
            }
        }

        async function loadAdmins() {
            try {
                const res = await fetch('/api/admins');
                if (!res.ok) throw new Error('Failed to fetch admins');
                const admins = await res.json();
                
                adminsTableBody.innerHTML = '';
                admins.forEach(admin => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td style="padding: 10px; border: 1px solid var(--border-color);">${admin.email}</td>
                        <td style="padding: 10px; border: 1px solid var(--border-color); text-align: center;">
                            <span style="padding: 2px 8px; border-radius: 999px; font-size: 0.75rem; background: ${admin.role === 'super_admin' ? 'var(--accent-color-light)' : 'var(--code-bg)'}; color: ${admin.role === 'super_admin' ? 'var(--accent-color)' : 'var(--text-primary)'}; border: 1px solid ${admin.role === 'super_admin' ? 'var(--accent-color)' : 'var(--border-color)'};">
                                ${admin.role}
                            </span>
                        </td>
                        <td style="padding: 10px; border: 1px solid var(--border-color); text-align: center;">
                            <button class="btn-danger-outline" onclick="deleteAdmin('${admin.email}')">Delete</button>
                        </td>
                    `;
                    adminsTableBody.appendChild(row);
                });
            } catch (e) {
                showAlert('Error', e.message, 'error');
            }
        }

        async function deleteAdmin(email) {
            const confirmed = await showConfirm('Remove Admin', `Are you sure you want to remove admin ${email}?`);
            if (!confirmed) return;
            try {
                const res = await fetch(`/api/admins?email=${encodeURIComponent(email)}`, { method: 'DELETE' });
                if (res.ok) {
                    loadAdmins();
                } else {
                    const data = await res.json();
                    showAlert('Error', data.error || 'Failed to delete admin', 'error');
                }
            } catch (e) {
                showAlert('Error', e.message, 'error');
            }
        }

        addAdminForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = addAdminForm.querySelector('button[type="submit"]');
            setButtonLoading(submitBtn, true, 'Adding Admin...');
            const email = document.getElementById('newAdminEmail').value.trim();
            const role = document.getElementById('newAdminRole').value;

            try {
                const res = await fetch('/api/admins', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, role })
                });
                if (res.ok) {
                    document.getElementById('newAdminEmail').value = '';
                    loadAdmins();
                    showAlert('Success', 'Admin added successfully!', 'success');
                } else {
                    const data = await res.json();
                    showAlert('Error', data.error || 'Failed to add admin', 'error');
                }
            } catch (e) {
                showAlert('Error', e.message, 'error');
            } finally {
                setButtonLoading(submitBtn, false);
            }
        });

        // Theme Toggle Logic
        const themeToggle = document.getElementById('themeToggle');
        const root = document.documentElement;

        function applyTheme(isDark) {
            if (isDark) {
                root.classList.add('dark-theme');
                localStorage.setItem('theme', 'dark');
                themeToggle.title = '切換至亮色模式';
            } else {
                root.classList.remove('dark-theme');
                localStorage.setItem('theme', 'light');
                themeToggle.title = '切換至暗色模式';
            }
        }

        themeToggle.addEventListener('click', () => {
            const isDark = !root.classList.contains('dark-theme');
            applyTheme(isDark);
        });

        // Initialize theme: Check storage, then system preference
        const savedTheme = localStorage.getItem('theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        applyTheme(savedTheme === 'dark' || (!savedTheme && prefersDark));

        // Initialize Admin Info
        fetchAdminInfo();

        // Initialize Token Dropdowns
        loadTokenDropdown(false);
        loadTokenDropdown(true);

        // Update tab switching to include Admins tab
        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetTab = button.getAttribute('data-tab');
                if (targetTab === 'admins-tab') {
                    loadAdmins();
                }
            });
        });