(function () {
    const API = '/api/local-account';
    let mode = 'login';
    let currentUser = null;

    function el(tag, attrs, children) {
        const node = document.createElement(tag);
        Object.entries(attrs || {}).forEach(([key, value]) => {
            if (key === 'class') node.className = value;
            else if (key === 'text') node.textContent = value;
            else node.setAttribute(key, value);
        });
        (children || []).forEach(child => node.appendChild(child));
        return node;
    }

    async function api(path, body) {
        const res = await fetch(API + path, {
            method: body ? 'POST' : 'GET',
            headers: body ? { 'Content-Type': 'application/json' } : {},
            credentials: 'same-origin',
            body: body ? JSON.stringify(body) : undefined
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || '请求失败');
        return data;
    }

    function setMode(nextMode) {
        mode = nextMode;
        document.querySelectorAll('[data-local-account-tab]').forEach(tab => {
            tab.classList.toggle('is-active', tab.dataset.localAccountTab === mode);
        });
        const submit = document.querySelector('[data-local-account-submit]');
        const title = document.querySelector('[data-local-account-form-title]');
        if (submit) submit.textContent = mode === 'login' ? '登录' : '注册并登录';
        if (title) title.textContent = mode === 'login' ? '登录本地账号' : '创建本地账号';
        const message = document.querySelector('[data-local-account-message]');
        if (message) message.textContent = '';
    }

    function setGateVisible(visible) {
        const gate = document.getElementById('local-account-gate');
        if (gate) gate.hidden = !visible;
        document.documentElement.classList.toggle('local-account-locked', visible);
    }

    function renderGate() {
        if (document.getElementById('local-account-gate')) return;
        const username = el('input', { name: 'username', autocomplete: 'username', required: 'required', minlength: '3' });
        const password = el('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: 'required', minlength: '6' });
        const form = el('form', { class: 'local-account-form' }, [
            el('div', { class: 'local-account-tabs' }, [
                el('button', { class: 'local-account-tab is-active', type: 'button', 'data-local-account-tab': 'login', text: '登录' }),
                el('button', { class: 'local-account-tab', type: 'button', 'data-local-account-tab': 'register', text: '注册' })
            ]),
            el('h2', { class: 'local-account-title', 'data-local-account-form-title': '', text: '登录本地账号' }),
            el('p', { class: 'local-account-subtitle', text: '登录后，对话和后续个人数据会绑定到账号 ID，方便以后继续扩展。' }),
            el('label', { class: 'local-account-field' }, [el('span', { text: '账号' }), username]),
            el('label', { class: 'local-account-field' }, [el('span', { text: '密码' }), password]),
            el('button', { class: 'local-account-submit', type: 'submit', 'data-local-account-submit': '', text: '登录' }),
            el('p', { class: 'local-account-message', 'data-local-account-message': '' }),
            el('div', { class: 'local-account-footer' }, [
                el('span', { text: '账号数据仅保存在本机 data/local_account。' }),
                el('button', { class: 'local-account-link', type: 'button', text: '刷新状态' })
            ])
        ]);
        const gate = el('div', { class: 'local-account-gate', id: 'local-account-gate', hidden: '' }, [
            el('div', { class: 'local-account-panel' }, [form])
        ]);
        document.body.appendChild(gate);

        gate.querySelectorAll('[data-local-account-tab]').forEach(tab => {
            tab.addEventListener('click', () => setMode(tab.dataset.localAccountTab));
        });
        gate.querySelector('.local-account-link').addEventListener('click', refresh);
        form.addEventListener('submit', async event => {
            event.preventDefault();
            const message = gate.querySelector('[data-local-account-message]');
            message.textContent = '';
            try {
                const data = await api(mode === 'login' ? '/login' : '/register', {
                    username: username.value.trim(),
                    password: password.value
                });
                currentUser = data.user;
                updateUserChip();
                setGateVisible(false);
                location.reload();
            } catch (error) {
                message.textContent = error.message || '操作失败';
            }
        });
    }

    function updateUserChip() {
        const actions = document.querySelector('.side-actions');
        if (!actions) return;
        let chip = document.getElementById('local-account-user-chip');
        if (!chip) {
            chip = el('div', { class: 'local-account-user-chip', id: 'local-account-user-chip', title: '本地账号' }, [
                el('span', { 'aria-hidden': 'true' }),
                el('span', { class: 'local-account-user-name' }),
                el('button', { class: 'local-account-logout', type: 'button', text: '退出' })
            ]);
            chip.firstChild.innerHTML = '<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21a8 8 0 0 0-16 0"></path><circle cx="12" cy="7" r="4"></circle></svg>';
            chip.querySelector('button').addEventListener('click', async event => {
                event.preventDefault();
                event.stopPropagation();
                await api('/logout', {});
                currentUser = null;
                setGateVisible(true);
            });
            actions.insertBefore(chip, actions.firstChild);
        }
        chip.hidden = !currentUser;
        chip.querySelector('.local-account-user-name').textContent = currentUser ? currentUser.username : '';
    }

    async function refresh() {
        renderGate();
        try {
            const data = await api('/me');
            currentUser = data.user;
            updateUserChip();
            setGateVisible(!data.authenticated);
        } catch (error) {
            currentUser = null;
            updateUserChip();
            setGateVisible(true);
        }
    }

    document.addEventListener('DOMContentLoaded', refresh, { once: true });
})();
