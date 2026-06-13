/* AgentDockControl 控制台 — 完整聊天功能 */
(function () {
  'use strict';

  const S = {
    token:      localStorage.getItem('token') || '',
    masterKey:  localStorage.getItem('masterKey') || '',
    socket:     null,
    sessions:   [],
    machines:   [],
    messagesCache: [],
    currentSessionId: null,
    currentSessionDek: null,
    decryptedCache: {},
    showCategory: 'active',
  };

  const $ = s => document.querySelector(s);
  const $$ = s => [...document.querySelectorAll(s)];

  // ─── API ────────────────────────────────────
  async function api(method, path, body) {
    const h = { 'Content-Type': 'application/json' };
    if (S.token) h['Authorization'] = 'Bearer ' + S.token;
    const opts = { method, headers: h };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(path, opts);
    const d = await r.json();
    if (!r.ok) throw new Error(d?.error?.message || d?.detail || r.statusText);
    return d;
  }
  const get = p => api('GET', p);
  const post = (p, b) => api('POST', p, b);

  window.copyText = t => navigator.clipboard?.writeText(t).then(
    () => toast('已复制'), () => toast('复制失败', 'error'));

  function toast(msg, type) {
    const el = $('#toast');
    el.textContent = msg; el.className = 'toast show ' + (type || '');
    clearTimeout(el._t); el._t = setTimeout(() => el.classList.remove('show'), 2500);
  }

  function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

  // ─── 导航 ───────────────────────────────────
  let currentPage = 'sessions';
  function navigate(page, sessionId) {
    const sp = $('#page-session'), panel = $('.session-panel');
    if (page === 'session' && sessionId) {
      S.currentSessionId = sessionId; sp.classList.add('active');
      showSession(sessionId);
      if (innerWidth <= 900) panel.style.display = 'none';
      currentPage = 'session'; updateNav('session'); return;
    }
    if (currentPage === 'session' && page !== 'session') {
      panel.style.display = ''; sp.classList.remove('active');
      S.currentSessionDek = null; S.decryptedCache = {};
    }
    currentPage = page;
    $$('.page').forEach(p => p.classList.remove('active'));
    const t = $('#page-' + page); if (t) t.classList.add('active');
    updateNav(page); refreshData(page);
  }
  function updateNav(page) {
    const p = page === 'session' ? 'sessions' : page;
    $$('.nav-item, .mnav-item').forEach(n => n.classList.toggle('active', n.dataset.page === p));
  }
  function bindNav() {
    $$('.nav-item[data-page], .mnav-item[data-page]').forEach(el => {
      el.addEventListener('click', e => { e.preventDefault(); navigate(el.dataset.page); });
    });
  }
  function refreshData(page) {
    if (page === 'sessions') loadSessions();
    if (page === 'machines') loadMachines();
    if (page === 'insights') loadInsights();
    if (page === 'tasks') loadTasks();
    if (page === 'settings') loadSettings();
  }
  // Expose navigation for inline handlers
  window.navigate = navigate;

  // ─── Socket ─────────────────────────────────
  function connectSocket() {
    if (S.socket) S.socket.disconnect();
    if (!S.token) return;
    S.socket = io('/', {
      auth: { token: S.token },
      transports: ['websocket', 'polling'],
      reconnection: true, reconnectionDelay: 2000, reconnectionAttempts: Infinity,
    });
    S.socket.on('message', d => {
      if (d.sessionId === S.currentSessionId) loadMessages(S.currentSessionId);
      else { loadSessions(); toast('新消息到达', 'info'); }
    });
    S.socket.on('session-create', () => { loadSessions(); toast('新会话已创建', 'success'); });
    S.socket.on('machine-status-update', () => { if (currentPage === 'machines') loadMachines(); });
    S.socket.on('core-update', d => {
      const b = d?.body || {};
      if (b.t === 'new-message' && b.sid === S.currentSessionId) loadMessages(S.currentSessionId);
    });
  }

  // ─── 健康检查 ──────────────────────────────
  setInterval(async () => {
    try {
      const h = await get('/v1/health');
      const n = h.connectedMachines || 0;
      $('#conn-dot').className = 'dot ' + (n > 0 ? 'online' : 'offline');
      $('#conn-text').textContent = n > 0 ? n + ' 台已连接' : '未连接';
      if (S.token && currentPage === 'machines') loadMachines();
    } catch { $('#conn-dot').className = 'dot offline'; $('#conn-text').textContent = '服务器离线'; }
  }, 5000);

  // ─── 新建会话弹窗 ─────────────────────────
  $('#btn-new-session').addEventListener('click', () => {
    const modal = $('#new-session-modal');
    modal.style.display = 'flex';
  });

  window.closeNewSessionModal = function () {
    $('#new-session-modal').style.display = 'none';
  };

  // Agent option selection
  document.addEventListener('click', e => {
    const opt = e.target.closest('.agent-option');
    if (opt) {
      $$('.agent-option').forEach(o => o.classList.remove('selected'));
      opt.classList.add('selected');
      opt.querySelector('input[type="radio"]').checked = true;
    }
  });

  $('#btn-create-session').addEventListener('click', async () => {
    const agentType = document.querySelector('input[name="agent-type"]:checked')?.value || 'hermes';
    const prompt = $('#session-prompt').value.trim();
    const btn = $('#btn-create-session');
    btn.disabled = true; btn.textContent = '创建中...';

    try {
      const body = { agentType: agentType, prompt: prompt || undefined };
      // If hermes, set a default cwd
      if (agentType === 'hermes') body.cwd = '/home';
      const data = await post('/v1/sessions/create', body);
      if (data.sessionId) {
        toast('会话已创建', 'success');
        window.closeNewSessionModal();
        $('#session-prompt').value = '';
        btn.disabled = false; btn.textContent = '创建';
        loadSessions();
        navigate('session', data.sessionId);
      } else {
        throw new Error(data.daemonResult?.error || '创建失败');
      }
    } catch (e) {
      toast('创建会话失败: ' + e.message, 'error');
      btn.disabled = false; btn.textContent = '创建';
    }
  });

  // ─── 配对 ───────────────────────────────────
  const pinInput = $('#pin-input'), btnPair = $('#btn-pair'), pairStatus = $('#pair-status');
  pinInput.addEventListener('input', () => { btnPair.disabled = pinInput.value.length !== 6; });

  btnPair.addEventListener('click', async () => {
    const pin = pinInput.value.trim();
    if (pin.length !== 6) return;
    btnPair.disabled = true; pairStatus.textContent = '查找配对请求...';
    pairStatus.style.color = 'var(--warning)';
    try {
      const pair = await get('/v1/pairing/find-by-pin/' + pin);
      pairStatus.textContent = '找到终端，完成配对...';
      const masterKey = generateMasterKey();
      let encryptedPayload = btoa(masterKey);
      if (typeof nacl !== 'undefined') {
        try {
          const ep = nacl.box.keyPair(), nonce = nacl.randomBytes(24);
          const ct = nacl.box(base64ToBytes(masterKey), nonce, base64ToBytes(pair.publicKey), ep.secretKey);
          if (ct) {
            const buf = new Uint8Array(ep.publicKey.length + nonce.length + ct.length);
            buf.set(ep.publicKey, 0); buf.set(nonce, ep.publicKey.length); buf.set(ct, ep.publicKey.length + nonce.length);
            encryptedPayload = btoa(String.fromCharCode(...buf));
          }
        } catch {}
      }
      const resp = await post('/v1/pairing/respond', { publicKey: pair.publicKey, encryptedPayload });
      if (resp.token) {
        S.token = resp.token; S.masterKey = masterKey;
        localStorage.setItem('token', resp.token); localStorage.setItem('masterKey', masterKey);
        pairStatus.textContent = '✓ 配对成功！'; pairStatus.style.color = 'var(--success)';
        toast('配对成功！已自动连接', 'success');
        pinInput.value = ''; btnPair.disabled = true;
        connectSocket(); setTimeout(() => navigate('sessions'), 500);
      } else throw new Error('未收到令牌');
    } catch (e) {
      pairStatus.textContent = '配对失败: ' + e.message;
      pairStatus.style.color = 'var(--danger)'; btnPair.disabled = false;
    }
  });

  $('#btn-restore').addEventListener('click', () => {
    const key = $('#restore-key').value.trim();
    if (!key) { toast('请粘贴主密钥', 'error'); return; }
    S.masterKey = key; localStorage.setItem('masterKey', key);
    toast('主密钥已保存', 'success');
    $('#restore-key').value = '';
  });

  function generateMasterKey() {
    const k = new Uint8Array(32); crypto.getRandomValues(k);
    return btoa(String.fromCharCode(...k));
  }
  function base64ToBytes(b64) {
    const bin = atob(b64); const u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }

  // ─── 会话列表 ───────────────────────────────
  async function loadSessions() {
    const list = $('#session-items'), count = $('#session-count');
    if (!S.token) {
      list.innerHTML = '<div class="empty-state"><p>请先在<a href="#" onclick="navigate(\'settings\')" style="color:var(--brand)">设置</a>中填入访问令牌</p></div>';
      count.textContent = '0'; return;
    }
    try {
      const data = await get('/v1/sessions');
      S.sessions = data.sessions || []; count.textContent = S.sessions.length;
      const filtered = S.sessions.filter(s => S.showCategory === 'active' ? s.status === 'active' : s.status !== 'active');
      if (!filtered.length) {
        list.innerHTML = '<div class="empty-state">暂无' + (S.showCategory === 'active' ? '活跃' : '最近') + '会话，点击上方「+ 新建」创建</div>';
        return;
      }
      const ac = S.sessions.filter(s => s.status === 'active').length;
      $('#cat-active').textContent = '活跃' + (ac ? ' (' + ac + ')' : '');
      $('#cat-recent').textContent = '最近' + (S.sessions.length - ac ? ' (' + (S.sessions.length - ac) + ')' : '');
      list.innerHTML = filtered.map(s => {
        const d = new Date((s.createdAt || 0) * 1000);
        const t = d.toLocaleString('zh-CN', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        return '<div class="session-card" data-id="' + s.id + '">' +
          '<span class="dot ' + (s.status || 'ended') + '"></span>' +
          '<div class="session-info"><div class="session-name">' + esc(s.tag || s.id.substring(0, 12)) + '</div>' +
          '<div class="session-sub">' + (s.machineId || '') + ' · ' + (s.status || '') + '</div></div>' +
          '<span class="session-time">' + t + '</span></div>';
      }).join('');
    } catch (e) { list.innerHTML = '<div class="empty-state">加载失败: ' + esc(e.message) + '</div>'; }
  }

  $('#cat-active').addEventListener('click', () => {
    S.showCategory = 'active';
    $$('.category-label').forEach(l => l.classList.remove('active'));
    $('#cat-active').classList.add('active'); loadSessions();
  });
  $('#cat-recent').addEventListener('click', () => {
    S.showCategory = 'recent';
    $$('.category-label').forEach(l => l.classList.remove('active'));
    $('#cat-recent').classList.add('active'); loadSessions();
  });

  $('#session-search').addEventListener('input', function () {
    const q = this.value.toLowerCase();
    $$('.session-card').forEach(c => {
      const n = (c.querySelector('.session-name')?.textContent || '').toLowerCase();
      const s = (c.querySelector('.session-sub')?.textContent || '').toLowerCase();
      c.style.display = (n.includes(q) || s.includes(q)) ? '' : 'none';
    });
  });

  $('#session-items').addEventListener('click', e => {
    const card = e.target.closest('.session-card');
    if (card) navigate('session', card.dataset.id);
  });
  $('#btn-refresh').addEventListener('click', loadSessions);

  // ─── 会话详情 ───────────────────────────────
  async function showSession(sessionId) {
    S.decryptedCache = {}; S.currentSessionDek = null;
    const title = $('#session-title'), dot = $('#session-dot');
    try {
      const data = await get('/v1/sessions/' + sessionId);
      const sess = data.session;
      if (!sess) throw new Error('会话不存在');
      title.textContent = sess.tag || sessionId.substring(0, 12);
      dot.className = 'session-status-dot ' + (sess.status || 'ended');
      if (S.masterKey && sess.wrappedDek) {
        try { S.currentSessionDek = unwrapDek(sess.wrappedDek, S.masterKey); } catch {}
      }
      loadMessages(sessionId);
      $('#msg-input').disabled = false; $('#btn-send').disabled = false;
      $('#msg-input').focus();
    } catch (e) { toast('加载会话失败: ' + e.message, 'error'); }
  }

  async function loadMessages(sessionId) {
    const area = $('#messages-area');
    try {
      const data = await get('/v1/messages/' + sessionId);
      S.messagesCache = data.messages || [];
      if (!S.messagesCache.length) {
        area.innerHTML = '<div class="empty-state">此会话暂无消息，在下方输入框发送第一条消息</div>';
        return;
      }
      area.innerHTML = S.messagesCache.map(m => renderMsg(m)).join('');
      area.scrollTop = area.scrollHeight;
    } catch (e) { area.innerHTML = '<div class="empty-state">加载消息失败: ' + esc(e.message) + '</div>'; }
  }

  // ─── 消息渲染（带 Markdown） ────────────────
  function renderMsg(m) {
    const d = new Date((m.createdAt || 0) * 1000);
    const time = d.toLocaleTimeString('zh-CN');
    const content = m.content || {};
    const localId = m.localId || '';
    const isEnc = content.t === 'encrypted';
    const role = localId && localId.startsWith('user') ? 'user'
               : localId && localId.startsWith('system') ? 'system' : 'agent';

    if (role === 'system') {
      return '<div class="msg-bubble system"><div class="msg-content">' +
        (isEnc ? '&#x1F512; 加密数据' : renderMarkdown(String(content.c || ''))) + '</div></div>';
    }
    if (isEnc && S.decryptedCache[m.id]) {
      return '<div class="msg-bubble ' + role + '">' +
        '<div class="msg-header"><span class="msg-role">' + (role === 'user' ? '你' : 'Agent') + '</span>' +
        '<span class="msg-time">' + time + '</span></div>' +
        '<div class="msg-content">' + S.decryptedCache[m.id] + '</div></div>';
    }
    if (isEnc) {
      const hint = S.masterKey ? '' : '（需设置主密钥）';
      return '<div class="msg-bubble ' + role + '">' +
        '<div class="msg-header"><span class="msg-role">' + (role === 'user' ? '你' : 'Agent') + '</span>' +
        '<span class="msg-time">' + time + '</span><span style="opacity:0.3">&#x1F512;</span></div>' +
        '<div class="msg-content"><span style="opacity:0.4">&#x1F512; 加密消息 seq=' + m.seq + '</span> ' +
        '<button class="msg-decrypt-btn" onclick="window._decryptMsg(\'' + m.id + '\')">解密</button>' + hint +
        '</div></div>';
    }
    // 明文消息 → Markdown 渲染
    return '<div class="msg-bubble ' + role + '">' +
      '<div class="msg-header"><span class="msg-role">' + (role === 'user' ? '你' : 'Agent') + '</span>' +
      '<span class="msg-time">' + time + '</span></div>' +
      '<div class="msg-content">' + renderMarkdown(String(content.c || '')) + '</div></div>';
  }

  // ─── 简易 Markdown 渲染 ─────────────────────
  function renderMarkdown(text) {
    if (!text) return '';
    let h = esc(text);
    // Code blocks (```...```)
    h = h.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
    // Inline code
    h = h.replace(/`([^`]+)`/g, '<code>$1</code>');
    // Bold **text** or __text__
    h = h.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    h = h.replace(/__([^_]+)__/g, '<strong>$1</strong>');
    // Italic *text* or _text_
    h = h.replace(/\*([^*]+)\*/g, '<em>$1</em>');
    h = h.replace(/_([^_]+)_/g, '<em>$1</em>');
    // Inline images ![alt](url)
    h = h.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" style="max-width:200px;border-radius:6px" />');
    // Links [text](url)
    h = h.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');
    // Line breaks
    h = h.replace(/\n/g, '<br>');
    return h;
  }

  // ─── 解密 ───────────────────────────────────
  function unwrapDek(wrappedB64, masterKeyB64) {
    const wrapped = base64ToBytes(wrappedB64), mk = base64ToBytes(masterKeyB64);
    if (wrapped.length < 56) throw new Error('wrapped DEK 太短');
    if (typeof nacl === 'undefined') throw new Error('需要 nacl');
    const epk = wrapped.slice(0, 32), nonce = wrapped.slice(32, 56), ct = wrapped.slice(56);
    const shared = nacl.box.before(epk, mk);
    const opened = nacl.secretbox.open(ct, nonce, shared);
    if (!opened) throw new Error('DEK 展开失败');
    return opened;
  }

  async function decryptEnvelope(cipherB64, dek) {
    const raw = base64ToBytes(cipherB64);
    if (raw.length < 28) throw new Error('密文太短');
    const nonce = raw.slice(0, 12), tag = raw.slice(12, 28), ct = raw.slice(28);
    const key = await crypto.subtle.importKey('raw', dek, { name: 'AES-GCM' }, false, ['decrypt']);
    const full = new Uint8Array(ct.length + tag.length);
    full.set(ct, 0); full.set(tag, ct.length);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, full);
    return JSON.parse(new TextDecoder().decode(pt));
  }

  window._decryptMsg = async function (msgId) {
    const msg = (S.messagesCache || []).find(m => m.id === msgId);
    if (!msg?.content?.c) { toast('无密文数据', 'error'); return; }
    if (!S.currentSessionDek) {
      if (!S.masterKey) { toast('请先在设置中保存主密钥', 'error'); return; }
      try {
        const data = await get('/v1/sessions/' + S.currentSessionId);
        const wrapped = data.session?.wrappedDek;
        if (!wrapped) { toast('此会话没有 DEK', 'error'); return; }
        S.currentSessionDek = unwrapDek(wrapped, S.masterKey);
      } catch (e) { toast('DEK 展开失败: ' + e.message, 'error'); return; }
    }
    try {
      const ev = await decryptEnvelope(msg.content.c, S.currentSessionDek);
      S.decryptedCache[msgId] = decryptToHtml(ev);
      loadMessages(S.currentSessionId);
      toast('解密成功', 'success');
    } catch (e) { toast('解密失败: ' + e.message, 'error'); }
  };

  function decryptToHtml(ev) {
    if (!ev || typeof ev !== 'object') return '<div class="msg-decrypted">' + esc(JSON.stringify(ev)) + '</div>';
    const t = ev.t || 'unknown';
    let h = '<div class="msg-decrypted">';
    if (t === 'text' || t === 'service') {
      if (ev.thinking) h += '<div class="ev-thinking">' + esc(ev.text) + '</div>';
      else h += '<div class="ev-text">' + renderMarkdown(ev.text || '') + '</div>';
      if (ev.images) for (const img of ev.images) h += '<img src="data:' + esc(img.mediaType) + ';base64,' + img.data + '" style="max-width:200px;border-radius:6px;margin:4px 0" />';
    } else if (t === 'tool-call-start') {
      h += '<div class="ev-tool"><span class="ev-tool-name">&#x1F6E0; ' + esc(ev.title || ev.name) + '</span>';
      if (ev.args) h += '<pre>' + esc(JSON.stringify(ev.args, null, 2)) + '</pre>'; h += '</div>';
    } else if (t === 'tool-call-end') {
      h += '<div class="ev-tool"><span class="ev-tool-name">&#x2705; ' + esc(ev.name || '') + '</span>';
      if (ev.result) h += '<pre>' + esc(ev.result) + '</pre>'; if (ev.error) h += '<span style="color:var(--danger)">（失败）</span>'; h += '</div>';
    } else if (t === 'question') {
      h += '<div class="ev-question"><span style="color:var(--warning)">&#x2753; 问题</span><p>' + esc(ev.text) + '</p></div>';
    } else if (t === 'permission-request') {
      h += '<div class="ev-permission">&#x26A0; 权限申请: <strong>' + esc(ev.toolName || '') + '</strong></div>';
    } else if (t === 'answer') h += '<div class="ev-text">&#x1F4AC; ' + esc(ev.text) + '</div>';
    else if (t === 'turn-end') {
      let line = '状态: ' + (ev.status || '');
      if (ev.model) line += ' | 模型: ' + ev.model;
      if (ev.usage) line += ' | Tokens: ' + (ev.usage.inputTokens || 0) + '→' + (ev.usage.outputTokens || 0);
      h += '<div class="ev-text" style="color:var(--text-muted)">' + line + '</div>';
    } else if (t === 'turn-start') h += '<div class="ev-text" style="color:var(--text-muted)">--- 新轮次 ---</div>';
    else if (t === 'start') h += '<div class="ev-text">&#x25B6; ' + (ev.title || '开始') + '</div>';
    else if (t === 'stop') h += '<div class="ev-text">&#x23F9; 结束</div>';
    else h += '<div class="ev-text">' + esc(JSON.stringify(ev)) + '</div>';
    h += '</div>'; return h;
  }

  // ─── 消息发送 ───────────────────────────────
  function sendMsg() {
    const input = $('#msg-input');
    const text = input.value.trim();
    if (!text || !S.currentSessionId) return;
    input.value = '';
    toast('发送中...', 'info');
    post('/v1/messages/send', {
      sessionId: S.currentSessionId,
      content: { t: 'plaintext', c: text },
      localId: 'user_' + Date.now(),
    }).then(r => {
      if (r.ok) { toast('已发送', 'success'); loadMessages(S.currentSessionId); }
      else toast('发送失败', 'error');
    }).catch(e => {
      input.value = text; // restore on failure
      toast('发送失败: ' + e.message, 'error');
    });
  }

  $('#btn-send').addEventListener('click', sendMsg);
  $('#msg-input').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMsg(); }
  });

  // ─── 会话操作 ───────────────────────────────
  $('#btn-stop-session').addEventListener('click', async () => {
    if (!S.currentSessionId || !confirm('确定停止该会话？')) return;
    try { await post('/v1/sessions/' + S.currentSessionId + '/stop'); toast('已停止', 'success'); navigate('sessions'); }
    catch (e) { toast('停止失败: ' + e.message, 'error'); }
  });
  $('#btn-session-close').addEventListener('click', () => navigate('sessions'));
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && currentPage === 'session') navigate('sessions');
  });
  // 点击 modal backdrop 关闭
  document.addEventListener('click', e => {
    if (e.target.closest('#new-session-modal')) {
      const modal = $('#new-session-modal');
      if (e.target === modal || e.target.classList.contains('modal-backdrop')) {
        modal.style.display = 'none';
      }
    }
  });

  // ─── 机器 ───────────────────────────────────
  async function loadMachines() {
    const grid = $('#machine-grid');
    if (!S.token) { grid.innerHTML = '<div class="empty-state">请先在设置中填入访问令牌</div>'; return; }
    try {
      const data = await get('/v1/machines');
      S.machines = data.machines || [];
      if (!data.machines.length) { grid.innerHTML = '<div class="empty-state">暂无已注册机器</div>'; return; }
      grid.innerHTML = data.machines.map(m =>
        '<div class="machine-card">' +
        '<span class="dot ' + (m.active ? 'online' : 'offline') + '"></span>' +
        '<div class="machine-host">' + esc(m.hostname || m.id) + '</div>' +
        '<div class="machine-detail">' + (m.platform || '') + ' ' + (m.arch || '') + '</div>' +
        '<div class="machine-agents">' + ((m.availableAgents || []).join(', ') || '') + '</div>' +
        '<span class="' + (m.active ? 'machine-online' : 'machine-offline') + '">' + (m.active ? '在线' : '离线') + '</span>' +
        '</div>'
      ).join('');
    } catch (e) { grid.innerHTML = '<div class="empty-state">加载失败: ' + esc(e.message) + '</div>'; }
  }

  // ─── 统计 ───────────────────────────────────
  async function loadInsights() {
    if (!S.token) return;
    try {
      const overview = await get('/v1/stats/overview');
      const s = overview.stats || {};
      const machines = await get('/v1/stats');
      $('#stat-sessions').textContent = s.totalSessions ?? '-';
      $('#stat-messages').textContent = s.totalMessages ?? '-';
      $('#stat-machines-online').textContent = machines.onlineMachines ?? 0;
      $('#stat-total-machines').textContent = machines.totalMachines ?? 0;
      const bd = $('#stats-breakdown');
      const daily = (s.dailyActivity || []).slice(-7).reverse();
      if (!daily.length) { bd.innerHTML = '<div class="empty-state">暂无近期活动</div>'; return; }
      bd.innerHTML = '<h3 style="font-size:14px;margin-bottom:10px;color:var(--text-secondary)">每日活动</h3>' +
        daily.map(d => '<div style="display:flex;gap:12px;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px">' +
          '<span style="width:90px;color:var(--text-muted)">' + d.date + '</span>' +
          '<span style="width:60px">' + d.sessionCount + ' 会话</span>' +
          '<span style="width:60px;color:var(--text-secondary)">' + d.messageCount + ' 消息</span></div>').join('');
    } catch {}
  }

  // ─── 任务 ───────────────────────────────────
  async function loadTasks() {
    const list = $('#task-items');
    if (!S.token) { list.innerHTML = '<div class="empty-state">请先在设置中填入访问令牌</div>'; return; }
    try {
      const data = await get('/v1/tasks');
      if (!data.tasks || !data.tasks.length) { list.innerHTML = '<div class="empty-state">暂无定时任务</div>'; return; }
      list.innerHTML = data.tasks.map(t =>
        '<div class="machine-card">' +
        '<span class="dot ' + (t.enabled ? 'online' : 'offline') + '"></span>' +
        '<div class="machine-host">' + esc(t.name) + '</div>' +
        '<div class="machine-detail">' + t.schedule + '</div>' +
        '<div class="machine-agents">' + (t.enabled ? '已启用' : '已禁用') + '</div></div>'
      ).join('');
    } catch (e) { list.innerHTML = '<div class="empty-state">' + esc(e.message) + '</div>'; }
  }

  // ─── 设置 ───────────────────────────────────
  function loadSettings() {
    $('#set-token').value = S.token;
    $('#set-master-key').value = S.masterKey;
    loadCB();
  }
  $('#btn-save-token').addEventListener('click', () => {
    const val = $('#set-token').value.trim();
    if (!val) { toast('请输入令牌', 'error'); return; }
    S.token = val; localStorage.setItem('token', val);
    toast('令牌已保存', 'success');
    connectSocket(); loadSessions();
  });
  $('#set-master-key').addEventListener('change', function () {
    S.masterKey = this.value.trim(); localStorage.setItem('masterKey', S.masterKey);
  });
  async function loadCB() {
    const el = $('#cb-output');
    try {
      if (!S.token) { el.textContent = '请先设置令牌'; return; }
      const data = await get('/v1/circuit-breakers');
      const cbs = data.circuitBreakers || {};
      if (Object.keys(cbs).length === 0) { el.textContent = '暂无熔断器事件'; return; }
      el.textContent = Object.entries(cbs).map(([k, v]) => k + ': ' + v.state + ' (' + v.failuresInWindow + '/' + v.threshold + ')').join('\n');
    } catch (e) { el.textContent = '加载失败: ' + e.message; }
  }
  $('#btn-reset-cb').addEventListener('click', async () => {
    try { await post('/v1/circuit-breakers/reset'); toast('已重置', 'success'); loadCB(); }
    catch (e) { toast('重置失败', 'error'); }
  });

  // ─── 初始化 ─────────────────────────────────
  bindNav();
  if (S.token) connectSocket();
  navigate('sessions');
})();
