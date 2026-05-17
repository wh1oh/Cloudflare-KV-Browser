// 保留的 env 变量名（不能作为 KV namespace）
const RESERVED_ENV = new Set(['SECRET_KEY', 'PASSWORD', 'USER']);

export default {
  async fetch(request, env) {

    // ── 必需环境变量检查 ───────────────────────────────────────────────────────

    if (!env.SECRET_KEY || !env.PASSWORD || !env.USER) {
      return html(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>KV Manager</title>
<style>
*{ box-sizing:border-box; }
body{ margin:0; height:100vh; display:flex; align-items:center; justify-content:center; background:#f5f5f5; font-family:Inter,sans-serif; }
.box{ width:360px; background:#fff; border:1px solid #e5e5e5; border-radius:16px; padding:24px; }
h1{ margin:0 0 12px; font-size:20px; }
p{ margin:0 0 16px; font-size:14px; color:#555; line-height:1.6; }
code{ background:#f3f3f3; border-radius:6px; padding:2px 6px; font-size:13px; }
</style>
</head>
<body>
<div class="box">
<h1>Configuration Required</h1>
<p>Please set the following environment variables in your Worker settings:</p>
<p><code>USER</code> &nbsp; <code>PASSWORD</code> &nbsp; <code>SECRET_KEY</code></p>
</div>
</body>
</html>`);
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    // ── cookies ───────────────────────────────────────────────────────────────

    const cookieHeader = request.headers.get('Cookie') || '';

    const cookies = Object.fromEntries(
      cookieHeader.split(';').map(c => {
        const [k, ...v] = c.trim().split('=');
        return [k.trim(), v.join('=')];
      })
    );

    // ── login ─────────────────────────────────────────────────────────────────

    if (path === '/login' && request.method === 'POST') {

      const fd = await request.formData();

      const userOk = fd.get('user') === env.USER;
      const passOk = await verifyPassword(
        fd.get('pass') || '',
        env.PASSWORD,
        env.SECRET_KEY
      );

      if (userOk && passOk) {

        // 生成签名 cookie：payload 只存 expire，不暴露用户名
        const expire  = Date.now() + 86400 * 1000; // 24 小时
        const payload = String(expire);
        const sig     = await hmacSign(payload, env.SECRET_KEY);
        const token   = btoa(payload) + '.' + sig;

        return redirect('/', {
          'Set-Cookie':
            `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`
        });
      }

      return html(loginPage('Wrong username or password'));
    }

    // ── logout ────────────────────────────────────────────────────────────────

    if (path === '/logout') {
      return redirect('/', {
        'Set-Cookie': 'session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict'
      });
    }

    // ── auth ──────────────────────────────────────────────────────────────────

    const sessionValid = await verifySession(
      cookies.session,
      env.SECRET_KEY
    );

    if (!sessionValid) {
      return html(loginPage());
    }

    // ── download ──────────────────────────────────────────────────────────────

    if (path === '/download') {

      const ns  = url.searchParams.get('ns');
      const key = url.searchParams.get('key');

      if (RESERVED_ENV.has(ns)) return new Response('Not found', { status: 404 });

      const kv = env[ns];
      if (!kv || typeof kv.get !== 'function') return new Response('Not found', { status: 404 });

      const file = await kv.get(key, { type: 'arrayBuffer' });
      if (!file) return new Response('Not found', { status: 404 });

      return new Response(file, {
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${encodeURIComponent(key)}"`
        }
      });
    }

    // ── actions ───────────────────────────────────────────────────────────────

    if (request.method === 'POST') {

      const fd     = await request.formData();
      const action = fd.get('action');
      const ns     = fd.get('ns');

      if (RESERVED_ENV.has(ns)) return new Response('Not found', { status: 404 });

      const kv = env[ns];
      if (!kv || typeof kv.get !== 'function') return new Response('Not found', { status: 404 });

      try {

        if (action === 'upload') {

          const file = fd.get('file');
          if (!file) throw new Error('No file selected');

          const buf = await file.arrayBuffer();

          await kv.put(file.name, new Uint8Array(buf), {
            metadata: {
              size: buf.byteLength,
              contentType: file.type || 'application/octet-stream'
            }
          });

          return redirect(
            '/?ns='  + encodeURIComponent(ns) +
            '&key='  + encodeURIComponent(file.name) +
            '&ok=uploaded'
          );
        }

        if (action === 'delete') {

          const key   = fd.get('key');
          const token = fd.get('delete_token');
          if (!key) throw new Error('Missing key');

          // 服务端验证删除 token，防止绕过前端 confirm 直接 POST
          const expectedToken = await hmacSign(`delete:${ns}:${key}`, env.SECRET_KEY);
          if (!token || !timingSafeEqual(token, expectedToken)) {
            throw new Error('Invalid delete token');
          }

          await kv.delete(key);

          return redirect(
            '/?ns='       + encodeURIComponent(ns) +
            '&ok=deleted' +
            '&deleted='   + encodeURIComponent(key)
          );
        }

      } catch (e) {
        return redirect('/?err=' + encodeURIComponent(e.message));
      }
    }

    const kvList = await getKVList(env);
    return html(await render(kvList, url, env));
  }
};

// ── security helpers ──────────────────────────────────────────────────────────

async function hmacSign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 验证 session cookie
 * 格式：base64(expire).hmac
 */
async function verifySession(token, secret) {
  if (!token) return false;
  try {
    const dotIdx = token.lastIndexOf('.');
    if (dotIdx === -1) return false;

    const b64     = token.slice(0, dotIdx);
    const sig     = token.slice(dotIdx + 1);
    const payload = atob(b64);

    const expectedSig = await hmacSign(payload, secret);
    if (!timingSafeEqual(sig, expectedSig)) return false;

    const expire = parseInt(payload, 10);
    if (!expire || Date.now() > expire) return false;

    return true;
  } catch {
    return false;
  }
}

async function verifyPassword(input, stored, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const [sigInput, sigStored] = await Promise.all([
    crypto.subtle.sign('HMAC', key, enc.encode(input)),
    crypto.subtle.sign('HMAC', key, enc.encode(stored))
  ]);
  const toHex = buf =>
    Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  return timingSafeEqual(toHex(sigInput), toHex(sigStored));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ── misc helpers ──────────────────────────────────────────────────────────────

const EXT_TYPE = {
  js:   'application/javascript',
  json: 'application/json',
};

function guessType(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  return EXT_TYPE[ext] || 'application/octet-stream';
}

async function getKVList(env) {
  const out = {};
  for (const k in env) {
    if (RESERVED_ENV.has(k)) continue; // 跳过保留变量
    if (env[k] && typeof env[k].list === 'function') {
      try {
        const list  = await env[k].list({ limit: 1000 });
        const items = await Promise.all(
          list.keys.map(async i => {
            if (i.metadata?.size) {
              return { name: i.name, size: i.metadata.size, type: i.metadata.contentType || 'unknown' };
            }
            try {
              const buf = await env[k].get(i.name, { type: 'arrayBuffer' });
              if (!buf) return { name: i.name, size: 0, type: 'unknown' };
              const size        = buf.byteLength;
              const contentType = guessType(i.name);
              await env[k].put(i.name, new Uint8Array(buf), { metadata: { size, contentType } });
              return { name: i.name, size, type: contentType };
            } catch {
              return { name: i.name, size: 0, type: 'unknown' };
            }
          })
        );
        out[k] = items;
      } catch {
        out[k] = [];
      }
    }
  }
  return out;
}

function fmt(bytes) {
  if (bytes < 1024)         return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1024 / 1024).toFixed(1) + ' MB';
}

function esc(s = '') {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function redirect(url, headers = {}) {
  return new Response('', { status: 302, headers: { Location: url, ...headers } });
}

function html(body) {
  return new Response(body, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

// ── login page ────────────────────────────────────────────────────────────────

function loginPage(err = '') {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>KV Manager</title>
<style>
*{ box-sizing:border-box; }
body{ margin:0; height:100vh; display:flex; align-items:center; justify-content:center; background:#f5f5f5; font-family:Inter,sans-serif; }
.box{ width:320px; background:#fff; border:1px solid #e5e5e5; border-radius:16px; padding:24px; }
h1{ margin:0 0 20px; font-size:20px; }
input{ width:100%; padding:12px; margin-bottom:12px; border:1px solid #ddd; border-radius:10px; }
button{ width:100%; border:none; background:#111; color:#fff; padding:12px; border-radius:10px; cursor:pointer; }
.err{ color:#dc2626; margin-bottom:14px; font-size:14px; }
</style>
</head>
<body>
<div class="box">
<h1>KV Manager</h1>
${err ? `<div class="err">${esc(err)}</div>` : ''}
<form method="POST" action="/login">
<input name="user" placeholder="Username" required autocomplete="username"/>
<input name="pass" type="password" placeholder="Password" required autocomplete="current-password"/>
<button>Login</button>
</form>
</div>
</body>
</html>`;
}

// ── main ui ───────────────────────────────────────────────────────────────────

async function render(kvList, url, env) {

  const namespaces  = Object.keys(kvList);
  const firstNs     = namespaces[0] || '';
  const selectedNs  = url.searchParams.get('ns')      || firstNs;
  const selectedKey = url.searchParams.get('key')     || '';
  const deletedKey  = url.searchParams.get('deleted') || '';
  const files       = (kvList[selectedNs] || []).filter(f => f.name !== deletedKey);
  const current     = files.find(f => f.name === selectedKey);

  // 为当前选中文件预计算删除 token
  const deleteToken = current
    ? await hmacSign(`delete:${selectedNs}:${current.name}`, env.SECRET_KEY)
    : '';

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>KV File Manager</title>
<style>
*{ box-sizing:border-box; }
body{ margin:0; font-family:Inter,sans-serif; background:#f5f5f5; color:#111; }
.top{ height:60px; background:#fff; border-bottom:1px solid #e5e5e5; display:flex; align-items:center; justify-content:space-between; padding:0 20px; position:sticky; top:0; z-index:20; }
.logo{ font-weight:700; }
.layout{ display:flex; height:calc(100vh - 60px); }
.sidebar{ width:300px; background:#fff; border-right:1px solid #e5e5e5; overflow:auto; }
.main{ flex:1; overflow:auto; padding:24px; }
.ns-select{ padding:16px; border-bottom:1px solid #eee; position:sticky; top:0; background:#fff; z-index:5; }
.ns{ width:100%; padding:12px; border:1px solid #ddd; border-radius:10px; background:#fff; }
.file{ display:block; padding:12px 16px; text-decoration:none; color:#111; border-top:1px solid #f3f3f3; }
.file:hover{ background:#f7f7f7; }
.file.active{ background:#111; color:#fff; }
.meta{ margin-top:4px; font-size:12px; opacity:.7; }
.card{ background:#fff; border:1px solid #e5e5e5; border-radius:16px; padding:24px; margin-bottom:20px; }
.title{ font-size:14px; font-weight:700; margin-bottom:16px; }
.upload{ border:2px dashed #ddd; border-radius:12px; padding:40px; text-align:center; }
.btn{ display:inline-flex; align-items:center; justify-content:center; border:none; border-radius:10px; padding:12px 18px; cursor:pointer; text-decoration:none; font-size:14px; }
.black{ background:#111; color:#fff; }
.red{ background:#ef4444; color:#fff; }
.gray{ background:#eee; color:#111; }
.row{ display:flex; gap:12px; margin-top:16px; }
.ok{ color:#16a34a; margin-bottom:20px; }
.err{ color:#dc2626; margin-bottom:20px; }
.empty{ color:#888; padding:20px; }
.menu-btn{ display:none; border:none; background:none; font-size:24px; cursor:pointer; }
input[type=file]{ width:100%; padding:12px; border:1px solid #ddd; border-radius:10px; margin-bottom:16px; background:#fff; }
.preview{ width:100%; max-width:420px; border-radius:12px; margin-bottom:16px; border:1px solid #eee; display:block; }
@media (max-width:768px){
  .menu-btn{ display:block; }
  .sidebar{ position:fixed; top:60px; left:-100%; bottom:0; width:82%; max-width:320px; z-index:100; transition:.25s; box-shadow:0 0 20px rgba(0,0,0,.08); }
  .sidebar.show{ left:0; }
  .main{ width:100%; padding:16px; }
  .upload{ padding:24px 16px; }
  .row{ flex-direction:column; }
  .row .btn{ width:100%; }
  .top{ padding:0 14px; }
}
</style>
</head>
<body>

<div class="top">
  <div style="display:flex;align-items:center;gap:12px;">
    <button class="menu-btn" onclick="toggleSidebar()">☰</button>
    <div class="logo">KV FILE MANAGER</div>
  </div>
  <a href="/logout" class="btn gray">Logout</a>
</div>

<div class="layout">
<div class="sidebar">
<div class="ns-select">
<select class="ns" onchange="location.href='/?ns='+encodeURIComponent(this.value)">
${namespaces.map(ns => `<option value="${esc(ns)}" ${ns === selectedNs ? 'selected' : ''}>${esc(ns)} (${kvList[ns].length})</option>`).join('')}
</select>
</div>
${files.length ? files.map(file => {
  const active = file.name === selectedKey;
  return `<a class="file ${active ? 'active' : ''}" href="/?ns=${encodeURIComponent(selectedNs)}&key=${encodeURIComponent(file.name)}">
    <div>${esc(file.name)}</div>
    <div class="meta">${esc(file.type)} · ${fmt(file.size)}</div>
  </a>`;
}).join('') : `<div class="empty">Empty namespace</div>`}
</div>

<div class="main">
${url.searchParams.get('ok') === 'uploaded' ? `<div class="ok">File uploaded</div>` : ''}
${url.searchParams.get('ok') === 'deleted'  ? `<div class="ok">File deleted</div>`  : ''}
${url.searchParams.get('err') ? `<div class="err">${esc(url.searchParams.get('err'))}</div>` : ''}

<div class="card">
<div class="title">Upload File</div>
<form method="POST" enctype="multipart/form-data">
<input type="hidden" name="action" value="upload"/>
<input type="hidden" name="ns" value="${esc(selectedNs)}"/>
<div class="upload">
<input type="file" name="file" required/>
<button class="btn black">Upload</button>
</div>
</form>
</div>

<div class="card">
<div class="title">Selected File</div>
${current ? `
${current.type.startsWith('image/') ? `<img class="preview" src="/download?ns=${encodeURIComponent(selectedNs)}&key=${encodeURIComponent(current.name)}"/>` : ''}
<div style="font-size:18px;font-weight:600;word-break:break-all;">${esc(current.name)}</div>
<div style="margin-top:8px;color:#666;font-size:14px;">${esc(current.type)} · ${fmt(current.size)}</div>
<div class="row">
<a class="btn black" href="/download?ns=${encodeURIComponent(selectedNs)}&key=${encodeURIComponent(current.name)}">Download</a>
<form method="POST">
<input type="hidden" name="action" value="delete"/>
<input type="hidden" name="ns" value="${esc(selectedNs)}"/>
<input type="hidden" name="key" value="${esc(current.name)}"/>
<input type="hidden" name="delete_token" value="${esc(deleteToken)}"/>
<button class="btn red" onclick="return confirm('Delete this file?')">Delete</button>
</form>
</div>
` : `<div class="empty">Select a file from the sidebar</div>`}
</div>
</div>
</div>

<script>
function toggleSidebar(){
  document.querySelector('.sidebar').classList.toggle('show');
}
document.addEventListener('click', e => {
  const sb  = document.querySelector('.sidebar');
  const btn = document.querySelector('.menu-btn');
  if (window.innerWidth <= 768 && sb.classList.contains('show') &&
      !sb.contains(e.target) && !btn.contains(e.target)) {
    sb.classList.remove('show');
  }
});
</script>
</body>
</html>`;
}
