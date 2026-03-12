/**
 * RomanceSpace Edge Router — READ-ONLY v4 (Defense Hardened)
 *
 * Architecture (CQRS read-side):
 *   All writes (template upload, page render, KV updates) are handled by the VPS backend.
 *   This Worker only reads KV/R2 and serves cached HTML to end users.
 *
 * Flow for user subdomain requests:
 *   1. Validate projectId format (alphanumeric + hyphen, max 64 chars)
 *   2. Check caches.default (free, fastest)
 *   3. If ?preview=xxx → bypass cache, read R2 directly, return no-cache response
 *   4. Otherwise: read KV for routing, read R2 for HTML, inject security headers + viral footer, cache 1 hour
 *
 * Defense Layer (v4 additions):
 *   - Strict projectId RegEx validation rejects malicious hostnames before any KV/R2 hit
 *   - preview param length limited to 64 chars (prevents cache-busting exhaustion)
 *   - Global try/catch for graceful 500 fallback on Cloudflare infra failures
 *   - Security headers on all HTML responses (nosniff, XSS protection, frame options)
 */

// ── Security Headers ──────────────────────────────────────────────────────────

const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-XSS-Protection': '1; mode=block',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

// ── Utilities ─────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  if (typeof str !== 'string') str = String(str ?? '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Map file extensions to MIME types. */
function getMime(filename) {
  const ext = (filename.split('.').pop() ?? '').toLowerCase();
  return (
    {
      html: 'text/html;charset=UTF-8',
      css: 'text/css',
      js: 'application/javascript',
      json: 'application/json',
      png: 'image/png',
      jpg: 'image/jpeg',
      jpeg: 'image/jpeg',
      gif: 'image/gif',
      svg: 'image/svg+xml',
      webp: 'image/webp',
      woff: 'font/woff',
      woff2: 'font/woff2',
      ttf: 'font/ttf',
      mp3: 'audio/mpeg',
      ogg: 'audio/ogg',
    }[ext] ?? 'application/octet-stream'
  );
}

/** Inject viral footer link before </body>. */
function injectViralFooter(html) {
  const viralHtml = `
  <div style="text-align:center; padding: 20px 0; background: transparent; font-family: sans-serif; position: relative; z-index: 9999;">
    <a href="https://www.885201314.xyz" target="_blank" style="display:inline-block; padding:8px 16px; background:rgba(255,255,255,0.8); border-radius:20px; color:#d6336c; font-size:12px; font-weight:bold; text-decoration:none; box-shadow:0 2px 10px rgba(0,0,0,0.1); backdrop-filter:blur(4px);">
      ✨ 想要制作同款浪漫网页？点击创建你的专属页面 ✨
    </a>
  </div>`;
  const bodyEndIdx = html.lastIndexOf('</body>');
  if (bodyEndIdx !== -1) {
    return html.substring(0, bodyEndIdx) + viralHtml + '\n' + html.substring(bodyEndIdx);
  }
  return html + '\n' + viralHtml;
}

/** 404 — redirect to main platform. */
function notFoundResponse() {
  return Response.redirect('https://www.885201314.xyz', 302);
}

/** 500 — graceful error page for infrastructure failures. */
function serverErrorResponse(detail = '') {
  const body = `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>暂时无法访问</title>
  <style>
    body { font-family: sans-serif; display: flex; flex-direction: column; align-items: center;
           justify-content: center; min-height: 100vh; margin: 0; background: #fff5f7; color: #555; }
    h1 { color: #d6336c; font-size: 2rem; margin-bottom: .5rem; }
    p { font-size: 1rem; }
    a { color: #d6336c; text-decoration: none; }
  </style>
</head>
<body>
  <h1>💔 页面暂时无法加载</h1>
  <p>服务器正在努力恢复中，请稍后再试。</p>
  <p><a href="https://www.885201314.xyz">← 返回 RomanceSpace 主页</a></p>
</body>
</html>`;
  return new Response(body, {
    status: 500,
    headers: { 'Content-Type': 'text/html;charset=UTF-8', ...SEC_HEADERS },
  });
}

/**
 * Fetch page HTML from R2.
 * Strategy: try folder-based path first (new standard), fall back to legacy flat file.
 */
async function fetchPageHtml(r2, projectId) {
  let obj = await r2.get(`pages/${projectId}/index.html`);
  if (!obj) {
    obj = await r2.get(`pages/${projectId}.html`);
  }
  return obj;
}

// ── Global Memoization Cache ─────────────────────────────────────────────────
// These persist as long as the Worker isolate is warm.
// Greatly reduces KV read quota usage for high-traffic assets.
const templateCache = new Map();

async function getTemplateMeta(kv, type) {
  if (templateCache.has(type)) {
    return templateCache.get(type);
  }
  const raw = await kv.get(`__tmpl__${type}`);
  if (!raw) return null;
  try {
    const meta = JSON.parse(raw);
    templateCache.set(type, meta);
    return meta;
  } catch (e) {
    return null;
  }
}

// ── Main handler ──────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      console.error('[Worker Fatal]', err?.message ?? err);
      return serverErrorResponse();
    }
  },
};

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const host = url.hostname;
  const path = url.pathname;
  const method = request.method;

  // ── 0. Doc site passthrough ────────────────────────────────────
  if (host === 'docs.885201314.xyz' || host === 'document.885201314.xyz') {
    const fwd = new URL(request.url);
    fwd.hostname = 'romancespace-docs.pages.dev';
    return fetch(fwd.toString(), request);
  }

  // ── MAIN DOMAIN (Platform Homepage / Assets) ───────────────────
  const isMainDomain =
    host === 'romancespace.885201314.xyz' || host === 'www.885201314.xyz' || host.includes('workers.dev');

  if (isMainDomain) {
    if (method !== 'GET') {
      return new Response(
        JSON.stringify({ error: 'Write operations are handled by the VPS backend API.' }),
        { status: 405, headers: { 'Content-Type': 'application/json', ...SEC_HEADERS } }
      );
    }

    // ── GET /assets/{type}/{...filepath} — static template assets
    if (path.startsWith('/assets/')) {
      const parts = path.split('/'); 
      const type = parts[2];
      const filePath = parts.slice(3).join('/');

      const meta = await getTemplateMeta(env.ROMANCESPACE_KV, type);
      if (!meta) return new Response('Not found', { status: 404 });

      const obj = await env.ROMANCESPACE_R2.get(`templates/${type}/${meta.version}/${filePath}`);
      if (!obj) return new Response('Asset not found', { status: 404 });

      return new Response(obj.body, {
        headers: {
          'Content-Type': getMime(filePath),
          'Cache-Control': 'public, max-age=31536000, immutable', // 1 year (asset is versioned by parent folder)
          ...SEC_HEADERS,
        },
      });
    }

    // ── GET /preview/{type} — render template with schema defaults
    if (path.startsWith('/preview/')) {
      const type = path.split('/')[2];
      const meta = await getTemplateMeta(env.ROMANCESPACE_KV, type);
      if (!meta) return new Response('Template not found', { status: 404 });

      const [htmlObj, schemaObj] = await Promise.all([
        env.ROMANCESPACE_R2.get(`templates/${type}/${meta.version}/index.html`),
        env.ROMANCESPACE_R2.get(`templates/${type}/${meta.version}/schema.json`),
      ]);
      if (!htmlObj) return new Response('Template HTML missing in R2', { status: 404 });

      const html = await htmlObj.text();
      const schema = schemaObj ? JSON.parse(await schemaObj.text()) : null;
      const defaults = {};
      (schema?.fields ?? []).forEach((f) => {
        if (f.default !== undefined) defaults[f.key] = f.default;
      });

      return new Response(html.replace(/\{\{(\w+)\}\}/g, (m, k) => escapeHtml(defaults[k] ?? '')), {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'no-cache, no-store',
          ...SEC_HEADERS,
        },
      });
    }

    if (host === 'romancespace.885201314.xyz') {
      return Response.redirect('https://www.885201314.xyz' + path, 301);
    }

    if (host === 'www.885201314.xyz') {
      return new Response('Frontend works, please configure Cloudflare Pages Custom Domains.', { status: 200 });
    }

    return notFoundResponse();
  }

  // ── USER SUBDOMAIN ─────────────────────────────────────────────
  const subdomain = host.split('.')[0];

  if (!/^[a-zA-Z0-9-]{1,64}$/.test(subdomain)) {
    return notFoundResponse();
  }

  const isPreview = url.searchParams.has('preview');

  if (isPreview) {
    const previewVal = url.searchParams.get('preview') ?? '';
    if (previewVal.length > 64) {
      url.searchParams.delete('preview');
      return Response.redirect(url.toString(), 302);
    }
  }

  // ── Preview mode: bypass all caches, read R2 directly ─────────
  if (isPreview) {
    const cfgRaw = await env.ROMANCESPACE_KV.get(subdomain);
    if (!cfgRaw) return notFoundResponse();

    const obj = await fetchPageHtml(env.ROMANCESPACE_R2, subdomain);
    if (!obj) return notFoundResponse();

    return new Response(await obj.text(), {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        ...SEC_HEADERS,
      },
    });
  }

  // ── Normal mode: Cache API → KV → R2 → Cache ──────────────────
  const cacheKey = new Request(`https://cache.rs.internal/${subdomain}`);
  const cached = await caches.default.match(cacheKey);
  if (cached) return cached;

  const cfgRaw = await env.ROMANCESPACE_KV.get(subdomain);
  if (!cfgRaw) return notFoundResponse();

  const obj = await fetchPageHtml(env.ROMANCESPACE_R2, subdomain);
  if (!obj) return notFoundResponse();

  const html = injectViralFooter(await obj.text());

  const response = new Response(html, {
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'public, max-age=86400, s-maxage=86400', // 24 hours (VPS can purge if needed)
      ...SEC_HEADERS,
    },
  });

  ctx.waitUntil(caches.default.put(cacheKey, response.clone()));
  return response;
}

