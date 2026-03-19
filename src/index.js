/**
 * EmotionalSpace Edge Router — READ-ONLY v4 (Defense Hardened)
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

/** 404 — redirect to main platform. */
/** 404 — redirect to main platform. */
function notFoundResponse() {
  return Response.redirect('https://www.moodspace.xyz', 302);
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
  <p><a href="https://www.moodspace.xyz">← 返回主页</a></p>
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

  // ── /assets/ and /preview/ work on any hostname (incl. workers.dev for local dev) ──
  // www.moodspace.xyz is served by VPS Nginx — Worker never touches it.

  // ── GET /assets/{type}/{...filepath} — static template assets
  if (path.startsWith('/assets/')) {
    const parts = path.split('/');
    const type = parts[2];
    const filePath = parts.slice(3).join('/');

    const meta = await getTemplateMeta(env.MOODSPACE_KV, type);
    if (!meta) return new Response('Not found', { status: 404 });

    const obj = await env.MOODSPACE_R2.get(`templates/${type}/${meta.version}/${filePath}`);
    if (!obj) return new Response('Asset not found', { status: 404 });

    return new Response(obj.body, {
      headers: {
        'Content-Type': getMime(filePath),
        'Cache-Control': 'public, max-age=31536000, immutable',
        ...SEC_HEADERS,
      },
    });
  }

  // ── GET /preview/{type} — render template with schema defaults
  if (path.startsWith('/preview/')) {
    const type = path.split('/')[2];
    const meta = await getTemplateMeta(env.MOODSPACE_KV, type);
    if (!meta) return new Response('Template not found', { status: 404 });

    const [htmlObj, schemaObj] = await Promise.all([
      env.MOODSPACE_R2.get(`templates/${type}/${meta.version}/index.html`),
      env.MOODSPACE_R2.get(`templates/${type}/${meta.version}/schema.json`),
    ]);
    if (!htmlObj) return new Response('Template HTML missing in R2', { status: 404 });

    const html = await htmlObj.text();
    const schema = schemaObj ? JSON.parse(await schemaObj.text()) : null;
    const data = {};
    (schema?.fields ?? []).forEach((f) => {
      const key = typeof f === 'string' ? f : (f.id || f.key);
      const defaultValue = typeof f === 'string' ? (f.default ?? '') : (f.default ?? '');
      data[key] = defaultValue;
    });

    const rendered = html.replace(/\{\{(\w+)\}\}/g, (match, key) => {
      const val = data[key] ?? '';
      return escapeHtml(String(val));
    });

    return new Response(rendered, {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-cache, no-store',
        ...SEC_HEADERS,
      },
    });
  }


  // ── USER SUBDOMAIN ─────────────────────────────────────────────
  const subdomain = host.split('.')[0];

  if (!/^[a-zA-Z0-9-]{1,64}$/.test(subdomain)) {
    return notFoundResponse();
  }

  // ── Bot filter: protect KV/R2 quota from scrapers ────────────
  // Strategy: whitelist-first. Allow known legit bots (SEO, social preview),
  // then block anything that still looks like a bot/script.
  const ua = request.headers.get('User-Agent') ?? '';
  const WHITELIST = /Googlebot|Bingbot|facebookexternalhit|Twitterbot|LinkedInBot|Slackbot|Discordbot|TelegramBot|WhatsApp|Applebot/i;
  const BLOCKLIST = /python-requests|go-http|curl\/|wget|scrapy|nikto|masscan|zgrab|headless|phantom|selenium|puppeteer/i;
  if (!WHITELIST.test(ua) && BLOCKLIST.test(ua)) {
    return new Response('Forbidden', { status: 403, headers: { ...SEC_HEADERS } });
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
    const cfgRaw = await env.MOODSPACE_KV.get(subdomain);
    if (!cfgRaw) return notFoundResponse();

    const obj = await fetchPageHtml(env.MOODSPACE_R2, subdomain);
    if (!obj) return notFoundResponse();

    return new Response(await obj.text(), {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        ...SEC_HEADERS,
      },
    });
  }

  // ── Normal mode: Cache API → KV → R2 → Lazy version check ────
  // Normalize URL for caching (Strip query params so that cache purge by URL works)
  const cacheUrl = new URL(request.url);
  cacheUrl.search = "";
  const cacheKey = new Request(cacheUrl.toString());
  const cached = await caches.default.match(cacheKey);
  if (cached) return cached;

  const cfgRaw = await env.MOODSPACE_KV.get(subdomain);
  if (!cfgRaw) return notFoundResponse();

  let cfg;
  try { cfg = JSON.parse(cfgRaw); } catch { return notFoundResponse(); }

  const obj = await fetchPageHtml(env.MOODSPACE_R2, subdomain);
  if (!obj) return notFoundResponse();

  let html = await obj.text();

  // ── Lazy Version Check (Stale-While-Revalidate) ───────────────
  // Compare the tmpl-version stamp in the stored HTML against the current KV meta.
  // If stale, trigger a one-shot background re-render on the VPS — no R2 writes here.
  if (cfg.template) {
    const tmplMeta = await getTemplateMeta(env.MOODSPACE_KV, cfg.template);
    if (tmplMeta?.version) {
      const isStale = !html.includes(`<meta name="tmpl-version" content="${tmplMeta.version}">`);
      if (isStale) {
        console.log(`[Worker] Stale page detected for ${subdomain} (want: ${tmplMeta.version}). Triggering lazy re-render.`);
        ctx.waitUntil(
          Promise.race([
            fetch(`https://api.885201314.xyz/api/project/re-render/${subdomain}`, {
              method: 'POST',
              headers: {
                'X-Admin-Key': env.ADMIN_KEY ?? '',
                'X-Internal-Source': 'worker',
                'Content-Type': 'application/json',
              },
            }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000)),
          ]).catch((e) => console.error('[Worker] Lazy re-render failed:', e.message))
        );
        // Serve stale content immediately — user gets the old version for now,
        // and will see the updated version on the next CDN miss (after re-render + cache purge).
      }
    }
  }

  const response = new Response(html, {
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'public, max-age=86400, s-maxage=86400, must-revalidate', // 24h cache
      ...SEC_HEADERS,
    },
  });

  ctx.waitUntil(caches.default.put(cacheKey, response.clone()));
  return response;
}

