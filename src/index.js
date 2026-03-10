/**
 * RomanceSpace Edge Router — READ-ONLY v3
 *
 * Architecture (CQRS read-side):
 *   All writes (template upload, page render, KV updates) are handled by the VPS backend.
 *   This Worker only reads KV/R2 and serves cached HTML to end users.
 *
 * Flow for user subdomain requests:
 *   1. Check caches.default (free, fastest)
 *   2. If ?preview=xxx → bypass cache, read R2 directly, return no-cache response
 *   3. Otherwise: read KV for routing, read R2 for HTML, cache result for 1 hour
 */

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

/** 404 HTML response with auto-redirect to main domain. */
function notFoundResponse() {
  return Response.redirect('https://www.885201314.xyz', 302);
}

// ── Main handler ──────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
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
      // Reject any non-GET write attempts — all writes go to the VPS backend
      if (method !== 'GET') {
        return new Response(
          JSON.stringify({ error: 'Write operations are handled by the VPS backend API.' }),
          { status: 405, headers: { 'Content-Type': 'application/json' } }
        );
      }

      // ── GET /assets/{type}/{...filepath} — static template assets
      if (path.startsWith('/assets/')) {
        const parts = path.split('/'); // ['', 'assets', type, ...rest]
        const type = parts[2];
        const filePath = parts.slice(3).join('/');

        const tmplRaw = await env.ROMANCESPACE_KV.get(`__tmpl__${type}`);
        if (!tmplRaw) return new Response('Not found', { status: 404 });
        const { version } = JSON.parse(tmplRaw);

        const obj = await env.ROMANCESPACE_R2.get(`templates/${type}/${version}/${filePath}`);
        if (!obj) return new Response('Asset not found', { status: 404 });

        return new Response(obj.body, {
          headers: {
            'Content-Type': getMime(filePath),
            'Cache-Control': 'public, max-age=604800, immutable', // 7 days for assets
          },
        });
      }

      // ── GET /preview/{type} — render template with schema defaults
      if (path.startsWith('/preview/')) {
        const type = path.split('/')[2];
        const tmplRaw = await env.ROMANCESPACE_KV.get(`__tmpl__${type}`);
        if (!tmplRaw) return new Response('Template not found', { status: 404 });

        const { version } = JSON.parse(tmplRaw);
        const [htmlObj, schemaObj] = await Promise.all([
          env.ROMANCESPACE_R2.get(`templates/${type}/${version}/index.html`),
          env.ROMANCESPACE_R2.get(`templates/${type}/${version}/schema.json`),
        ]);
        if (!htmlObj) return new Response('Template HTML missing in R2', { status: 404 });

        const html = await htmlObj.text();
        const schema = schemaObj ? JSON.parse(await schemaObj.text()) : null;
        const defaults = {};
        (schema?.fields ?? []).forEach((f) => {
          if (f.default !== undefined) defaults[f.key] = f.default;
        });

        // Preview is NOT cached (no injectViralFooter on preview)
        return new Response(html.replace(/\{\{(\w+)\}\}/g, (m, k) => defaults[k] ?? ''), {
          headers: {
            'Content-Type': 'text/html;charset=UTF-8',
            'Cache-Control': 'no-cache, no-store',
          },
        });
      }

      // If it's romancespace.885201314.xyz (old main domain) but not assets/preview
      // Redirect it to the new frontend www site
      if (host === 'romancespace.885201314.xyz') {
        return Response.redirect('https://www.885201314.xyz' + path, 301);
      }

      // If it's already www (meaning it passed through without Pages intercepting it locally or custom domain binding issue), 
      // return a placeholder telling user to configure it via Pages. 
      // Normally Cloudflare Pages intercepts the request BEFORE the Worker if configured via Custom Domains.
      // If the Worker sees it, it means Pages isn't configured for www yet, or a Worker Route is intercepting it.
      if (host === 'www.885201314.xyz') {
        return new Response("Frontend works, please configure Cloudflare Pages Custom Domains.", { status: 200 });
      }

      return notFoundResponse();
    }

    // ── USER SUBDOMAIN ─────────────────────────────────────────────
    // Pattern: [projectId].885201314.xyz
    const parts = host.split('.');
    const projectId = parts[0];
    const isPreview = url.searchParams.has('preview');

    // ── Preview mode: bypass all caches, read R2 directly ─────────
    if (isPreview) {
      const cfgRaw = await env.ROMANCESPACE_KV.get(projectId);
      if (!cfgRaw) return notFoundResponse();

      let obj = await env.ROMANCESPACE_R2.get(`pages/${projectId}/index.html`);
      if (!obj) {
        obj = await env.ROMANCESPACE_R2.get(`pages/${projectId}.html`);
      }
      if (!obj) return notFoundResponse();

      return new Response(await obj.text(), {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          Pragma: 'no-cache',
        },
      });
    }

    // ── Normal mode: Cache API → R2 → Cache ───────────────────────

    // 1. Check local Cache API (fastest, free)
    const cacheKey = new Request(`https://cache.rs.internal/${projectId}`);
    const cached = await caches.default.match(cacheKey);
    if (cached) return cached;

    // 2. Check KV for routing config
    const cfgRaw = await env.ROMANCESPACE_KV.get(projectId);
    if (!cfgRaw) return notFoundResponse();

    // 3. Fetch pre-rendered HTML from R2
    let obj = await env.ROMANCESPACE_R2.get(`pages/${projectId}/index.html`);
    if (!obj) {
      obj = await env.ROMANCESPACE_R2.get(`pages/${projectId}.html`);
    }
    if (!obj) return notFoundResponse();

    const html = injectViralFooter(await obj.text());

    const response = new Response(html, {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'public, max-age=3600', // 1 hour CDN + Cache API
      },
    });

    // 4. Cache for subsequent requests at this edge node
    ctx.waitUntil(caches.default.put(cacheKey, response.clone()));
    return response;
  },
};
