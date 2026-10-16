/**
 * HSV Space Jobs — Worker with Static Assets + server-side advertise intake.
 *
 * After this is deployed (replacing assets-only), Cloudflare allows Worker secrets:
 *   TURNSTILE_SECRET_KEY, RESEND_API_KEY, MAIL_FROM
 *
 * Static files (/, /index.html, /jobs.json, /advertise.html) stay asset-served.
 * Only /api/* runs this Worker first (see wrangler.toml run_worker_first).
 *
 * Does NOT write jobs.json or store employer PII in GitHub/public files.
 */

const MAIL_TO = 'hsvspacejobs@outlook.com';
const MAX_LEN = {
  company: 200,
  title: 200,
  location: 200,
  job_url: 2000,
  contact_name: 200,
  contact_email: 320,
};

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

function bad(status, error) {
  return json(status, { ok: false, error });
}

function missingSecrets(env) {
  const missing = [];
  if (!env.TURNSTILE_SECRET_KEY) missing.push('TURNSTILE_SECRET_KEY');
  if (!env.RESEND_API_KEY) missing.push('RESEND_API_KEY');
  if (!env.MAIL_FROM) missing.push('MAIL_FROM');
  return missing;
}

function isNonEmptyString(v, max) {
  return typeof v === 'string' && v.trim().length > 0 && v.trim().length <= max;
}

function isEmail(v) {
  if (!isNonEmptyString(v, MAX_LEN.contact_email)) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim());
}

function isHttpUrl(v) {
  if (!isNonEmptyString(v, MAX_LEN.job_url)) return false;
  try {
    const u = new URL(v.trim());
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    const host = u.hostname.toLowerCase();
    const blocked = [
      'indeed.com',
      'www.indeed.com',
      'linkedin.com',
      'www.linkedin.com',
      'ziprecruiter.com',
      'www.ziprecruiter.com',
    ];
    if (blocked.some((b) => host === b || host.endsWith('.' + b))) return false;
    return true;
  } catch {
    return false;
  }
}

async function verifyTurnstile(token, secret, ip) {
  if (!token || !secret) return false;
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: form,
  });
  if (!res.ok) return false;
  const data = await res.json();
  return data.success === true;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function sendEmail(env, fields, meta) {
  const subject = `[HSVSpaceJobs] Advertise intake: ${fields.company} — ${fields.title}`;
  const text = [
    'New employer advertising submission (review only; no payment collected).',
    '',
    `Company: ${fields.company}`,
    `Job title: ${fields.title}`,
    `Location: ${fields.location}`,
    `Job URL: ${fields.job_url}`,
    `Contact name: ${fields.contact_name}`,
    `Contact email: ${fields.contact_email}`,
    '',
    `Received at (UTC): ${meta.received_at}`,
    `CF ray: ${meta.cf_ray || 'n/a'}`,
    `Country: ${meta.country || 'n/a'}`,
    '',
    'Do not publish until verified. Do not store this in the public GitHub repo.',
  ].join('\n');

  const html = `
    <p><strong>New employer advertising submission</strong> (review only; no payment collected).</p>
    <ul>
      <li><strong>Company:</strong> ${escapeHtml(fields.company)}</li>
      <li><strong>Job title:</strong> ${escapeHtml(fields.title)}</li>
      <li><strong>Location:</strong> ${escapeHtml(fields.location)}</li>
      <li><strong>Job URL:</strong> <a href="${escapeHtml(fields.job_url)}">${escapeHtml(fields.job_url)}</a></li>
      <li><strong>Contact name:</strong> ${escapeHtml(fields.contact_name)}</li>
      <li><strong>Contact email:</strong> ${escapeHtml(fields.contact_email)}</li>
    </ul>
    <p>Received at (UTC): ${escapeHtml(meta.received_at)}<br/>
    CF ray: ${escapeHtml(meta.cf_ray || 'n/a')}<br/>
    Country: ${escapeHtml(meta.country || 'n/a')}</p>
    <p>Do not publish until verified. Do not store this in the public GitHub repo.</p>
  `;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.MAIL_FROM,
      to: [MAIL_TO],
      reply_to: fields.contact_email,
      subject,
      text,
      html,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    console.error('resend_failed', res.status, body.slice(0, 500));
    throw new Error('email_send_failed');
  }
}

async function handleAdvertise(request, env) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': 'https://hsvspacejobs.com',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400',
      },
    });
  }

  if (request.method !== 'POST') {
    return bad(405, 'Method not allowed');
  }

  // Secrets are added in Cloudflare AFTER the first Worker+assets deploy.
  const missing = missingSecrets(env);
  if (missing.length) {
    console.error('advertise_secrets_missing', missing.join(','));
    return bad(
      503,
      'Advertising intake is not fully configured yet. Please email hsvspacejobs@outlook.com.',
    );
  }

  const ctype = request.headers.get('content-type') || '';
  if (!ctype.includes('application/json')) {
    return bad(415, 'Content-Type must be application/json');
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return bad(400, 'Invalid JSON');
  }

  // Honeypot: if filled, pretend success without emailing.
  if (typeof body.website === 'string' && body.website.trim() !== '') {
    return json(200, { ok: true });
  }

  const fields = {
    company: typeof body.company === 'string' ? body.company.trim() : '',
    title: typeof body.title === 'string' ? body.title.trim() : '',
    location: typeof body.location === 'string' ? body.location.trim() : '',
    job_url: typeof body.job_url === 'string' ? body.job_url.trim() : '',
    contact_name: typeof body.contact_name === 'string' ? body.contact_name.trim() : '',
    contact_email: typeof body.contact_email === 'string' ? body.contact_email.trim() : '',
  };

  if (!isNonEmptyString(fields.company, MAX_LEN.company)) return bad(400, 'Invalid company name');
  if (!isNonEmptyString(fields.title, MAX_LEN.title)) return bad(400, 'Invalid job title');
  if (!isNonEmptyString(fields.location, MAX_LEN.location)) return bad(400, 'Invalid job location');
  if (!isHttpUrl(fields.job_url)) return bad(400, 'Invalid or unsupported job posting URL');
  if (!isNonEmptyString(fields.contact_name, MAX_LEN.contact_name)) return bad(400, 'Invalid contact name');
  if (!isEmail(fields.contact_email)) return bad(400, 'Invalid contact email');

  const turnstileToken = typeof body.turnstile_token === 'string' ? body.turnstile_token : '';
  const ip = request.headers.get('CF-Connecting-IP') || undefined;
  const turnstileOk = await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY, ip);
  if (!turnstileOk) {
    return bad(403, 'Turnstile verification failed');
  }

  try {
    await sendEmail(env, fields, {
      received_at: new Date().toISOString(),
      cf_ray: request.headers.get('CF-Ray'),
      country: request.headers.get('CF-IPCountry'),
    });
  } catch (err) {
    console.error('advertise_email_error', String(err && err.message ? err.message : err));
    return bad(502, 'Unable to deliver submission. Please email hsvspacejobs@outlook.com.');
  }

  return json(200, { ok: true });
}

// ---- First-party traffic tracking (no cookies, no IPs, no PII) ----
const PAGE_PATHS = new Set(['/', '/index.html', '/advertise', '/advertise.html']);
const BOT_RE = /bot|crawl|spider|slurp|headless|phantom|puppeteer|playwright|selenium|curl|wget|python|httpclient|okhttp|go-http|java\/|axios|node-fetch|scrapy|facebookexternalhit|preview|monitor|uptime|lighthouse|bingpreview|embedly|quora link|discordbot|telegrambot|whatsapp|slackbot|twitterbot/i;
const cut = (v, n) => String(v || '').slice(0, n);

function refBucket(ref, selfHost) {
  if (!ref) return 'direct';
  let h;
  try { h = new URL(ref).hostname.toLowerCase().replace(/^www\./, ''); } catch { return 'unknown'; }
  if (h === selfHost || h.endsWith('.' + selfHost)) return 'internal';
  if (h === 't.co' || h === 'x.com' || h.endsWith('.x.com') || h === 'twitter.com' || h.endsWith('.twitter.com')) return 'x';
  return cut(h, 60);
}

function trafficEvent(request, url, extra) {
  const ua = request.headers.get('user-agent') || '';
  const cf = request.cf || {};
  const bm = cf.botManagement;
  let bot = BOT_RE.test(ua) || !ua;
  if (bm && typeof bm.score === 'number') bot = bot || bm.score < 30 || !!bm.verifiedBot;
  const selfHost = url.hostname.toLowerCase().replace(/^www\./, '');
  return Object.assign({
    t: Date.now(),
    p: cut(url.pathname, 80),
    r: refBucket(request.headers.get('referer'), selfHost),
    u: cut(url.searchParams.get('utm_source'), 40),
    c: cut(cf.country, 2),
    d: /mobi|android|iphone|ipad/i.test(ua) ? 'mobile' : 'desktop',
    b: bot ? 1 : 0,
  }, extra || {});
}

async function storeEvent(env, ev) {
  try {
    if (env.TRAFFIC_AE) {
      env.TRAFFIC_AE.writeDataPoint({
        indexes: [ev.e || 'pv'],
        blobs: [ev.e || 'pv', ev.p, ev.r, ev.u, ev.c, ev.d, ev.co || '', ev.j || ''],
        doubles: [1, ev.b],
      });
    }
  } catch (e) { console.error('ae_write', String(e)); }
  try {
    if (env.TRAFFIC) {
      // Data lives in key metadata so the report can read it via a key list.
      const key = `ev:${new Date(ev.t).toISOString()}:${Math.random().toString(36).slice(2, 8)}`;
      await env.TRAFFIC.put(key, '', { metadata: ev, expirationTtl: 60 * 60 * 24 * 400 });
    }
  } catch (e) { console.error('kv_write', String(e)); }
}

function handleHit(request, env, ctx, url) {
  if (request.method === 'POST' || request.method === 'GET') {
    const e = url.searchParams.get('e');
    if (e === 'apply') {
      const ref = request.headers.get('referer') || '';
      let page = '/';
      try { page = new URL(ref).pathname; } catch {}
      const ev = trafficEvent(request, url, {
        e: 'apply',
        co: cut(url.searchParams.get('company'), 80),
        j: cut(url.searchParams.get('job'), 120),
      });
      ev.p = cut(page, 80);
      ev.r = 'internal';
      ctx.waitUntil(storeEvent(env, ev));
    }
  }
  return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/api/hit') {
      return handleHit(request, env, ctx, url);
    }

    if (url.pathname === '/api/advertise') {
      return handleAdvertise(request, env);
    }

    // Non-API paths under run_worker_first should still fall through to assets.
    if (env.ASSETS) {
      const res = await env.ASSETS.fetch(request);
      const ctype = res.headers.get('content-type') || '';
      if (request.method === 'GET' && PAGE_PATHS.has(url.pathname) && res.status === 200 && ctype.includes('text/html')) {
        ctx.waitUntil(storeEvent(env, trafficEvent(request, url, { e: 'pv' })));
      }
      return res;
    }
    return new Response('Not found', { status: 404 });
  },
};
