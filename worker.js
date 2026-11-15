// u.bo.ge URL shortener
// - Public:  GET /<code>           -> 302 redirect (existing + new links stay open)
// - Locked:  /admin, /admin/api/*  -> requires Cloudflare Access login (JWT verified here too)
// KV format is unchanged from the old worker: LINKS[<code>] = <long url>,
// LINKS[sha512(<long url>)] = <code> (de-dup index).

const CODE_RE = /^[A-Za-z0-9]{4,16}$/;
const CODE_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678";

// Destinations we refuse: other shorteners (used to hide the real target)
// and free dynamic-DNS providers (heavily used for phishing).
const BLOCKED_HOST_SUFFIXES = [
  // shorteners
  "uurl.at", "bit.ly", "tinyurl.com", "t.co", "is.gd", "v.gd", "cutt.ly", "rb.gy",
  "shorturl.at", "ow.ly", "t.ly", "tiny.cc", "rebrand.ly", "s.id", "shorturl.asia",
  "goo.su", "clck.ru", "qrco.de", "bl.ink", "short.io", "linktr.ee",
  // dynamic DNS / free subdomain hosts
  "twilightparadox.com", "mooo.com", "afraid.org", "duckdns.org", "no-ip.org",
  "ddns.net", "hopto.org", "zapto.org", "servebeer.com", "sytes.net", "dynu.net",
  "freedns.org", "chickenkiller.com", "strangled.net", "ignorelist.com", "crabdance.com",
  "ngrok.io", "ngrok-free.app", "trycloudflare.com", "serveo.net", "loca.lt",
  // this shortener itself (no loops)
  "u.bo.ge",
];

// ---------- Cloudflare Access JWT verification ----------
let certCache = { keys: null, fetchedAt: 0 };

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function getAccessKeys(teamDomain) {
  if (certCache.keys && Date.now() - certCache.fetchedAt < 10 * 60 * 1000) return certCache.keys;
  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error("certs fetch failed");
  const { keys } = await res.json();
  certCache = { keys, fetchedAt: Date.now() };
  return keys;
}

async function verifyAccess(request, env) {
  const token =
    request.headers.get("Cf-Access-Jwt-Assertion") ||
    (request.headers.get("Cookie") || "").match(/(?:^|;\s*)CF_Authorization=([^;]+)/)?.[1];
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let header, payload;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
  } catch {
    return null;
  }
  if (header.alg !== "RS256") return null;
  const jwk = (await getAccessKeys(env.ACCESS_TEAM_DOMAIN)).find((k) => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey(
    "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
  );
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, b64urlToBytes(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  );
  if (!ok) return null;
  const now = Math.floor(Date.now() / 1000);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(env.ACCESS_AUD)) return null;
  if (payload.iss !== `https://${env.ACCESS_TEAM_DOMAIN}`) return null;
  if (typeof payload.exp !== "number" || payload.exp < now) return null;
  return payload.email || payload.common_name || "unknown";
}

// ---------- helpers ----------
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json;charset=UTF-8", "cache-control": "no-store" },
  });
}

async function sha512(text) {
  const d = await crypto.subtle.digest("SHA-512", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomCode(len = 6) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let out = "";
  for (const b of bytes) out += CODE_CHARS[b % CODE_CHARS.length];
  return out;
}

function validateDestination(raw) {
  let u;
  try {
    u = new URL(String(raw).trim());
  } catch {
    return { error: "Not a valid URL." };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return { error: "Only http(s) URLs are allowed." };
  if (u.username || u.password) return { error: "URLs with embedded credentials are not allowed." };
  const host = u.hostname.toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) return { error: "IP-address URLs are not allowed." };
  if (!host.includes(".")) return { error: "Invalid host." };
  if (BLOCKED_HOST_SUFFIXES.some((s) => host === s || host.endsWith("." + s)))
    return { error: `Links to ${host} are not allowed (shortener / dynamic DNS).` };
  return { url: u.toString() };
}

// ---------- handlers ----------
async function createLink(request, env, email) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "Expected JSON body {\"url\": \"...\"}." }, 400);
  }
  const v = validateDestination(body?.url);
  if (v.error) return json({ ok: false, error: v.error }, 400);

  const hash = await sha512(v.url);
  const existing = await env.LINKS.get(hash);
  if (existing && CODE_RE.test(existing) && (await env.LINKS.get(existing)) === v.url) {
    return json({ ok: true, code: existing, short: `https://u.bo.ge/${existing}`, reused: true });
  }

  for (let i = 0; i < 5; i++) {
    const code = randomCode();
    if ((await env.LINKS.get(code)) !== null) continue;
    await env.LINKS.put(code, v.url, {
      metadata: { by: email, at: new Date().toISOString() },
    });
    await env.LINKS.put(hash, code);
    console.log(JSON.stringify({ event: "link_created", code, url: v.url, by: email }));
    return json({ ok: true, code, short: `https://u.bo.ge/${code}` });
  }
  return json({ ok: false, error: "Could not allocate a code, try again." }, 500);
}

async function redirect(code, requestURL, env) {
  const target = await env.LINKS.get(code);
  if (!target) return notFound();
  let location = target;
  // Keep extra query params working (e.g. utm tags) but merge them properly.
  if (requestURL.search) {
    try {
      const dest = new URL(target);
      for (const [k, v] of requestURL.searchParams) dest.searchParams.append(k, v);
      location = dest.toString();
    } catch {
      location = target;
    }
  }
  return new Response(null, { status: 302, headers: { Location: location, "cache-control": "no-store" } });
}

function notFound() {
  return new Response(
    `<!doctype html><meta charset="utf-8"><title>Not found</title><body style="font-family:system-ui;padding:40px"><h1>404</h1><p>This short link does not exist.</p></body>`,
    { status: 404, headers: { "content-type": "text/html;charset=UTF-8" } }
  );
}

const HOME_HTML = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>u.bo.ge</title><body style="font-family:system-ui;padding:40px;max-width:640px;margin:auto">
<h1>u.bo.ge</h1><p>Private link shortener of BackOffice. Short links are created by staff only.</p>
<p>To report abuse of a u.bo.ge link, write to <a href="mailto:info@backoffice.ge">info@backoffice.ge</a>.</p></body>`;

const ADMIN_HTML = (email) => `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>u.bo.ge admin</title>
<style>
:root{--bg:#fff;--fg:#111;--muted:#666;--line:#ddd;--accent:#1a5fff}
@media (prefers-color-scheme:dark){:root{--bg:#111;--fg:#eee;--muted:#999;--line:#333;--accent:#5b8cff}}
body{background:var(--bg);color:var(--fg);font-family:system-ui;max-width:640px;margin:auto;padding:32px 16px}
input{width:100%;box-sizing:border-box;padding:12px;font-size:16px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg)}
button{margin-top:12px;padding:12px 20px;font-size:16px;border:0;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer}
#out{margin-top:20px;font-size:18px;word-break:break-all}.muted{color:var(--muted);font-size:14px}.err{color:#d33}
</style></head><body>
<h1>Create short link</h1><p class="muted">Signed in as ${email.replace(/[<>&"]/g, "")}</p>
<form id="f"><input id="u" type="url" placeholder="https://..." required autofocus><button>Shorten</button></form>
<div id="out"></div>
<script>
document.getElementById('f').onsubmit=async e=>{e.preventDefault();const o=document.getElementById('out');o.textContent='...';
const r=await fetch('/admin/api/shorten',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url:document.getElementById('u').value})});
const j=await r.json().catch(()=>({ok:false,error:'HTTP '+r.status}));
if(j.ok){o.className='';o.innerHTML='';const a=document.createElement('a');a.href=j.short;a.textContent=j.short;o.appendChild(a);navigator.clipboard?.writeText(j.short).catch(()=>{});}
else{o.className='err';o.textContent=j.error||'Error';}};
</script></body></html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ---- locked area ----
    if (path === "/admin" || path.startsWith("/admin/")) {
      const email = await verifyAccess(request, env).catch(() => null);
      if (!email) return json({ ok: false, error: "Login required." }, 403);
      if (path === "/admin" || path === "/admin/") {
        return new Response(ADMIN_HTML(email), {
          headers: { "content-type": "text/html;charset=UTF-8", "cache-control": "no-store" },
        });
      }
      if (path === "/admin/api/shorten" && request.method === "POST") return createLink(request, env, email);
      return json({ ok: false, error: "Not found." }, 404);
    }

    // ---- public area: redirects only ----
    if (request.method !== "GET" && request.method !== "HEAD") {
      return json({ ok: false, error: "Link creation requires login at https://u.bo.ge/admin" }, 403);
    }
    if (path === "/" || path === "") {
      return new Response(HOME_HTML, { headers: { "content-type": "text/html;charset=UTF-8" } });
    }
    const code = path.split("/")[1];
    if (!CODE_RE.test(code)) return notFound();
    return redirect(code, url, env);
  },
};
