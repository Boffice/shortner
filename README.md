# u.bo.ge URL shortener

- `worker.js` — the Cloudflare Worker `url` serving **u.bo.ge** (KV binding `LINKS`).
  - `GET /<code>` — public redirect.
  - `/admin` and `POST /admin/api/shorten` — create links; protected by Cloudflare Access
    (app "u.bo.ge link admin"). The worker also verifies the Access JWT itself
    (vars `ACCESS_AUD`, `ACCESS_TEAM_DOMAIN`).
  - Destinations on other shorteners, dynamic-DNS hosts and raw IPs are refused.
- The HTML files here are deployed by Cloudflare Pages (`shortner-7bn.pages.dev`) and are
  no longer used by the worker.

**Note:** pushing this repo does **not** deploy the worker. Deploy changes to `worker.js`
from the Cloudflare dashboard (Workers & Pages → url) or the API, and keep this file in sync.
Never put secrets in this repo — it is public.
