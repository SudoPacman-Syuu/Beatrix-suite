# Repeater "HTTP Tips" — coverage & roadmap

An opt-in learning aid in the Repeater tab. When **HTTP Tips** is toggled **on**
(button at the top-right of the Repeater toolbar), hovering a token in the
request or response pops a small bubble explaining what it is — and, where
relevant, what to look at when hunting for bugs.

The goal: help a human quickly understand what they're looking at and manually
spot issues. We start with the common, high-value stuff and grow the knowledge
base over time. **This file is the running ledger of what's covered and what's
next — update it whenever tips are added.**

---

## How it works (architecture)

- The syntax highlighter already wraps meaningful tokens in `<span>`s. For the
  tip-bearing ones it also stamps a `data-tip="<prefix>:<key>"` attribute:
  - `h:<header-name>` — request/response header names
  - `m:<method>` — request methods
  - `s:<status-code>` — response status codes (falls back to the class, e.g. `4xx`)
  - `t:<tag>` — HTML/XML tag names in a body
  - `cookie:<attr>` / `cookie:samesite-<val>` — Set-Cookie / Cookie attributes
  - `csp:<directive>` / `csp:kw-<source>` / `csp:star` — CSP value tokens
  - `cc:<directive>` — Cache-Control directives
  - `hsts:<token>` — Strict-Transport-Security tokens
  - `ct:<mime>` — Content-Type media types
  - `auth:<scheme>` — Authorization schemes
  - `attr:<name>` / `attr:on` — security-relevant HTML attributes
  - `json:<field>` — a security-relevant JSON body **key** (normalized: lowercased,
    `_`/`-` stripped, so `user_id`/`userId` → `userid`)
  - `param:<name>` — a commonly-injectable URL **query parameter** name (same
    normalization as `json:`)
  - `gql:<key>` — a GraphQL operation / introspection token (`query`, `mutation`,
    `introspection`, `__typename`, …)
  - `vary:<token>` / `cd:<param>` / `wwwauth:<token>` / `refpol:<value>` — per-value
    tokens inside Vary / Content-Disposition / WWW-Authenticate / Referrer-Policy
  - per-value tokens for many more header families: `ce:` (Content-/Accept-Encoding),
    `tenc:` (Transfer-Encoding), `conn:` (Connection), `pp:` (Permissions-Policy),
    `altsvc:` (Alt-Svc), `csd:` (Clear-Site-Data), `xfo:` (X-Frame-Options),
    `xcto:` (X-Content-Type-Options), `coop:`/`coep:`/`corp:` (the Cross-Origin trio),
    `sfs:`/`sfm:`/`sfd:` (the Sec-Fetch trio), `cachestatus:` (cf-cache-status / X-Cache),
    `ctparam:` (Content-Type charset/boundary)
  - `csp:nonce` / `csp:hash` — CSP `'nonce-…'` and `'sha256/384/512-…'` sources
  - `corr:<key>` — a **cross-line** correlation finding, stamped only when a
    message-level condition holds (see below), e.g. `corr:desync`, `corr:cors-*`
  - `jwt:<token>` / `basic:<b64>` / `enc:<type>:<blob>` / `verdis:<product/version>`
    — **dynamic** tips decoded/built live on hover (see below), not static entries
- Header **values** are tokenized by `hlHeaderValue()` → `hlTokens()`, which wraps
  matched sub-tokens in tip spans while emitting the gaps verbatim, so every
  character is preserved and the request overlay stays aligned.
- The knowledge base is `HTTP_TIPS` in the embedded page JS (`beatrix/cli/suite.py`),
  keyed by those prefixes. Each entry is `{ title, desc, sec? }` where `sec` is an
  optional security note.
- `lookupTip(key)` resolves a `data-tip` value to an entry. Several kinds are
  **dynamic** — built on hover from the token itself, not looked up in a table:
  `jwt:` (`decodeJwtTip()` — base64url header+payload; flags `alg=none`, HMAC
  secret-guessing, RS↔HS confusion), `basic:` (`decodeBasicTip()` — base64 →
  `user:pass`), `enc:<type>:<blob>` (`decodeEncTip()` — re-decodes the blob and
  previews it), and `verdis:` (`decodeVerdisTip()` — echoes the disclosed
  product/version with a CVE-lookup cue, deliberately with **no** hard-coded CVE
  list).
- **Encoded-blob detection is gated by a printable ratio.** `hlValueMaybeJwt()`
  (and `encTipFor()` for whole JSON/query values) tries URL / hex / base64
  decodes but only stamps `enc:` when the decoded bytes are mostly printable
  (`encPrintable() ≥ ~0.85`) — that one check is what stops random tokens,
  hashes, and session ids from lighting up everywhere.
- **Correlation tips are cross-line.** A single token can't reveal that two
  *different* headers combine dangerously, so before highlighting a message
  `hlHttp()` runs `msgCtx(headLines, reqOrigin)` to gather message-level facts
  (is Content-Length *and* Transfer-Encoding present? what is Allow-Origin, is
  Allow-Credentials true?). That `ctx` is threaded into `hlHeaderLine` /
  `hlHeaderValue`, which stamp a `corr:<key>` only when the condition holds — so
  the key itself already implies the finding and `lookupTip` stays a static
  lookup into `HTTP_TIPS.corr`. For reflection, `reqOrigin` is the Origin the
  *paired request* sent (`reqOriginOf()`), passed in by the response renderers.
- Hover detection uses `document.elementsFromPoint()` so it works even in the
  request pane, where an editable textarea sits on top of the highlighted layer.
- The toggle state persists in `localStorage` (`beatrix.rep.tips`). When on,
  hoverable tokens get a faint dotted underline as an affordance.

**To add a tip:** add an entry to the right `HTTP_TIPS` sub-object, make sure the
highlighter stamps a matching `data-tip` key for that token type (a new header
value type usually means a new `case` in `hlHeaderValue`), then tick it off below.
**For a cross-line tip:** add the fact to `msgCtx`, stamp a `corr:<key>` from the
relevant `hlHeaderLine`/`hlHeaderValue` branch guarded on that fact, and add the
entry under `HTTP_TIPS.corr`.
**For a body/param tip:** JSON keys and values are stamped in `hlJson()` /
`hlJsonStringValue()`, query keys in `hlPath()` (wired into `hlReqLine`), and a
GraphQL body in `hlGraphql()` (reached via `repDetectCT` → `hlBody`).
**For a dynamic (decoded) tip:** add a `decodeXTip()` builder and route its prefix
in `lookupTip`; stamp the key where the token is tokenized (e.g. a new
alternative in `hlValueMaybeJwt`).

---

## Semantic colour (readability)

Beyond per-token tips, the highlighter colours tokens by what they *are* to a
tester, so a message is scannable at a glance. Three semantic classes sit on top
of the structural ones, each a theme token the settings panel can recustomise:

- `tok-param` (blue) — parameter and field **names**: query keys, JSON keys,
  form fields, cookie names.
- `tok-val` (orange) — **modifiable values**: query/form values and JSON string
  values. On the **request side** (`#rep-request-hl`) these get a highlighter
  background chip so the things you edit are unmissable; the response side keeps
  the colour without the chip (you read it, you don't tamper with it).
- `tok-sensitive` (violet, faint chip) — **encoded / decodable blobs, cookies,
  tokens, and secrets**: base64/hex/URL/JWT/Basic values, cookie values, and
  Authorization credentials — one colour for "decode-me / handle-with-care".

Points of interest (methods, status, security-header keywords, CSP sources, …)
keep their existing structural colours. Only colour, background, and
monospace-safe weight are used on code tokens — never padding or borders — so
the request backdrop stays glyph-aligned under the editable textarea.

---

## Auto-decode panel (no hovering)

A **Decode** toggle in the Repeater toolbar (beside Tips / Beautify, state in
`localStorage` `beatrix.rep.decode`) opens a strip below the request/response
split that lists every cookie, Authorization credential, encoded query param,
and JWT in the current request and response — each with its decoded form or an
honest verdict. It refreshes on send, tab switch, history scrub, and edits.

- `extractDecodables(text, src)` pulls the candidates from one message; each is
  rendered with a `REQ`/`RESP` source chip, the item name, an optional framework
  chip, and the decoded value.
- `repDecodeValue(v)` returns `{kind, summary}`: a JWT's claims, a strict
  multi-layer decode (reusing `analyzeEncoding`), the payload of a dot-segmented
  signed token (Flask-style `payload.ts.sig`), or a plain "binary / needs the
  key" verdict — never mojibake.
- **Framework recognition** (`COOKIE_FRAMEWORKS` → `cookieFramework(name)`)
  fingerprints session cookies by name and states whether the value is readable
  or **encrypted** (undecodable without the server key): JSESSIONID, PHPSESSID,
  ASP.NET(/Core), Flask `session`, Laravel, Django, Rails, Express `connect.sid`,
  NextAuth, Drupal, WordPress, AWS ALB, Cloudflare, Google Analytics. Encrypted
  ones are labelled as such rather than shown as garbage — the honest answer when
  a value genuinely can't be decoded without a key.

Trivial cookies (short, no framework, nothing to decode) are skipped so the
panel stays signal.

---

## Covered

**~720 static tips across 36 categories, plus live JWT / Basic-auth / encoded-blob
/ version decoding, and cross-line correlation callouts.** Header names, security
headers, CSP, Permissions-Policy, Content-Encoding, Alt-Svc, Clear-Site-Data, and
the value enumerations were cross-referenced against the MDN HTTP reference, the
OWASP Secure Headers Project, and the relevant W3C/RFC specs for accuracy
(see *Research sources* at the end).

### Correlation — cross-line (`corr:`)
- **Request smuggling / desync** — `corr:desync`: stamped on both the
  Content-Length and Transfer-Encoding header names when **both** are present on
  one message (the CL.TE / TE.CL setup).
- **CORS misconfig** — on the Access-Control-Allow-Origin value and the
  Access-Control-Allow-Credentials value, graded by how exploitable the
  combination is: `*` / `null` / reflected-Origin, each with and without
  `Allow-Credentials: true` (`corr:cors-star[-creds]`, `corr:cors-null[-creds]`,
  `corr:cors-reflect[-creds]`, `corr:cors-creds`). Reflection is detected against
  the Origin the paired request actually sent.

### JSON body fields (`json:`)
~65 security-relevant object-key names, normalized (lowercase, `_`/`-` stripped):
IDOR/BOLA identifiers (id, user_id, account_id, order_id, uuid, object_id, …),
privilege / mass-assignment flags (role, is_admin, scope, permissions, plan,
verified, status, …), secrets that shouldn't appear or must be handled with care
(password, token, access_token, api_key, client_secret, private_key, jwt, otp,
csrf_token, card, cvv, ssn, …), SSRF/redirect/file fields (url, redirect_uri,
callback, webhook, file, path, template, include, …), business-logic money/qty
(amount, price, total, balance, quantity, discount, currency, coupon), and
injection surfaces (query, search, filter, sort, cmd, sql). Stamped on keys in a
JSON body; GraphQL / encoded string **values** are detected too.

### URL query parameters (`param:`)
~57 commonly-probed parameter names (same normalization): open-redirect / SSRF
(redirect, url, next, callback, dest, host, proxy, image_url, …), LFI / traversal
(file, path, page, template, include, dir, download, …), RCE / SSTI / eval (cmd,
exec, command, code, eval, query, q, …), IDOR / authz (id, user, account, uid,
order, token, key, impersonate, …), and debug/control toggles (debug, test,
admin, format). Stamped on the query keys in the request line.

### GraphQL (`gql:`)
query, mutation, subscription, fragment, plus `introspection` (`__schema`/`__type`)
and `__typename`, with notes on authz/CSRF, introspection leakage, field
suggestions, aliasing/batching, and nesting DoS. Detected both in a raw
`application/graphql` body and inside a JSON-wrapped `{"query": …}`.

### Per-value header depth
The structured value of many headers is tokenized so each token gets its own tip:
- **Vary** (`vary:`) — Origin, Cookie, Accept-Encoding, User-Agent, Accept.
- **Content-Disposition** (`cd:`) — filename, attachment, inline, form-data.
- **WWW-Authenticate** (`wwwauth:`) — Basic/Bearer/Digest/Negotiate/NTLM + realm,
  charset, error, nonce, qop, stale, algorithm.
- **Referrer-Policy** (`refpol:`) — all eight values, graded by URL leakage.
- **Content-Encoding / Accept-Encoding** (`ce:`) — gzip, br, zstd, deflate,
  compress, identity, dcb, dcz (zip-bomb / BREACH / decode-gap notes).
- **Transfer-Encoding** (`tenc:`) — chunked (+ the request-smuggling angle),
  gzip/deflate/compress/identity transfer codings.
- **Connection** (`conn:`) — keep-alive (why smuggling matters), close, upgrade
  (h2c / WebSocket).
- **Permissions-Policy / Feature-Policy** (`pp:`) — ~32 features (camera,
  microphone, geolocation, payment, usb/serial/hid/bluetooth/midi,
  display-capture, clipboard-read/write, publickey-credentials-*,
  local-network-access, local-fonts, storage-access, …) with the `()`/self/`*`
  allowlist semantics in each note.
- **Alt-Svc** (`altsvc:`) — h2, h3 (incl. draft ids), clear, ma, persist.
- **Clear-Site-Data** (`csd:`) — cache, cookies, storage, executionContexts,
  clientHints, prefetchCache, prerenderCache.
- **X-Frame-Options** (`xfo:`) — DENY, SAMEORIGIN, ALLOW-FROM (flagged obsolete).
- **X-Content-Type-Options** (`xcto:`) — nosniff.
- **Cross-Origin trio** — `coop:` (unsafe-none, same-origin, …), `coep:`
  (unsafe-none, require-corp, credentialless), `corp:` (same-origin/-site/cross).
- **Sec-Fetch trio** — `sfs:` (site), `sfm:` (mode), `sfd:` (dest) values, framed
  as server-side request-provenance defenses.
- **cf-cache-status / X-Cache** (`cachestatus:`) — HIT, MISS, DYNAMIC, EXPIRED,
  BYPASS, … (cache-poisoning / deception cues).
- **Content-Type params** (`ctparam:`) — charset (encoding-confusion XSS),
  boundary (multipart parser differentials).
- **CSP sources** — `csp:nonce` and `csp:hash` for `'nonce-…'` / `'sha256/384/512-…'`,
  plus the newer directives/sources (fenced-frame-src, 'trusted-types-eval',
  ws:/wss:/http:/filesystem:/mediastream:).

Header-name coverage also grew to ~160: Alt-Svc, Early-Data, SourceMap/X-SourceMap,
Origin-Agent-Cluster, Sec-GPC, X-Robots-Tag, Service-Worker-Allowed, the
Private-Network-Access pair, Content-Digest/Repr-Digest, Signature/Signature-Input,
the Sec-WebSocket-* handshake set, more Sec-CH-UA-* client hints, and common CDN
fingerprints (CF-RAY, X-Amz-Cf-Id, X-Served-By, X-Vercel-Id), among others.

### Encodings (`enc:`) — dynamic, recursive
`analyzeEncoding()` peels **nested** layers off a value — percent-encoding,
HTML entities, unicode escapes, hex, and base64 / base64url — up to five deep,
stopping at a fixed point. The hover shows the whole chain and names the final
structure, e.g. `base64 → URL-encoded ⟶ JSON`.

How each layer is judged:
- **Strict UTF-8.** Decoded bytes count as text only if they are valid UTF-8
  (`binToUtf8`) and essentially free of control bytes (`encReadable`). Random,
  signed, or compressed bytes fail this, so they are never shown as mojibake.
- **Binary is reported, not hidden.** When base64 or hex decodes to bytes that
  aren't text, the chain ends with that layer marked `(binary)` and the tip
  states the byte count, e.g. `URL-encoded → base64 (binary)`, 99 bytes —
  likely a signature, MAC, hash, or encrypted token.
- **`name=` prefixes are stripped** before a base64 attempt, so a matched blob
  like `s=nBm4…` decodes the token instead of failing on the prefix.
- **Noise control** (`encWorthStamping`): decoded text always gets a tip; a
  binary result only when it is nested (2+ layers) or a substantial token
  (24+ bytes). Short random ids stay quiet.

It runs on header values, query values, cookie values, form values, and JSON
string values. JWTs and Basic creds keep their own dedicated decoders.

### Version disclosure (`verdis:`) — dynamic
Server, X-Powered-By, X-AspNet(-Mvc)-Version, and X-Generator values carrying a
product + version (e.g. `Apache/2.4.49`, `PHP/5.6.40`) flag the disclosure and
cue a CVE lookup — without asserting any specific CVE.

### Request methods (`m:`)
GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT,
PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, REPORT, SEARCH (WebDAV),
PURGE, TRACK, DEBUG

### Status codes (`s:`)
100, 101, 200, 201, 202, 203, 204, 205, 206, 226,
300, 301, 302, 303, 304, 305, 307, 308,
400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414,
415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451,
500, 501, 502, 503, 504, 505, 507, 508, 510, 511 —
plus class fallbacks (`1xx`/`2xx`/`3xx`/`4xx`/`5xx`)

### Header names (`h:`)
host, user-agent, accept, accept-encoding, accept-language, referer, origin,
authorization, cookie, set-cookie, content-type, content-length,
content-encoding, transfer-encoding, connection, cache-control, pragma, date,
expires, etag, last-modified, location, server, x-powered-by, vary,
www-authenticate, content-disposition, content-language, content-md5, link,
accept-ranges, range, content-range, if-match, if-none-match, if-modified-since,
if-unmodified-since, if-range, te, expect, upgrade, keep-alive, max-forwards, dnt.
**Security headers:** x-frame-options, content-security-policy,
content-security-policy-report-only, x-content-security-policy (legacy),
x-webkit-csp (legacy), strict-transport-security, x-content-type-options,
x-xss-protection, referrer-policy, permissions-policy, feature-policy,
cross-origin-opener-policy, cross-origin-embedder-policy,
cross-origin-resource-policy, clear-site-data, timing-allow-origin, nel,
x-permitted-cross-domain-policies, x-dns-prefetch-control, x-download-options.
**CORS:** access-control-allow-origin, access-control-allow-credentials,
access-control-allow-methods, access-control-allow-headers,
access-control-expose-headers, access-control-max-age,
access-control-request-method, access-control-request-headers.
**Proxy / forwarding:** x-forwarded-for, x-forwarded-host, x-forwarded-proto,
x-forwarded-port, x-forwarded-server, forwarded, x-real-ip, x-host, via,
proxy-authorization, proxy-authenticate, x-original-url, x-rewrite-url,
x-http-method-override.
**Fetch metadata / client hints:** sec-fetch-site, sec-fetch-mode,
sec-fetch-dest, sec-fetch-user, sec-ch-ua, sec-ch-ua-platform, sec-ch-ua-mobile.
**Caching / rate-limit / tracing:** age, x-cache, cf-cache-status, retry-after,
allow, server-timing, report-to, reporting-endpoints, x-request-id,
x-correlation-id, x-amzn-trace-id, x-ratelimit-limit, x-ratelimit-remaining,
x-ratelimit-reset

### HTML/XML tags (`t:`)
html, head, title, meta, link, script, style, iframe, form, input, button,
textarea, a, img, svg, object, embed, base, `<!DOCTYPE>`,
body, video, audio, source, template, noscript, noembed, math, annotation-xml,
foreignObject, frame, frameset, applet, select, option, label, details,
marquee, dialog, portal, table, xml

### Cookie attributes (`cookie:`) — on the Set-Cookie / Cookie **value**
HttpOnly, Secure, SameSite (+ Strict/Lax/None values), Domain, Path, Max-Age,
Expires, Partitioned, and the `__Host-` / `__Secure-` name prefixes

### CSP tokens (`csp:`) — on the Content-Security-Policy **value**
default-src, script-src, script-src-elem, script-src-attr, style-src,
style-src-elem, style-src-attr, img-src, connect-src, font-src, object-src,
frame-src, child-src, worker-src, manifest-src, media-src, prefetch-src,
frame-ancestors, base-uri, form-action, navigate-to, report-uri, report-to,
trusted-types, require-trusted-types-for, webrtc, upgrade-insecure-requests,
block-all-mixed-content, sandbox;
sources `'unsafe-inline'`, `'unsafe-eval'`, `'wasm-unsafe-eval'`,
`'unsafe-hashes'`, `'self'`, `'none'`, `'strict-dynamic'`, `'report-sample'`,
`'inline-speculation-rules'`, `data:`, `blob:`, `https:`, `*`

### Cache-Control directives (`cc:`)
no-store, no-cache, private, public, max-age, s-maxage, must-revalidate,
proxy-revalidate, immutable, stale-while-revalidate, stale-if-error,
only-if-cached, max-stale, min-fresh, must-understand, no-transform

### HSTS tokens (`hsts:`)
max-age, includeSubDomains, preload

### Content-Type media types (`ct:`)
application/json, x-www-form-urlencoded, multipart/form-data, multipart/mixed,
application/xml, text/xml, application/soap+xml, application/xhtml+xml,
image/svg+xml, text/html, text/plain, octet-stream, application/javascript,
application/graphql, text/csv, application/ld+json, application/vnd.api+json,
application/hal+json, application/jwt, application/x-yaml, text/yaml,
application/pdf, application/zip, application/wasm, text/event-stream,
application/x-ndjson, application/x-protobuf, application/x-amf,
application/dns-message

### Authorization schemes (`auth:`)
Basic, Bearer, Digest, Negotiate, NTLM, AWS4-HMAC-SHA256 (AWS SigV4), Hawk,
Signature (HTTP Message Signatures)

### HTML attributes (`attr:`)
on* (event handlers), src, href, action, formaction, srcdoc, sandbox, rel,
target, type, http-equiv, content, integrity, nonce, style, autocomplete, name,
method, value, enctype, formmethod, formenctype, crossorigin, referrerpolicy,
ping, download, allow, loading

### JWT (`jwt:`) — dynamic
Any `eyJ….eyJ….` token (in Authorization, Cookie, or a body) is decoded live:
alg + typ, the first claims, and warnings for `alg=none`, HMAC secret-guessing,
and RS↔HS algorithm confusion.

### Basic auth (`basic:`) — dynamic
An `Authorization: Basic <base64>` credential is base64-decoded live on hover to
its `user : pass`, with a reminder that Basic is encoding (not encryption) and a
nudge to test the recovered credentials for reuse. Hovering the `Basic` scheme
word still shows its static `auth:basic` note.

---

## TODO / roadmap (not yet covered)

Ordered roughly by value for manual hunting.

- [x] **Request smuggling / desync** — an explicit callout when both
      Content-Length *and* Transfer-Encoding are present on the same message.
      Done (`corr:desync`).
- [x] **CORS correlation** — flag ACAO reflecting the request Origin, or ACAO
      `*`/`null` combined with Allow-Credentials `true` (needs cross-line logic).
      Done (`corr:cors-*`); introduced the `msgCtx` cross-line mechanism.
- [x] **More response headers** — Retry-After, Allow, Age, Via, X-Cache,
      Permissions-Policy, Cross-Origin-* (COOP/COEP/CORP), Timing-Allow-Origin,
      X-Request-Id, Server-Timing, Report-To/Reporting-Endpoints — *plus* the
      full forwarding/proxy set (X-Forwarded-*, Forwarded, X-Original-URL, …),
      Fetch-metadata/client hints (Sec-Fetch-*, Sec-CH-UA-*), the complete CORS
      family, conditional/range validators, and rate-limit headers. Done.
- [x] **Broader methods / status / content-types** — WebDAV methods
      (PROPFIND…UNLOCK, plus PURGE/TRACK/DEBUG), the remaining 1xx–5xx status
      codes (incl. 421/425/431/451/511), and many more media types
      (image/svg+xml, SOAP/XHTML, YAML, protobuf, AMF, …). Done.
- [x] **JSON structure tips** — hovering a key path; flag likely secrets/IDs and
      IDOR-ish fields (id, uuid, role, isAdmin, token). Done (`json:`, ~65 keys;
      also GraphQL/encoded string values).
- [x] **URL / query params** — hover a query key; note commonly injectable params.
      Done (`param:`, ~57 names, via `hlPath`).
- [x] **GraphQL / API shapes** — `query`/`mutation`, `__schema`, introspection.
      Done (`gql:`; raw and JSON-wrapped bodies).
- [x] **Encodings** — recognize base64 / URL-encoding / hex blobs and offer a
      decode hint (same dynamic pattern as JWT). Done (`enc:`, printable-ratio
      gated).
- [x] **Basic-auth decode** — like JWT, decode `Basic <base64>` inline to
      `user:pass`. Done (`basic:` dynamic tip).
- [x] **Server/version → CVE hint** — when Server/X-Powered-By carries a version.
      Done (`verdis:` dynamic tip; no hard-coded CVE list — points at a CVE source).
- [x] **Per-value depth for more headers** — Vary tokens, Content-Disposition
      filename, WWW-Authenticate params, Referrer-Policy values. Done
      (`vary:` / `cd:` / `wwwauth:` / `refpol:`).

**All roadmap items are now covered.** Remaining future work lives in *Ideas for
later* below.

## Ideas for later (beyond hover)

- **[shipped] Predictive parameters (Params).** The hover tip for `__schema`
  says "try introspection"; the Repeater's **Params** button now does that and
  much more — it discovers an endpoint's parameters from the best source
  available (GraphQL introspection · OpenAPI/Swagger · HTML forms · captured
  traffic), shows each param's type / required / enum / **source** / confidence
  (the endpoint's own ruleset, not a guess), and inserts a correctly-typed,
  ready-to-send stencil (params written into the query string, JSON body, form
  body, or GraphQL document). **Verify (active)** then confirms what the
  server actually accepts via Arjun (REST) or Clairvoyance (GraphQL schema
  recovery), scope-gated. Server core in `suite.py`: `_param_discover` /
  `_param_active_verify` + the per-source parsers (`_src_openapi`, `_html_forms`,
  `_src_observed`, `_src_graphql`) and location-aware stencil builders; reuses
  `beatrix/core/external_tools.py` (`ArjunRunner`, `ClairvoyanceRunner`).
- A "why is this interesting?" severity dot on tokens that commonly indicate
  misconfig (e.g. `Server: Apache/2.2.3`, `ACAO: *`).
- Click-through: hover shows the gist, click opens a fuller reference panel.
- Per-token "send this to a scanner" action.

## Research sources

The tip content and (especially) the value enumerations were cross-referenced
against authoritative references rather than written from memory:

- **MDN HTTP reference** — the header index and individual pages for
  Permissions-Policy, Content-Security-Policy, Alt-Svc, Content-Encoding, and
  Clear-Site-Data (exact directive/value lists and syntax).
- **OWASP Secure Headers Project** — the canonical security-header set and the
  information-disclosure headers worth flagging.
- **W3C / WHATWG specs & RFCs** — CSP Level 3 (nonce/hash source grammar),
  Permissions Policy, Fetch (Sec-Fetch-* and the Cross-Origin isolation trio),
  RFC 9110/9112 (framing, Transfer-Encoding) and the request-smuggling literature
  for the desync callouts, RFC 7838 (Alt-Svc), RFC 8470 (Early-Data / 0-RTT
  replay), RFC 9530 (digests), RFC 9421 (message signatures), RFC 8878 (zstd).

The version-disclosure tip (`verdis:`) deliberately carries **no** embedded CVE
database — it flags the disclosure and points at a CVE source, so it can't go
stale or assert a vuln that isn't there.
