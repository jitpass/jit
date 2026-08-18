// spike: download-redirect Worker for dl.jitpass.com.
//
// The whole job: log one line about the request, then 302 to the real GitHub
// release asset. GitHub keeps serving the bytes, the cask's sha256 stays a
// hash of GitHub's bytes, and the Developer ID signature check in `jit
// upgrade` is untouched. If this Worker is wrong in any way the worst case
// must be "download fails loudly", never "different bytes served" — which is
// why it only ever redirects to a URL it builds from an allowlisted shape,
// and never proxies a body.
//
// Routes (mirroring GitHub's own path shape so the cask template is trivial):
//   GET /jitpass/jit/releases/download/<tag>/<asset>   -> 302 pinned tag
//   GET /jitpass/jit/releases/latest/download/<asset>  -> 302 latest
//   anything else                                      -> 404
//
// What gets logged, and deliberately nothing more:
//   client class (brew | curl | jit-upgrade | browser | other), tag, asset,
//   country, Cloudflare colo, and a salted hash of the IP. NO RAW IP, NO full
//   user-agent string, NO cookies.
//   The privacy story must still survive being read aloud: "we count downloads
//   by client type and country, and we can tell two downloads apart without
//   knowing who either one is." The hash exists because a download count that
//   cannot separate one person pulling ten times from ten people is not a
//   number worth quoting. It is salted because SHA-256 over a bare IPv4 is
//   2^32 guesses, which is an IP with extra steps.
//
// The columns themselves are named and ordered in schema.mjs. Run `./sql.mjs`
// for queries that come back with those names as headers instead of blob1..9.

import { BLOBS, DOUBLES, INDEX } from "./schema.mjs";

const OWNER = "jitpass";
const REPO = "jit";

// Only assets a release actually publishes; anything else 404s rather than
// becoming an open redirect namespace.
const ASSET_ALLOW = /^(jitpass_darwin_arm64\.tar\.gz|checksums\.txt)$/;
const TAG_ALLOW = /^v\d+\.\d+\.\d+$/;

function classifyUA(ua) {
  if (!ua) return "other";
  if (ua.startsWith("jit-upgrade")) return "jit-upgrade";
  if (ua.includes("Homebrew")) return "brew";
  if (ua.startsWith("curl/") || ua.startsWith("Wget/")) return "curl";
  if (ua.includes("Mozilla/")) return "browser";
  return "other";
}

// Pull the aggregate platform facts out of Homebrew's UA without storing the
// UA itself: "Homebrew/6.0.18 (Macintosh; arm64 Mac OS X 26.5.2) curl/8.7.1".
// arch is the one that matters — jit is arm64-only by decision, and x86_64
// rows here are the first real measure of Intel demand.
//
// Deliberately loose about the platform segment. The original pattern demanded
// "Macintosh; <arch> Mac OS X <version>" exactly, and a real brew download in
// JP arrived classified as brew with all three fields empty, which means the
// UA said something this did not anticipate — Homebrew on Linux, an older
// release, or a format change. Rather than guess which, match the version and
// arch wherever they appear and let the OS label be whatever it is.
//
// When it still does not parse, say so in the log. We never store the full UA,
// so a silent "" is unfalsifiable: it looks the same whether the client was
// curl (correct) or a brew format we cannot read (a bug).
function platformFromUA(ua, client) {
  const s = ua || "";
  const brew = /Homebrew\/([\d.]+)/.exec(s);
  if (!brew) return { brewVersion: "", arch: "", os: "" };

  // "(Macintosh; arm64 Mac OS X 26.5.2)" and "(Linux; x86_64 Ubuntu 22.04)"
  // both land here; group 2 is the OS label, group 3 its version.
  const platform = /\((?:Macintosh|Linux); (\w+) ([A-Za-z ]+?) ([\d._]+)\)/.exec(s);
  if (!platform) {
    console.log(`dl ua-parse-miss client=${client} brew=${brew[1]}`);
    return { brewVersion: brew[1], arch: "", os: "" };
  }

  return { brewVersion: brew[1], arch: platform[1], os: platform[3] };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);

    // /jitpass/jit/releases/download/<tag>/<asset>
    // /jitpass/jit/releases/latest/download/<asset>
    let tag = null;
    let asset = null;
    if (
      parts.length === 6 &&
      parts[0] === OWNER && parts[1] === REPO &&
      parts[2] === "releases" && parts[3] === "download" &&
      TAG_ALLOW.test(parts[4]) && ASSET_ALLOW.test(parts[5])
    ) {
      tag = parts[4];
      asset = parts[5];
    } else if (
      parts.length === 6 &&
      parts[0] === OWNER && parts[1] === REPO &&
      parts[2] === "releases" && parts[3] === "latest" &&
      parts[4] === "download" && ASSET_ALLOW.test(parts[5])
    ) {
      tag = "latest";
      asset = parts[5];
    } else {
      return new Response("not found\n", { status: 404 });
    }

    const dest = tag === "latest"
      ? `https://github.com/${OWNER}/${REPO}/releases/latest/download/${asset}`
      : `https://github.com/${OWNER}/${REPO}/releases/download/${tag}/${asset}`;

    const ua = request.headers.get("user-agent") || "";
    const client = classifyUA(ua);
    const { brewVersion, arch, os } = platformFromUA(ua, client);
    const country = (request.cf && request.cf.country) || "??";
    const colo = (request.cf && request.cf.colo) || "??";
    // ASN org separates datacenter/CI pulls (GitHub Actions, AWS, ...) from
    // residential ISPs — the bot filter GitHub's own counter can never give.
    // An org name is an aggregate fact about a network, not about a person.
    const asnOrg = (request.cf && request.cf.asOrganization) || "";

    // Always console.log (visible in `wrangler tail` / dev); additionally
    // write an Analytics Engine row when the binding exists (deployed only —
    // AE has no local emulation worth trusting).
    //
    // FAIL OPEN, same rule internal/guard lives by: measurement must never
    // break delivery. Before the dataset existed, writeDataPoint threw and
    // every download 500'd — counting took the redirect down. Nothing in
    // this block may prevent the 302.
    try {
      console.log(`dl client=${client} tag=${tag} asset=${asset} country=${country} colo=${colo} arch=${arch} os=${os} asn=${asnOrg}`);
      if (env.DL_STATS) {
        // Column order and meaning both live in schema.mjs, which `./sql.mjs`
        // reads to generate queries with real headers.
        const view = { client, tag, asset, country, os, arch, brewVersion, asnOrg, colo };
        ctx.waitUntil(record(env, view, request.headers.get("cf-connecting-ip")));
      }
    } catch (e) {
      // swallowed deliberately: a lost data point over a lost download
    }

    return Response.redirect(dest, 302);
  },
};

// Hashing is async, so this runs detached after the 302 has already gone out.
// It keeps its own try/catch for the same FAIL OPEN reason: a lost data point
// is always cheaper than a lost download.
async function record(env, view, ip) {
  try {
    // All three derive from the IP, none of them keep it. Run together because
    // two are network calls and this is already off the critical path.
    const [vid, netblockOrg, ptrHost] = await Promise.all([
      visitorId(ip, env.IP_SALT),
      netblockOrgOf(ip),
      ptrHostOf(ip),
    ]);
    const row = { ...view, visitorId: vid, netblockOrg, ptrHost };
    env.DL_STATS.writeDataPoint({
      blobs: BLOBS.map(([, get]) => get(row) || ""),
      doubles: DOUBLES.map(([, get]) => get(row) || 0),
      indexes: [INDEX[1](row)],
    });
  } catch (e) {
    // swallowed deliberately: see above
  }
}

// A stable pseudonym for one downloader: the first 64 bits of SHA-256 over the
// IP and a secret salt. Enough to tell a repeat puller from a new one, not
// enough to be an IP at rest. Matches the landing site's worker exactly, so
// the two datasets can be reasoned about the same way.
//
// Unset salt writes a marker rather than a reversible hash. Set it with:
//   npx wrangler secret put IP_SALT
async function visitorId(ip, salt) {
  if (!ip) return "";
  if (!salt) return "unsalted";

  const bytes = new TextEncoder().encode(`${salt}:${ip}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest, 0, 8))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// IP enrichment. Both lookups answer "which company is this" better than the
// ASN can, and both return "" rather than throwing: a row with a blank column
// is worth more than no row, and neither may ever be the reason a download
// goes uncounted.
// ---------------------------------------------------------------------------

const LOOKUP_TIMEOUT_MS = 3000;

// RDAP is WHOIS over HTTPS returning JSON, free and unauthenticated, so a
// Worker can query it directly. rdap.org bootstraps to whichever RIR owns the
// address (ARIN, RIPE, APNIC, ...).
//
// Cached by /24 for a day. RIRs rate-limit, and a team pulling the binary
// would otherwise issue the same lookup over and over.
async function netblockOrgOf(ip) {
  if (!ip) return "";

  const key = new Request(`https://rdap.cache.invalid/${block(ip)}`);
  const cache = caches.default;

  try {
    const hit = await cache.match(key);
    if (hit) return await hit.text();

    const res = await fetch(`https://rdap.org/ip/${ip}`, {
      headers: { accept: "application/rdap+json" },
      signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
    });
    if (!res.ok) {
      console.log(`dl rdap-http status=${res.status} block=${block(ip)}`);
      return "";
    }

    const org = registrantOf(await res.json());
    // The first live row came back with this column empty even though the same
    // lookup by hand returned a usable registrant in 0.3s. Log the outcome so
    // the next occurrence says which half failed instead of leaving us to
    // guess between the fetch, the parse, and the cache.
    if (!org) console.log(`dl rdap-no-org block=${block(ip)}`);
    await cache.put(
      key,
      new Response(org, { headers: { "cache-control": "max-age=86400" } }),
    );
    return org;
  } catch (e) {
    console.log(`dl rdap-threw block=${block(ip)} err=${e && e.name}`);
    return "";
  }
}

// Prefer a named registrant entity; fall back to the network's own name, which
// is often a handle like "COMCAST-BIZ-4" but still narrows it down.
function registrantOf(data) {
  for (const entity of data.entities || []) {
    const roles = entity.roles || [];
    if (!roles.includes("registrant") && !roles.includes("administrative")) continue;
    for (const field of (entity.vcardArray || [])[1] || []) {
      if (field[0] === "fn" && field[3]) return String(field[3]).slice(0, 128);
    }
  }
  return String(data.name || "").slice(0, 128);
}

// Reverse DNS over Cloudflare's DoH endpoint. A corporate host frequently
// resolves to something carrying the company's own domain.
//
// IPv4 only: IPv6 reverse names are nibble-expanded and the hit rate on them
// is close to nothing, so it is not worth the code.
async function ptrHostOf(ip) {
  if (!ip || !isIPv4(ip)) return "";

  const name = ip.split(".").reverse().join(".") + ".in-addr.arpa";
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${name}&type=PTR`,
      {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
      },
    );
    if (!res.ok) return "";

    const ptr = ((await res.json()).Answer || []).find((a) => a.type === 12);
    return ptr ? String(ptr.data).replace(/\.$/, "").slice(0, 128) : "";
  } catch (e) {
    return "";
  }
}

const isIPv4 = (ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);

// Cache key granularity: a /24 for v4, the routing-ish prefix for v6.
function block(ip) {
  if (isIPv4(ip)) return ip.split(".").slice(0, 3).join(".");
  return ip.split(":").slice(0, 4).join(":");
}
