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
//   country, Cloudflare colo. NO IP, NO full user-agent string, NO cookies.
//   The privacy story must survive being read aloud: "we count downloads by
//   client type and country". Analytics Engine rows carry no IP unless you
//   write one — so we don't.

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
// UA itself: "Homebrew/4.6.19 (Macintosh; arm64 Mac OS X 15.5)". arch is the
// one that matters — jit is arm64-only by decision, and x86_64 rows here are
// the first real measure of Intel demand. Non-brew UAs yield "" (curl's UA
// says nothing about the OS).
function platformFromUA(ua) {
  const m = /Homebrew\/([\d.]+) \(Macintosh; (\w+) Mac OS X ([\d.]+)\)/.exec(ua || "");
  if (!m) return { brewVersion: "", arch: "", os: "" };
  return { brewVersion: m[1], arch: m[2], os: m[3] };
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
    const { brewVersion, arch, os } = platformFromUA(ua);
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
        // blobs: dimensions to group by; doubles: the count. No IP, no full
        // UA, no city — aggregate facts only. Blob order is the query
        // contract: 1=client 2=tag 3=asset 4=country 5=os 6=arch
        // 7=brewVersion 8=asnOrg 9=colo.
        env.DL_STATS.writeDataPoint({
          blobs: [client, tag, asset, country, os, arch, brewVersion, asnOrg, colo],
          doubles: [1],
          indexes: [client],
        });
      }
    } catch (e) {
      // swallowed deliberately: a lost data point over a lost download
    }

    return Response.redirect(dest, 302);
  },
};
