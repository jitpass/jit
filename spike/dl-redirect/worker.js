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

    const client = classifyUA(request.headers.get("user-agent") || "");
    const country = (request.cf && request.cf.country) || "??";
    const colo = (request.cf && request.cf.colo) || "??";

    // Always console.log (visible in `wrangler tail` / dev); additionally
    // write an Analytics Engine row when the binding exists (deployed only —
    // AE has no local emulation worth trusting).
    console.log(`dl client=${client} tag=${tag} asset=${asset} country=${country} colo=${colo}`);
    if (env.DL_STATS) {
      // blobs: dimensions to group by; doubles: the count. No IP, ever.
      env.DL_STATS.writeDataPoint({
        blobs: [client, tag, asset, country],
        doubles: [1],
        indexes: [client],
      });
    }

    return Response.redirect(dest, 302);
  },
};
