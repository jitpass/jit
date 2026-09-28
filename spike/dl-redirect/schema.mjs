// The `jit_downloads` schema, in one place.
//
// Analytics Engine has no column names. It hands back `blob1` through
// `blob20` and leaves the meaning wherever someone wrote it down, which is how
// you end up staring at a row and grepping this directory to learn that blob8
// was the ASN organization.
//
// So the name and the value that fills it are defined together, once, here.
// worker.js writes the columns in this order; `./sql.mjs` reads the same list
// to emit a SELECT that aliases every column back to its name. Neither can
// drift from the other, because there is only one list.
//
// POSITIONS ARE PERMANENT. blob4 is whatever blob4 meant on the day the row
// was written, and no migration reaches back to fix it. Append to the end.
// Never reorder, never delete. To retire a field, keep its slot and return "".
//
// The names below are the only thing that changed when this list was
// extracted; every position still holds exactly what it held before.

export const BLOBS = [
  ["client", (v) => v.client],
  ["release_tag", (v) => v.tag],
  ["asset", (v) => v.asset],
  ["country", (v) => v.country],
  // The next three come out of Homebrew's UA string and are empty for every
  // other client -- curl's UA says nothing about the machine. Empty here means
  // "not a brew install", not "unknown Mac". `macos_version` is a macOS
  // release like "15.5"; it was called `os` when it was blob5 with no name,
  // which is most of why a row needed decoding by hand.
  ["macos_version", (v) => v.os],
  ["cpu_arch", (v) => v.arch],
  ["brew_version", (v) => v.brewVersion],
  // Separates datacenter and CI pulls (GitHub Actions, AWS, ...) from
  // residential ISPs -- the bot filter GitHub's own counter cannot give. An
  // org name is an aggregate fact about a network, not about a person.
  ["asn_org", (v) => v.asnOrg],
  // Which Cloudflare edge served it, as an IATA code: "CPH" is Copenhagen.
  // A rough proxy for where the request entered the network, not where the
  // person is.
  ["edge_colo", (v) => v.colo],
  // Appended after the fact, which is why it sits at the end rather than next
  // to the other per-request facts. A salted hash of the IP, never the IP.
  // This is what turns "downloads" into "downloaders": without it, one person
  // pulling ten times and ten people pulling once are the same number.
  ["visitor_id", (v) => v.visitorId],
  // Both of these are derived from the IP at write time and the IP is then
  // dropped. They exist because `asn_org` only names organizations big enough
  // to own an autonomous system -- everyone else shows up as their ISP.
  //
  // netblock_org is the RIR's registrant for the specific block. When an ISP
  // reassigns a range to a business customer that reassignment is registered,
  // so this resolves companies `asn_org` reports as "Comcast Cable".
  // ptr_host is reverse DNS, which often carries a corporate domain.
  //
  // Both are best-effort: empty when the lookup fails, is rate-limited, or the
  // block simply has no reassignment on file. Never treat empty as "unknown
  // company" -- it means "nothing on record", which is the common case.
  ["netblock_org", (v) => v.netblockOrg],
  ["ptr_host", (v) => v.ptrHost],
  // Appended 23 Sep 2026. NOT the full user-agent -- the closing note below
  // still holds. What lands here is the leading product token only:
  // "curl/8.7.1", "Homebrew/4.3.8", "Go-http-client/2.0". Everything a browser
  // prints after "Mozilla/5.0" (platform, engine, Chrome build) is the part
  // that fingerprints a person, and it never leaves the Worker. "Mozilla/5.0"
  // itself collapses to "Mozilla" because the 5.0 has meant nothing since
  // Netscape. "(empty)" is a request that sent no UA, which is its own signal.
  ["ua_product", (v) => v.uaProduct],
  // Why `client` was not enough: classifyUA maps every Mozilla-bearing UA to
  // "browser", and Bingbot, GPTBot and every scraper on the internet sends
  // one. In the week of 17 Sep 2026 that put 36 datacenter pulls in the same
  // bucket as 11 real people.
  //
  // This column records what the UA ADMITS to: "crawler" (declares itself a
  // bot), "headless" (a driven browser), "tool" (a generic HTTP library --
  // scrapers and mirrors), or "none". curl, Wget and Homebrew are deliberately
  // NOT "tool": they are documented install paths for jit, and `client`
  // already tells them apart.
  //
  // "" means the row predates this column, NOT "not a bot" -- the same trap
  // visitor_id documents above. A query counting humans must say
  // `bot_kind = 'none'`, never `bot_kind = ''`.
  //
  // A user-agent is self-reported, so this is a floor and never a ceiling. It
  // does not catch a scanner sending a real Chrome UA from a cloud IP; that is
  // what ptr_host and asn_org are for, and sql.mjs filters on all three.
  ["bot_kind", (v) => v.botKind],
];

// Always 1. Rows are the unit; `SUM(_sample_interval)` is the honest count
// once Analytics Engine starts sampling, and this column is the thing that
// makes `SUM(_sample_interval * downloads)` read the way you would say it.
export const DOUBLES = [["downloads", () => 1]];

// The sampling key. Client class is low cardinality and the thing most
// queries group by, so sampling degrades evenly across brew/curl/browser
// rather than throwing away one of them.
export const INDEX = ["client", (v) => v.client];

// Deliberately absent, and it should stay that way: no IP, no full user-agent,
// no city, no cookies. The privacy story has to survive being read aloud --
// "we count downloads by client type and country" -- and Analytics Engine
// rows carry no IP unless you write one.
