#!/usr/bin/env node
// Queries for the `jit_downloads` dataset, with every column aliased back to
// its name so a row reads as itself instead of blob1 through blob9.
//
// The aliases come from schema.mjs, the same list worker.js writes from, so a
// column added there shows up here without a second edit.
//
//   ./sql.mjs            recent downloads, newest first
//   ./sql.mjs summary    the headline numbers, for a deck or an update
//   ./sql.mjs growth     downloads and unique downloaders, week by week
//   ./sql.mjs companies  which organizations are installing it
//   ./sql.mjs countries  geographic spread
//   ./sql.mjs active     existing users upgrading -- the retention signal
//   ./sql.mjs --curl     wrap it in a SQL API call
//
// Paste into the Analytics Engine studio, or run the --curl form with an API
// token holding Account Analytics Read:
//
//   CF_ACCOUNT_ID=... CF_API_TOKEN=... ./sql.mjs orgs --curl | sh

import { BLOBS, DOUBLES, INDEX } from "./schema.mjs";

const DATASET = "jit_downloads";

// Cloud and CI networks. A pull from one of these is a build pipeline, not a
// person. Counting them as users is exactly how a download number falls apart
// the first time somebody looks closely, so every people-shaped query below
// excludes them -- and `summary` reports what it excluded rather than hiding it.
const INFRA = [
  "Amazon", "Google", "Microsoft", "DigitalOcean", "Hetzner", "OVH", "Linode",
  "GitHub", "Cloudflare", "Fastly", "Akamai", "Oracle", "Alibaba", "Scaleway",
  "Vultr", "Contabo", "Datacamp", "Choopa", "Leaseweb",
];
const HUMAN = INFRA.map((o) => `blob8 NOT LIKE '%${o}%'`).join("\n    AND ");

// visitor_id (blob10) was appended to the schema on 18 Aug 2026 and only
// reached every row from the 19th. Earlier rows carry "", and Analytics Engine
// counts "" as a value -- so a DISTINCT over the whole table reports one extra
// "downloader" who is actually every pre-19-Aug download collapsed into one.
// Any query that counts PEOPLE has to exclude those rows; queries that count
// downloads must not, or they lose the launch week.
const HAS_VISITOR = `blob10 != ''`;

// A conditional distinct count.
//
// Analytics Engine has no uniqIf/countDistinctIf, and it rejects
// IF(cond, blob10, NULL) outright -- both branches of IF must be the same type
// and NULL is not a String. That error is why `summary` and `active` below
// returned nothing but a 400 from the day they were written.
//
// IF(cond, blob10, '') is accepted, but it folds every non-matching row into a
// single "" bucket that DISTINCT then counts as one person. So subtract that
// bucket, and only when it exists -- MAX(IF(cond, 0, 1)) is 1 if any row fails
// the condition and 0 if none do, which keeps the all-match case exact too.
const peopleWhere = (cond) =>
  `COUNT(DISTINCT IF(${cond}, blob10, '')) - MAX(IF(${cond}, 0, 1))`;


// `_sample_interval` is how many real events a row stands for once Analytics
// Engine starts sampling. At this volume it is 1, but summing it instead of
// counting rows is what keeps the numbers right when it stops being 1.
const blobNames = BLOBS.map(([name]) => name);

const columns = [
  ["timestamp", "timestamp"],
  // The index is a copy of a blob whenever it samples on a dimension already
  // stored -- here it mirrors `client` -- and selecting both would emit the
  // same alias twice. Take index1 only when nothing else carries its name.
  ...(blobNames.includes(INDEX[0]) ? [] : [["index1", INDEX[0]]]),
  ...BLOBS.map(([name], i) => [`blob${i + 1}`, name]),
  ...DOUBLES.map(([name], i) => [`double${i + 1}`, name]),
  ["_sample_interval", "events"],
];

const select = columns
  .map(([col, name]) => (col === name ? `  ${col}` : `  ${col} AS ${name}`))
  .join(",\n");

const QUERIES = {
  recent: `SELECT
${select}
FROM ${DATASET}
WHERE timestamp >= NOW() - INTERVAL '7' DAY
ORDER BY timestamp DESC
LIMIT 100`,

  // The four numbers worth putting in front of someone, and the one caveat
  // that keeps them honest.
  // NOT scoped by HAS_VISITOR in the WHERE, on purpose: the download totals
  // (downloads_all, downloads_human) must span the whole 30 days including the
  // pre-19-Aug launch week, per HAS_VISITOR's own contract. The people counts
  // exclude the pre-visitor rows themselves, via peopleWhere -- so downloads
  // are all-time and downloaders start 19 Aug, in one query. countries and
  // networks span the full window too; a dimension count is not people, and a
  // launch-week country is still a real country.
  summary: `SELECT
  SUM(_sample_interval) AS downloads_all,
  ${peopleWhere(HAS_VISITOR)} AS downloaders_all,
  SUM(IF(${HUMAN}, _sample_interval, 0)) AS downloads_human,
  ${peopleWhere(HUMAN)} AS downloaders_human,
  COUNT(DISTINCT blob4) AS countries,
  COUNT(DISTINCT blob8) AS networks
FROM ${DATASET}
WHERE timestamp >= NOW() - INTERVAL '30' DAY`,

  // Downloaders, not downloads. The gap between the two columns is the answer
  // to "how many of those are the same person pulling repeatedly".
  // No HAS_VISITOR in the WHERE: the weekly downloads column is a total and
  // must keep the launch week. downloaders excludes the pre-visitor rows with
  // peopleWhere(HAS_VISITOR) instead -- the WHERE already filters to human, so
  // peopleWhere(HUMAN) would be all-true here and fold nothing.
  growth: `SELECT
  toStartOfWeek(timestamp) AS week,
  SUM(_sample_interval) AS downloads,
  ${peopleWhere(HAS_VISITOR)} AS downloaders,
  COUNT(DISTINCT blob8) AS networks
FROM ${DATASET}
WHERE timestamp >= NOW() - INTERVAL '90' DAY
  AND ${HUMAN}
GROUP BY week
ORDER BY week DESC`,

  // A repeat organization is the signal; a single pull is noise. first_seen
  // and last_seen are there so you can tell the two apart at a glance.
  companies: `SELECT
  blob8 AS company,
  blob4 AS country,
  COUNT(DISTINCT blob10) AS downloaders,
  SUM(_sample_interval) AS downloads,
  MIN(timestamp) AS first_seen,
  MAX(timestamp) AS last_seen
FROM ${DATASET}
WHERE timestamp >= NOW() - INTERVAL '90' DAY
  AND ${HUMAN}
  AND ${HAS_VISITOR}
  AND blob8 != ''
GROUP BY company, country
ORDER BY downloaders DESC
LIMIT 50`,

  countries: `SELECT
  blob4 AS country,
  COUNT(DISTINCT blob10) AS downloaders,
  SUM(_sample_interval) AS downloads,
  COUNT(DISTINCT blob8) AS networks
FROM ${DATASET}
WHERE timestamp >= NOW() - INTERVAL '90' DAY
  AND ${HUMAN}
  AND ${HAS_VISITOR}
GROUP BY country
ORDER BY downloaders DESC`,

  // `jit-upgrade` means an install that already existed came back for a newer
  // build. That is a used tool rather than a downloaded one, and it is the
  // number that answers the question a download count always invites.
  active: `SELECT
  toStartOfWeek(timestamp) AS week,
  ${peopleWhere(`blob1 = 'jit-upgrade'`)} AS upgrading_users,
  ${peopleWhere(`blob1 != 'jit-upgrade'`)} AS new_installs,
  COUNT(DISTINCT blob10) AS total_downloaders
FROM ${DATASET}
WHERE timestamp >= NOW() - INTERVAL '90' DAY
  AND ${HUMAN}
  AND ${HAS_VISITOR}
GROUP BY week
ORDER BY week DESC`,
};

const args = process.argv.slice(2);
const asCurl = args.includes("--curl");
const name = args.find((a) => !a.startsWith("--")) || "recent";

const sql = QUERIES[name];
if (!sql) {
  console.error(`unknown query "${name}"; try: ${Object.keys(QUERIES).join(", ")}`);
  process.exit(1);
}

if (!asCurl) {
  console.log(sql);
  process.exit(0);
}

const account = process.env.CF_ACCOUNT_ID;
const token = process.env.CF_API_TOKEN;
if (!account || !token) {
  console.error("--curl needs CF_ACCOUNT_ID and CF_API_TOKEN in the environment");
  process.exit(1);
}

console.log(
  `curl "https://api.cloudflare.com/client/v4/accounts/${account}/analytics_engine/sql" \\
  --header "Authorization: Bearer ${token}" \\
  --data ${JSON.stringify(sql.replace(/\n/g, " "))}`,
);
