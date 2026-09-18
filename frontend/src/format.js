/** Pure UTC-based derivations and display labels shared by the four screens. */

const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

const PLACEHOLDER = "—";
const UNKNOWN_DETECTOR = "unknown";
const SEPARATOR = "·";
const COMMIT_LENGTH = 7;
const WEEK_COUNT = 8;
const DAYS_PER_WEEK = 7;
const WEEK_MS = DAYS_PER_WEEK * 24 * 60 * 60 * 1000;
const RISK_HIGH_MIN = 20;
const RISK_MEDIUM_MIN = 8;
const GIT_SUFFIX = ".git";

/** Returns a Date for a parseable timestamp, or null for a missing or invalid one. */
function utcDate(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Returns the finding's repository, falling back to its scan target and then to a placeholder. */
export function repoKey(finding, scansById) {
  return finding?.repository ?? scansById?.[finding?.scan_id]?.target ?? PLACEHOLDER;
}

/** Returns the last path segment of a repository key without a trailing ".git". */
export function shortRepo(key) {
  if (typeof key !== "string" || key === "" || key === PLACEHOLDER) {
    return PLACEHOLDER;
  }
  const segments = key.split("/").filter((segment) => segment !== "");
  if (segments.length === 0) {
    return PLACEHOLDER;
  }
  const last = segments[segments.length - 1];
  return last.endsWith(GIT_SUFFIX) ? last.slice(0, -GIT_SUFFIX.length) : last;
}

/** Returns a timestamp as "Sep 15" in UTC, or a placeholder when it cannot be read. */
export function formatDay(iso) {
  const date = utcDate(iso);
  if (date === null) {
    return PLACEHOLDER;
  }
  return `${MONTHS[date.getUTCMonth()]} ${date.getUTCDate()}`;
}

/** Returns a timestamp as "Sep 16, 2026 · 09:14 UTC", or a placeholder when it cannot be read. */
export function formatLastScan(iso) {
  const date = utcDate(iso);
  if (date === null) {
    return PLACEHOLDER;
  }
  const day = `${MONTHS[date.getUTCMonth()]} ${date.getUTCDate()}, ${date.getUTCFullYear()}`;
  const hours = String(date.getUTCHours()).padStart(2, "0");
  const minutes = String(date.getUTCMinutes()).padStart(2, "0");
  return `${day} ${SEPARATOR} ${hours}:${minutes} UTC`;
}

/** Returns the first seven characters of a commit hash, or a placeholder when there is none. */
export function shortCommit(hash) {
  if (typeof hash !== "string" || hash === "") {
    return PLACEHOLDER;
  }
  return hash.slice(0, COMMIT_LENGTH);
}

/** Returns a finding's detector name exactly as the scanner emitted it, or "unknown" when it is missing. */
export function detectorLabel(finding) {
  const detector = finding?.detector;
  return typeof detector === "string" && detector !== "" ? detector : UNKNOWN_DETECTOR;
}

/** Returns a finding's location as "path:line", dropping a missing line and falling back to a placeholder. */
export function fileLabel(finding) {
  const file = finding?.file;
  if (typeof file !== "string" || file === "") {
    return PLACEHOLDER;
  }
  const line = finding?.line;
  return line === null || line === undefined ? file : `${file}:${line}`;
}

/** Returns a finding's redacted value, or a placeholder when the scan stored none. */
export function redactedLabel(finding) {
  const redacted = finding?.redacted;
  return typeof redacted === "string" && redacted !== "" ? redacted : PLACEHOLDER;
}

/** Returns "High", "Medium" or "Low" for a repository's verified finding count. */
export function riskTier(verifiedCount) {
  if (verifiedCount >= RISK_HIGH_MIN) {
    return "High";
  }
  if (verifiedCount >= RISK_MEDIUM_MIN) {
    return "Medium";
  }
  return "Low";
}

/** Returns [{key, repo, total, verified, unverified}] per repository, highest total first. */
export function aggregateByRepo(findings, scansById) {
  const rows = new Map();
  for (const finding of Array.isArray(findings) ? findings : []) {
    const key = repoKey(finding, scansById);
    let row = rows.get(key);
    if (row === undefined) {
      row = { key, repo: shortRepo(key), total: 0, verified: 0, unverified: 0 };
      rows.set(key, row);
    }
    row.total += 1;
    if (finding?.verified === true) {
      row.verified += 1;
    } else {
      row.unverified += 1;
    }
  }
  return Array.from(rows.values()).sort((a, b) => {
    if (b.total !== a.total) {
      return b.total - a.total;
    }
    if (a.key === b.key) {
      return 0;
    }
    return a.key < b.key ? -1 : 1;
  });
}

/** Returns 8 {weekStart (ISO), verified, unverified} entries, oldest first, for the UTC Monday-start weeks ending with now's week. */
export function weeklyBuckets(findings, now = new Date()) {
  const reference = utcDate(now) ?? new Date();
  const year = reference.getUTCFullYear();
  const month = reference.getUTCMonth();
  const monday = reference.getUTCDate() - ((reference.getUTCDay() + 6) % 7);
  const buckets = [];
  for (let step = WEEK_COUNT - 1; step >= 0; step -= 1) {
    const start = Date.UTC(year, month, monday - DAYS_PER_WEEK * step);
    buckets.push({
      weekStart: new Date(start).toISOString(),
      verified: 0,
      unverified: 0,
    });
  }
  const firstStart = Date.parse(buckets[0].weekStart);
  for (const finding of Array.isArray(findings) ? findings : []) {
    const created = utcDate(finding?.created_at);
    if (created === null) {
      continue;
    }
    const index = Math.floor((created.getTime() - firstStart) / WEEK_MS);
    if (index < 0 || index >= WEEK_COUNT) {
      continue;
    }
    if (finding?.verified === true) {
      buckets[index].verified += 1;
    } else {
      buckets[index].unverified += 1;
    }
  }
  return buckets;
}

/** Returns a one-sentence rotation instruction naming the detector, citing its rotation guide when the finding carries one. */
export function remediationText(finding) {
  const detector = detectorLabel(finding);
  const guide = finding?.raw?.ExtraData?.rotation_guide;
  if (typeof guide === "string" && guide.trim() !== "") {
    return `Rotate this ${detector} credential using the provider's rotation guide at ${guide}, then audit recent use of the old value and remove it from the repository.`;
  }
  return `Rotate this ${detector} credential at its provider, then audit recent use of the old value and remove it from the repository.`;
}
