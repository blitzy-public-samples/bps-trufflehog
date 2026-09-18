import { aggregateByRepo, formatDay, weeklyBuckets } from "../format.js";
import "./ExecutiveDashboard.css";

const EXPOSURE_ROWS = 6;
const RESOLVED = "resolved";
const IGNORED = "ignored";
const EXPOSURE_EMPTY = "No findings yet. Start a scan from the sidebar.";
const PROGRESS_MAX_DECIMALS = 3;

/** Returns count ÷ max as a CSS percentage string, or "0%" when max is not positive. */
function ratio(count, max) {
  if (!Number.isFinite(count) || !Number.isFinite(max) || max <= 0 || count <= 0) {
    return "0%";
  }
  return `${(Math.min(count, max) / max) * 100}%`;
}

/** Returns the largest value produced by read over rows, or 0 for an empty list. */
function maxOf(rows, read) {
  return rows.reduce((largest, row) => Math.max(largest, read(row)), 0);
}

/** Returns className plus modifier when count is positive, so zero-valued parts stay collapsed. */
function withNonzero(className, modifier, count) {
  return count > 0 ? `${className} ${modifier}` : className;
}

/** Returns the decimal places at which one resolution out of total changes the displayed percentage. */
function progressDecimals(total) {
  const step = 100 / total;
  let decimals = 0;
  while (decimals < PROGRESS_MAX_DECIMALS && 10 ** -decimals > step) {
    decimals += 1;
  }
  return decimals;
}

/** Returns resolved ÷ total as a percentage string, truncated to a precision where a single resolution is visible. */
function formatProgress(resolved, total) {
  if (total <= 0 || resolved <= 0) {
    return "0%";
  }
  if (resolved >= total) {
    return "100%";
  }
  const factor = 10 ** progressDecimals(total);
  return `${Math.floor((resolved / total) * 100 * factor) / factor}%`;
}

/** Returns one week's spoken summary: its start date, total detections and verified/unverified split. */
function weekSummary(week) {
  const total = week.verified + week.unverified;
  const noun = total === 1 ? "detection" : "detections";
  return `Week of ${formatDay(week.weekStart)}: ${total.toLocaleString()} ${noun}, ${week.verified.toLocaleString()} verified, ${week.unverified.toLocaleString()} unverified`;
}

/** Returns one repo row's spoken summary: its name, total detections and verified/unverified split. */
function exposureSummary(row) {
  const noun = row.total === 1 ? "detection" : "detections";
  return `${row.repo}: ${row.total.toLocaleString()} ${noun}, ${row.verified.toLocaleString()} verified, ${row.unverified.toLocaleString()} unverified`;
}

/** Renders one week column: a bottom-aligned stack scaled to week total ÷ max, its total above it and its date below. */
function WeekBar({ week, max }) {
  const total = week.verified + week.unverified;
  return (
    <div className="dash-bar-col" role="img" aria-label={weekSummary(week)}>
      <div className="dash-bar-plot">
        <div
          className={withNonzero("dash-bar-group", "dash-bar-group--nonzero", total)}
          style={{ height: ratio(total, max) }}
          aria-hidden="true"
        >
          <span className="dash-bar-total">{total.toLocaleString()}</span>
          <div className="dash-bar-stack">
            <div
              className={withNonzero(
                "dash-bar-seg--verified",
                "dash-bar-seg--nonzero",
                week.verified,
              )}
              style={{ height: ratio(week.verified, total) }}
            />
            <div
              className={withNonzero(
                "dash-bar-seg--unverified",
                "dash-bar-seg--nonzero",
                week.unverified,
              )}
              style={{ height: ratio(week.unverified, total) }}
            />
          </div>
        </div>
      </div>
      <span className="dash-bar-label" aria-hidden="true">
        {formatDay(week.weekStart)}
      </span>
    </div>
  );
}

/** Renders one metric tile from its label, numeric value and optional decorative dot class. */
function MetricTile({ label, value, dotClass }) {
  return (
    <div className="card dash-tile">
      <div className="dash-tile-label label">
        {dotClass === undefined ? null : <span className={`dash-dot ${dotClass}`} />}
        <span className="dash-tile-label-text">{label}</span>
      </div>
      <div className="dash-tile-value">{value.toLocaleString()}</div>
    </div>
  );
}

/** Executive Summary screen: detection totals, the eight-week trend, triage progress and repo exposure from {scans, findings, scansById, triage, onNavigate}. */
export function ExecutiveDashboard({ scans, findings, scansById, triage, onNavigate }) {
  const scanRows = Array.isArray(scans) ? scans : [];
  const findingRows = Array.isArray(findings) ? findings : [];
  const triageMap = triage ?? {};

  const verified = findingRows.filter((finding) => finding.verified === true).length;
  const unverified = findingRows.filter((finding) => finding.verified === false).length;
  const reposScanned = new Set(scanRows.map((scan) => scan.target)).size;

  const weeks = weeklyBuckets(findingRows);
  const weekMax = maxOf(weeks, (week) => week.verified + week.unverified);

  const resolved = findingRows.filter(
    (finding) => triageMap[finding.id]?.state === RESOLVED,
  ).length;
  const progress = formatProgress(resolved, findingRows.length);
  const open = findingRows.filter((finding) => {
    const state = triageMap[finding.id]?.state;
    return state !== RESOLVED && state !== IGNORED;
  });
  const openVerified = open.filter((finding) => finding.verified === true).length;
  const openUnverified = open.filter((finding) => finding.verified === false).length;

  const exposure = aggregateByRepo(findingRows, scansById).slice(0, EXPOSURE_ROWS);
  const exposureMax = maxOf(exposure, (row) => row.total);

  return (
    <>
      <section className="dash-tiles">
        <MetricTile label="TOTAL DETECTIONS" value={findingRows.length} />
        <MetricTile label="VERIFIED" value={verified} dotClass="dash-dot--verified" />
        <MetricTile label="UNVERIFIED" value={unverified} dotClass="dash-dot--unverified" />
        <MetricTile label="REPOS SCANNED" value={reposScanned} />
      </section>

      <section className="dash-row2">
        <div className="card">
          <h2 className="dash-card-title">Detections Over Time (8 weeks)</h2>
          <div className="dash-chart-area">
            {weeks.map((week) => (
              <WeekBar key={week.weekStart} week={week} max={weekMax} />
            ))}
          </div>
          <div className="dash-legend">
            <span className="dash-legend-item">
              <span className="dash-swatch dash-swatch--verified" />
              Verified
            </span>
            <span className="dash-legend-item">
              <span className="dash-swatch dash-swatch--unverified" />
              Unverified
            </span>
          </div>
        </div>

        <div className="card">
          <h2 className="dash-card-title">Triage Progress</h2>
          <div className="dash-progress-value">{progress}</div>
          <p className="dash-progress-count">
            {`${resolved.toLocaleString()} of ${findingRows.length.toLocaleString()} findings`}
          </p>
          <p className="dash-progress-caption">resolved in this session (not persisted)</p>
          <div className="dash-progress-row">
            <span>Open verified</span>
            <span>{openVerified.toLocaleString()}</span>
          </div>
          <div className="dash-progress-row">
            <span>Open unverified</span>
            <span>{openUnverified.toLocaleString()}</span>
          </div>
        </div>
      </section>

      <section className="card dash-exposure">
        <h2 className="dash-card-title">Exposure by Repo/Team</h2>
        {exposure.length === 0 ? (
          <p className="dash-exposure-empty">{EXPOSURE_EMPTY}</p>
        ) : (
          <div className="dash-exposure-rows">
            {exposure.map((row) => (
              <div className="dash-exposure-row" key={row.key}>
                <div className="dash-exposure-name" title={row.repo}>
                  {row.repo}
                </div>
                <div className="dash-exposure-count">{row.total.toLocaleString()}</div>
                <div className="dash-exposure-track" role="img" aria-label={exposureSummary(row)}>
                  <div
                    className={withNonzero(
                      "dash-exposure-fill",
                      "dash-exposure-fill--nonzero",
                      row.total,
                    )}
                    style={{ width: ratio(row.total, exposureMax) }}
                  >
                    <div
                      className={withNonzero(
                        "dash-exposure-seg--verified",
                        "dash-exposure-seg--nonzero",
                        row.verified,
                      )}
                      style={{ width: ratio(row.verified, row.total) }}
                    />
                    <div
                      className={withNonzero(
                        "dash-exposure-seg--unverified",
                        "dash-exposure-seg--nonzero",
                        row.unverified,
                      )}
                      style={{ width: ratio(row.unverified, row.total) }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
        <button type="button" className="dash-link" onClick={() => onNavigate("leaderboard")}>
          View full leaderboard →
        </button>
      </section>
    </>
  );
}

export default ExecutiveDashboard;
