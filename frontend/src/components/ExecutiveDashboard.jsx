import { aggregateByRepo, formatDay, weeklyBuckets } from "../format.js";
import "./ExecutiveDashboard.css";

const EXPOSURE_ROWS = 6;
const RESOLVED = "resolved";
const IGNORED = "ignored";

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

/** Renders one metric tile from its label, numeric value and optional decorative dot class. */
function MetricTile({ label, value, dotClass }) {
  return (
    <div className="card dash-tile">
      <div className="dash-tile-label label">
        {dotClass === undefined ? null : <span className={`dash-dot ${dotClass}`} />}
        <span>{label}</span>
      </div>
      <div className="dash-tile-value">{value.toLocaleString()}</div>
    </div>
  );
}

/** Executive Summary screen: detection totals, the eight-week trend, triage progress and repo exposure from {scans, findings, scansById, triage, onNavigate}. */
export default function ExecutiveDashboard({ scans, findings, scansById, triage, onNavigate }) {
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
  const progress =
    findingRows.length === 0 ? 0 : Math.round((resolved / findingRows.length) * 100);
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
              <div className="dash-bar-col" key={week.weekStart}>
                <span className="dash-bar-total">
                  {(week.verified + week.unverified).toLocaleString()}
                </span>
                <div className="dash-bar-stack">
                  <div
                    className="dash-bar-seg--verified"
                    style={{ height: ratio(week.verified, weekMax) }}
                  />
                  <div
                    className="dash-bar-seg--unverified"
                    style={{ height: ratio(week.unverified, weekMax) }}
                  />
                </div>
                <span className="dash-bar-label">{formatDay(week.weekStart)}</span>
              </div>
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
          <div className="dash-progress-value">{progress}%</div>
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
        {exposure.map((row) => (
          <div className="dash-exposure-row" key={row.key}>
            <div className="dash-exposure-name">{row.repo}</div>
            <div className="dash-exposure-count">{row.total.toLocaleString()}</div>
            <div className="dash-exposure-track">
              <div
                className="dash-exposure-fill"
                style={{ width: ratio(row.total, exposureMax) }}
              />
            </div>
          </div>
        ))}
        <button type="button" className="dash-link" onClick={() => onNavigate("leaderboard")}>
          View full leaderboard →
        </button>
      </section>
    </>
  );
}
