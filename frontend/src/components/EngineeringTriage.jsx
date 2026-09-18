import { useMemo, useState } from "react";

import {
  detectorLabel,
  fileLabel,
  formatDay,
  redactedLabel,
  repoKey,
  shortCommit,
  shortRepo,
} from "../format.js";

import "./EngineeringTriage.css";

const ALL_TYPES = "all";
const PLACEHOLDER = "—";
const DEFAULT_ASSIGNEE = "Unassigned";
const ASSIGNEES = [DEFAULT_ASSIGNEE, "Me"];
const TRIAGE_LABELS = { resolved: "Resolved", ignored: "Ignored" };
const STATUS_FILTERS = [
  { value: "all", label: "All" },
  { value: "verified", label: "Verified" },
  { value: "unverified", label: "Unverified" },
];

/** Returns the distinct detector names present in the findings, sorted alphabetically. */
function detectorNames(findings) {
  const names = new Set(findings.map((finding) => detectorLabel(finding)));
  return Array.from(names).sort((a, b) => a.localeCompare(b));
}

/** Returns true when the lower-cased query occurs in the finding's file, repository key or detector. */
function matchesQuery(finding, scansById, query) {
  if (query === "") {
    return true;
  }
  const fields = [finding?.file ?? "", repoKey(finding, scansById), detectorLabel(finding)];
  return fields.some((field) => String(field).toLowerCase().includes(query));
}

/** Returns true when the finding passes the detector-type and verification-status selections. */
function matchesSelections(finding, statusFilter, typeFilter) {
  if (typeFilter !== ALL_TYPES && detectorLabel(finding) !== typeFilter) {
    return false;
  }
  if (statusFilter === "verified") {
    return finding?.verified === true;
  }
  if (statusFilter === "unverified") {
    return finding?.verified === false;
  }
  return true;
}

/** Renders one finding row: status, secret type, repo, location, date, assignee and triage actions. */
function TriageRow({ finding, scansById, entry, onTriage, onSelectFinding }) {
  const verified = finding.verified === true;
  const triageLabel = TRIAGE_LABELS[entry?.state];
  const commit = shortCommit(finding.commit_hash);
  const openFinding = () => onSelectFinding(finding.id);

  return (
    <tr className={triageLabel === undefined ? "triage-row" : "triage-row triage-row--muted"}>
      <td>
        <span className={verified ? "badge badge--verified" : "badge badge--unverified"}>
          {verified ? "Verified" : "Unverified"}
        </span>
        {triageLabel === undefined ? null : (
          <span className="triage-status-secondary">{triageLabel}</span>
        )}
      </td>
      <td>
        <button type="button" className="triage-open" onClick={openFinding}>
          <span className="triage-primary">{detectorLabel(finding)}</span>
          <span className="triage-redacted">{redactedLabel(finding)}</span>
        </button>
      </td>
      <td className="triage-repo">{shortRepo(repoKey(finding, scansById))}</td>
      <td>
        <button type="button" className="triage-open" onClick={openFinding}>
          <span className="triage-primary">{fileLabel(finding)}</span>
          <span className="triage-secondary">
            {commit === PLACEHOLDER ? PLACEHOLDER : `commit ${commit}`}
          </span>
        </button>
      </td>
      <td>
        <span className="triage-primary">{formatDay(finding.created_at)}</span>
      </td>
      <td>
        <select
          className="select"
          aria-label="Assignee"
          value={entry?.assignee ?? DEFAULT_ASSIGNEE}
          onChange={(event) => onTriage(finding.id, { assignee: event.target.value })}
        >
          {ASSIGNEES.map((assignee) => (
            <option key={assignee} value={assignee}>
              {assignee}
            </option>
          ))}
        </select>
      </td>
      <td>
        <div className="triage-actions">
          <button
            type="button"
            className="btn"
            onClick={() => onTriage(finding.id, { state: "resolved" })}
          >
            Resolve
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => onTriage(finding.id, { state: "ignored" })}
          >
            Ignore
          </button>
        </div>
      </td>
    </tr>
  );
}

/** Engineering Triage screen: filters {findings} with {scansById}, displays {triage} and reports actions through {onTriage} and row selection through {onSelectFinding}. */
export function EngineeringTriage({ findings, scansById, triage, onTriage, onSelectFinding }) {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState(ALL_TYPES);

  const rows = useMemo(() => (Array.isArray(findings) ? findings : []), [findings]);
  const detectors = useMemo(() => detectorNames(rows), [rows]);
  const selectedType =
    typeFilter === ALL_TYPES || detectors.includes(typeFilter) ? typeFilter : ALL_TYPES;
  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return rows.filter(
      (finding) =>
        matchesSelections(finding, statusFilter, selectedType) &&
        matchesQuery(finding, scansById, needle),
    );
  }, [rows, query, statusFilter, selectedType, scansById]);

  return (
    <section className="triage-screen">
      <div className="triage-toolbar">
        <input
          type="text"
          className="input triage-search"
          aria-label="Search findings"
          placeholder="Search file path, repo, secret type..."
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <div className="triage-segment" role="group" aria-label="Verification status filter">
          {STATUS_FILTERS.map((filter) => (
            <button
              key={filter.value}
              type="button"
              className={
                statusFilter === filter.value
                  ? "triage-segment-btn triage-segment-btn--active"
                  : "triage-segment-btn"
              }
              aria-pressed={statusFilter === filter.value}
              onClick={() => setStatusFilter(filter.value)}
            >
              {filter.label}
            </button>
          ))}
        </div>
        <select
          className="select"
          aria-label="Secret type filter"
          value={selectedType}
          onChange={(event) => setTypeFilter(event.target.value)}
        >
          <option value={ALL_TYPES}>All types</option>
          {detectors.map((detector) => (
            <option key={detector} value={detector}>
              {detector}
            </option>
          ))}
        </select>
        <p className="triage-count">
          {visible.length} findings
          <span className="triage-note">· triage state is session-only</span>
        </p>
      </div>

      <div className="card triage-table-card">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">STATUS</th>
              <th scope="col">SECRET TYPE</th>
              <th scope="col">REPO</th>
              <th scope="col">FILE</th>
              <th scope="col">DETECTED</th>
              <th scope="col">ASSIGNEE</th>
              <th scope="col">ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 ? (
              <tr>
                <td className="triage-empty" colSpan={7}>
                  {rows.length === 0
                    ? "No findings yet. Start a scan from the sidebar."
                    : "No findings match the current filters."}
                </td>
              </tr>
            ) : (
              visible.map((finding) => (
                <TriageRow
                  key={finding.id}
                  finding={finding}
                  scansById={scansById}
                  entry={triage?.[finding.id]}
                  onTriage={onTriage}
                  onSelectFinding={onSelectFinding}
                />
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default EngineeringTriage;
