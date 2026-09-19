import {
  memo,
  useDeferredValue,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  detectorLabel,
  fileLabel,
  formatCount,
  formatDay,
  redactedLabel,
  repoKey,
  shortCommit,
  shortRepo,
} from "../format.js";

import "./EngineeringTriage.css";

const ALL_TYPES = "all";
const PLACEHOLDER = "—";
const ANCHOR_EPSILON_PX = 1;
const LOADING_MESSAGE = "Loading findings…";
const EMPTY_MESSAGE = "No findings yet. Start a scan from the sidebar.";
const NO_MATCH_MESSAGE = "No findings match the current filters.";
const SEARCH_ID = "triage-search";
const TYPE_ID = "triage-type";
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

/** Returns the search needle: lower-cased and stripped of surrounding whitespace, so a whitespace-only query is empty and matches every row. */
function normalizeQuery(query) {
  return String(query ?? "")
    .trim()
    .toLowerCase();
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

/** Returns the message for an empty table body from {isLoading} and the unfiltered row count. */
function emptyMessage(isLoading, total) {
  if (isLoading === true) {
    return LOADING_MESSAGE;
  }
  return total === 0 ? EMPTY_MESSAGE : NO_MATCH_MESSAGE;
}

/** Returns the index of the first row reaching below the viewport top, or -1 when there is none. */
function firstVisibleRowIndex(rows) {
  let low = 0;
  let high = rows.length - 1;
  let found = -1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    if (rows[middle].getBoundingClientRect().bottom > 0) {
      found = middle;
      high = middle - 1;
    } else {
      low = middle + 1;
    }
  }
  return found;
}

/** Returns {id, top} for the row the reader is looking at, or null while the page sits at the top. */
function captureAnchor(tbody) {
  if (tbody === null || window.scrollY <= 0) {
    return null;
  }
  const index = firstVisibleRowIndex(tbody.rows);
  if (index < 0) {
    return null;
  }
  const row = tbody.rows[index];
  const id = row.dataset.findingId;
  return id === undefined ? null : { id, top: row.getBoundingClientRect().top };
}

/** Holds the anchored row at its own screen position when a refresh of {rows} inserts newer rows above it. */
function useRowAnchor(tbodyRef, rows) {
  const anchor = useRef(null);

  useEffect(() => {
    const onScroll = () => {
      anchor.current = captureAnchor(tbodyRef.current);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, [tbodyRef]);

  useLayoutEffect(() => {
    const anchored = anchor.current;
    const tbody = tbodyRef.current;
    if (anchored === null || tbody === null) {
      return;
    }
    const row = tbody.querySelector(`[data-finding-id="${anchored.id}"]`);
    if (row === null) {
      anchor.current = null;
      return;
    }
    const delta = row.getBoundingClientRect().top - anchored.top;
    if (Math.abs(delta) >= ANCHOR_EPSILON_PX) {
      window.scrollBy(0, delta);
    }
  }, [tbodyRef, rows]);
}

/** Returns true when two row prop sets render identically, comparing the repo key the row shows
 * rather than the scan index it is derived from. */
function sameRowProps(previous, next) {
  return (
    previous.finding === next.finding &&
    previous.entry === next.entry &&
    previous.onTriage === next.onTriage &&
    previous.onSelectFinding === next.onSelectFinding &&
    repoKey(previous.finding, previous.scansById) === repoKey(next.finding, next.scansById)
  );
}

/** Returns one finding's detector, repository, location and id, naming a row's controls uniquely for assistive technology. */
function rowDescription(finding, scansById) {
  const repo = shortRepo(repoKey(finding, scansById));
  const location = fileLabel(finding);
  const place = location === PLACEHOLDER ? repo : `${repo}, ${location}`;
  return `${detectorLabel(finding)} in ${place}, id ${finding.id}`;
}

/** Renders one finding row: status, secret type, repo, location, date, assignee and triage actions. */
function TriageRowContent({ finding, scansById, entry, onTriage, onSelectFinding }) {
  const verified = finding.verified === true;
  const triageLabel = TRIAGE_LABELS[entry?.state];
  const commit = shortCommit(finding.commit_hash);
  const file = fileLabel(finding);
  const repo = shortRepo(repoKey(finding, scansById));
  const openFinding = () => onSelectFinding(finding.id);
  const rowLabel = rowDescription(finding, scansById);
  const assigneeId = `triage-assignee-${finding.id}`;

  return (
    <tr
      className={triageLabel === undefined ? "triage-row" : "triage-row triage-row--muted"}
      data-finding-id={finding.id}
    >
      <td>
        <span className={verified ? "badge badge--verified" : "badge badge--unverified"}>
          {verified ? "Verified" : "Unverified"}
        </span>
        {triageLabel === undefined ? null : (
          <span className="triage-status-secondary">{triageLabel}</span>
        )}
      </td>
      <td>
        <button
          type="button"
          className="triage-open"
          aria-label={`Open finding ${rowLabel}`}
          onClick={openFinding}
        >
          <span className="triage-primary">
            <bdi>{detectorLabel(finding)}</bdi>
          </span>
          <span className="triage-redacted">
            <bdi>{redactedLabel(finding)}</bdi>
          </span>
        </button>
      </td>
      <td className="triage-repo" title={repo === PLACEHOLDER ? undefined : repo}>
        <bdi>{repo}</bdi>
      </td>
      <td>
        <button
          type="button"
          className="triage-open"
          aria-label={`Open finding ${rowLabel}`}
          onClick={openFinding}
        >
          <span
            className="triage-primary triage-file"
            title={file === PLACEHOLDER ? undefined : file}
          >
            <bdi>{file}</bdi>
          </span>
          <span className="triage-secondary">
            {commit === PLACEHOLDER ? (
              PLACEHOLDER
            ) : (
              <>
                {"commit "}
                <bdi>{commit}</bdi>
              </>
            )}
          </span>
        </button>
      </td>
      <td>
        <span className="triage-primary">{formatDay(finding.created_at)}</span>
      </td>
      <td>
        <select
          className="select"
          id={assigneeId}
          name={assigneeId}
          aria-label={`Assignee for ${rowLabel}`}
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
            className="btn triage-action"
            aria-label={`Resolve ${rowLabel}`}
            aria-pressed={entry?.state === "resolved"}
            onClick={() => onTriage(finding.id, { state: "resolved" })}
          >
            Resolve
          </button>
          <button
            type="button"
            className="btn triage-action"
            aria-label={`Ignore ${rowLabel}`}
            aria-pressed={entry?.state === "ignored"}
            onClick={() => onTriage(finding.id, { state: "ignored" })}
          >
            Ignore
          </button>
        </div>
      </td>
    </tr>
  );
}

const TriageRow = memo(TriageRowContent, sameRowProps);

/** Engineering Triage screen: filters {findings} with {scansById}, displays {triage} and {isLoading} and reports actions through {onTriage} and row selection through {onSelectFinding}. */
export function EngineeringTriage({
  findings,
  scansById,
  triage,
  isLoading,
  onTriage,
  onSelectFinding,
}) {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState(ALL_TYPES);
  const tbodyRef = useRef(null);

  const rows = useMemo(() => (Array.isArray(findings) ? findings : []), [findings]);
  const detectors = useMemo(() => detectorNames(rows), [rows]);
  const selectedType =
    typeFilter === ALL_TYPES || detectors.includes(typeFilter) ? typeFilter : ALL_TYPES;
  const filters = useMemo(
    () => ({ query, statusFilter, typeFilter: selectedType }),
    [query, statusFilter, selectedType],
  );
  const activeFilters = useDeferredValue(filters);
  const visible = useMemo(() => {
    const needle = normalizeQuery(activeFilters.query);
    return rows.filter(
      (finding) =>
        matchesSelections(finding, activeFilters.statusFilter, activeFilters.typeFilter) &&
        matchesQuery(finding, scansById, needle),
    );
  }, [rows, activeFilters, scansById]);
  const rowElements = useMemo(
    () =>
      visible.map((finding) => (
        <TriageRow
          key={finding.id}
          finding={finding}
          scansById={scansById}
          entry={triage?.[finding.id]}
          onTriage={onTriage}
          onSelectFinding={onSelectFinding}
        />
      )),
    [visible, scansById, triage, onTriage, onSelectFinding],
  );

  useRowAnchor(tbodyRef, rows);

  return (
    <section className="triage-screen">
      <div className="triage-toolbar">
        <input
          type="text"
          className="input triage-search"
          id={SEARCH_ID}
          name={SEARCH_ID}
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
          className="select triage-type-select"
          id={TYPE_ID}
          name={TYPE_ID}
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
          {`${formatCount(visible.length)} findings`}
          <span className="triage-note">{" · triage state is session-only"}</span>
        </p>
      </div>

      <div className="card triage-table-card">
        <table className="table" aria-label="Findings triage">
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
          <tbody ref={tbodyRef}>
            {visible.length === 0 ? (
              <tr>
                <td
                  className="triage-empty"
                  colSpan={7}
                  aria-busy={isLoading === true ? "true" : undefined}
                >
                  {emptyMessage(isLoading, rows.length)}
                </td>
              </tr>
            ) : (
              rowElements
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default EngineeringTriage;
