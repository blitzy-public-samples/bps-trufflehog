import { useEffect, useState } from "react";

import { getScanFindings } from "../api.js";
import {
  detectorLabel,
  fileLabel,
  formatCount,
  formatDay,
  redactedLabel,
  remediationText,
  repoKey,
  shortCommit,
  shortRepo,
} from "../format.js";

import "./FindingDetail.css";

const PLACEHOLDER = "—";
const DEFAULT_ASSIGNEE = "Unassigned";
const ASSIGNEES = [DEFAULT_ASSIGNEE, "Me"];
const TRIAGE_LABELS = { resolved: "Resolved", ignored: "Ignored" };
const EMPTY_MESSAGE = "Select a finding from Engineering Triage.";
const BACK_LABEL = "← Back to Engineering Triage";
const SESSION_NOTE = "Triage actions are session-only.";
const SIBLINGS_UNAVAILABLE = "Sibling count unavailable";
const TITLE_ID = "detail-finding-title";
const ASSIGNEE_ID = "detail-assignee-select";

/** Returns the number of the scan's other findings that share the selected finding's repository key. */
function countSiblings(siblings, finding, scansById) {
  const key = repoKey(finding, scansById);
  return siblings.filter(
    (sibling) => sibling?.id !== finding.id && repoKey(sibling, scansById) === key,
  ).length;
}

/** Returns the footer sentence for the loading, failed and loaded sibling states. */
function siblingSentence(siblings, siblingsFailed, finding, scansById, repo) {
  if (siblingsFailed) {
    return SIBLINGS_UNAVAILABLE;
  }
  if (siblings === null) {
    return `Counting other findings in ${repo}…`;
  }
  return `${formatCount(countSiblings(siblings, finding, scansById))} other finding(s) in ${repo}.`;
}

/** Renders one uppercase-labelled value of the meta grid, with the full value as its tooltip. */
function MetaField({ label, value }) {
  return (
    <div>
      <span className="detail-meta-label">{label}</span>
      <p className="detail-meta-value" title={value === PLACEHOLDER ? undefined : value}>
        {value}
      </p>
    </div>
  );
}

/** One finding in full, from {finding, scansById, triage, onTriage, onBack}, with its scan's sibling count. */
export function FindingDetail({ finding, scansById, triage, onTriage, onBack }) {
  const scanId = finding?.scan_id;
  const [siblings, setSiblings] = useState(null);
  const [siblingsFailed, setSiblingsFailed] = useState(false);

  useEffect(() => {
    setSiblingsFailed(false);

    if (scanId === null || scanId === undefined) {
      setSiblings([]);
      return undefined;
    }

    setSiblings(null);

    let cancelled = false;

    const load = async () => {
      try {
        const rows = await getScanFindings(scanId);
        if (!cancelled) {
          setSiblings(Array.isArray(rows) ? rows : []);
          setSiblingsFailed(false);
        }
      } catch {
        if (!cancelled) {
          setSiblings([]);
          setSiblingsFailed(true);
        }
      }
    };

    load();

    return () => {
      cancelled = true;
    };
  }, [scanId]);

  if (finding === null || finding === undefined) {
    return <p className="detail-empty">{EMPTY_MESSAGE}</p>;
  }

  const verified = finding.verified === true;
  const assignee = triage?.[finding.id]?.assignee ?? DEFAULT_ASSIGNEE;
  const triageState = triage?.[finding.id]?.state;
  const triageLabel = TRIAGE_LABELS[triageState];
  const repo = shortRepo(repoKey(finding, scansById));
  const footerCount = siblingSentence(siblings, siblingsFailed, finding, scansById, repo);

  return (
    <>
      <button type="button" className="detail-back" onClick={() => onBack()}>
        {BACK_LABEL}
      </button>

      <section className="card detail-card" aria-labelledby={TITLE_ID}>
        <div className="detail-head">
          <div>
            <h2 className="detail-title" id={TITLE_ID}>
              {detectorLabel(finding)}
            </h2>
            <p className="detail-subtitle">{repo}</p>
          </div>
          <div className="detail-status">
            {triageLabel === undefined ? null : (
              <span className="detail-state">{triageLabel}</span>
            )}
            <span className={verified ? "badge badge--verified" : "badge badge--unverified"}>
              {verified ? "Verified" : "Unverified"}
            </span>
          </div>
        </div>

        <div className="detail-meta">
          <MetaField label="FILE" value={fileLabel(finding)} />
          <MetaField label="COMMIT" value={shortCommit(finding.commit_hash)} />
          <MetaField label="DETECTED" value={formatDay(finding.created_at)} />
          <MetaField label="DETECTOR" value={detectorLabel(finding)} />
          <MetaField label="TEAM" value={PLACEHOLDER} />
          <MetaField label="ASSIGNEE" value={assignee} />
        </div>

        <span className="detail-meta-label">SNIPPET</span>
        <pre className="detail-snippet">
          <code>{redactedLabel(finding)}</code>
        </pre>

        <span className="detail-meta-label">REMEDIATION</span>
        <p className="detail-remediation">{remediationText(finding)}</p>

        <div className="detail-actions">
          <div className="detail-actions-group">
            <button
              type="button"
              className="btn detail-action"
              aria-pressed={triageState === "resolved"}
              onClick={() => onTriage(finding.id, { state: "resolved" })}
            >
              Resolve
            </button>
            <button
              type="button"
              className="btn detail-action"
              aria-pressed={triageState === "ignored"}
              onClick={() => onTriage(finding.id, { state: "ignored" })}
            >
              Ignore
            </button>
          </div>
          <label className="detail-assignee" htmlFor={ASSIGNEE_ID}>
            Assignee
            <select
              className="select"
              id={ASSIGNEE_ID}
              name="assignee"
              value={assignee}
              onChange={(event) => onTriage(finding.id, { assignee: event.target.value })}
            >
              {ASSIGNEES.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
        </div>
      </section>

      <p className="detail-footer">
        {footerCount}
        <span className="detail-footer-note">{SESSION_NOTE}</span>
      </p>
    </>
  );
}

export default FindingDetail;
