import { useEffect, useState } from "react";

import { getScanFindings } from "../api.js";
import {
  detectorLabel,
  fileLabel,
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

/** Renders one uppercase-labelled value of the meta grid. */
function MetaField({ label, value }) {
  return (
    <div>
      <span className="detail-meta-label">{label}</span>
      <p className="detail-meta-value">{value}</p>
    </div>
  );
}

/** One finding in full, from {finding, scansById, triage, onTriage, onBack}, with its scan's sibling count. */
export function FindingDetail({ finding, scansById, triage, onTriage, onBack }) {
  const scanId = finding?.scan_id;
  const [siblings, setSiblings] = useState([]);
  const [siblingsFailed, setSiblingsFailed] = useState(false);

  useEffect(() => {
    setSiblings([]);
    setSiblingsFailed(false);

    if (scanId === null || scanId === undefined) {
      return undefined;
    }

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
  const repo = shortRepo(repoKey(finding, scansById));
  const footerCount = siblingsFailed
    ? SIBLINGS_UNAVAILABLE
    : `${countSiblings(siblings, finding, scansById)} other finding(s) in ${repo}.`;

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
          <span className={verified ? "badge badge--verified" : "badge badge--unverified"}>
            {verified ? "Verified" : "Unverified"}
          </span>
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
