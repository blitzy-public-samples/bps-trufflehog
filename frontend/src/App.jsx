import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { listFindings, listScans, startScan } from "./api.js";
import { formatLastScan } from "./format.js";
import EngineeringTriage from "./components/EngineeringTriage.jsx";
import ExecutiveDashboard from "./components/ExecutiveDashboard.jsx";
import FindingDetail from "./components/FindingDetail.jsx";
import RepoLeaderboard from "./components/RepoLeaderboard.jsx";

const POLL_INTERVAL_MS = 2000;
const RUNNING = "running";
const DEFAULT_SCREEN = "summary";
const DETAIL_SCREEN = "detail";
const TRIAGE_SCREEN = "triage";
const LEADERBOARD_SCREEN = "leaderboard";
const NO_SCANS = "No scans yet";
const LAST_SCAN_PREFIX = "Last scan: ";
const TARGET_PLACEHOLDER = "https://… or file:///…";
const SOURCES = ["git", "filesystem"];
const FORM_TITLE_ID = "shell-scan-title";
const SOURCE_ID = "shell-scan-source";
const TARGET_ID = "shell-scan-target";

const SCREENS = [
  { key: DEFAULT_SCREEN, label: "Executive Summary" },
  { key: TRIAGE_SCREEN, label: "Engineering Triage" },
  { key: LEADERBOARD_SCREEN, label: "Repo Leaderboard" },
  { key: DETAIL_SCREEN, label: "Finding Detail" },
];

/** Returns the nav and header label for a screen key, falling back to the default screen's label. */
function screenLabel(screen) {
  return SCREENS.find((entry) => entry.key === screen)?.label ?? SCREENS[0].label;
}

/** Returns a caught value as a display string, preferring an Error's message. */
function errorText(caught) {
  return caught instanceof Error ? caught.message : String(caught);
}

/** Returns the newest parseable started_at across the scans, or null when there is none. */
function newestStartedAt(scans) {
  let newest = null;
  let newestTime = Number.NEGATIVE_INFINITY;
  for (const scan of scans) {
    const started = scan?.started_at;
    if (typeof started !== "string" || started === "") {
      continue;
    }
    const time = Date.parse(started);
    if (Number.isNaN(time) || time <= newestTime) {
      continue;
    }
    newest = started;
    newestTime = time;
  }
  return newest;
}

/** Returns {count, findings}: how many scans are running and how many findings they have stored. */
function runningSummary(scans) {
  let count = 0;
  let findings = 0;
  for (const scan of scans) {
    if (scan?.status !== RUNNING) {
      continue;
    }
    count += 1;
    const stored = scan?.finding_count;
    if (Number.isFinite(stored)) {
      findings += stored;
    }
  }
  return { count, findings };
}

/** Returns a started scan as a list row with a running status fallback, or null when the body carries no finite id. */
function startedRow(started) {
  if (started === null || typeof started !== "object" || Array.isArray(started)) {
    return null;
  }
  if (!Number.isFinite(started.id)) {
    return null;
  }
  return { ...started, status: typeof started.status === "string" ? started.status : RUNNING };
}

/** Returns the server scans with the locally started rows in front, taking precedence over the same id. */
function mergeScans(serverScans, pendingScans) {
  if (pendingScans.length === 0) {
    return serverScans;
  }
  const started = new Set(pendingScans.map((scan) => scan.id));
  return [...pendingScans, ...serverScans.filter((scan) => !started.has(scan?.id))];
}

/** Sidebar form that starts a scan from {running, onStarted} and reports its own submit failures. */
function NewScanForm({ running, onStarted }) {
  const [source, setSource] = useState(SOURCES[0]);
  const [target, setTarget] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState(null);

  const trimmed = target.trim();

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (submitting || trimmed === "") {
      return;
    }
    setSubmitting(true);
    try {
      const started = await startScan(trimmed, source);
      setTarget("");
      setFormError(null);
      await onStarted(started);
    } catch (caught) {
      setFormError(errorText(caught));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form className="shell-scan-form" aria-labelledby={FORM_TITLE_ID} onSubmit={handleSubmit}>
      <p className="label" id={FORM_TITLE_ID}>
        New scan
      </p>
      <label className="label" htmlFor={SOURCE_ID}>
        Source
      </label>
      <select
        className="select"
        id={SOURCE_ID}
        value={source}
        onChange={(event) => setSource(event.target.value)}
      >
        {SOURCES.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
      <label className="label" htmlFor={TARGET_ID}>
        Target
      </label>
      <input
        className="input mono"
        id={TARGET_ID}
        type="text"
        placeholder={TARGET_PLACEHOLDER}
        value={target}
        onChange={(event) => setTarget(event.target.value)}
      />
      <button className="btn" type="submit" disabled={submitting || trimmed === ""}>
        Scan
      </button>
      {running.count === 0 ? null : (
        <p className="shell-scan-status">
          {`Scanning ${running.count} target(s) · ${running.findings} findings so far`}
        </p>
      )}
      {formError === null ? null : <p className="shell-error">{formError}</p>}
    </form>
  );
}

/** Sidebar: wordmark, screen nav, the New scan form and the last refresh error. */
function Sidebar({ screen, running, error, onNavigate, onStarted }) {
  return (
    <aside className="shell-sidebar">
      <div className="shell-wordmark">TRUFFLEHOG</div>
      <p className="shell-subtitle">Secret Detection Results</p>
      <nav className="shell-nav" aria-label="Screens">
        {SCREENS.map((entry) => {
          const active = entry.key === screen;
          return (
            <button
              key={entry.key}
              type="button"
              className={active ? "shell-nav-item shell-nav-item--active" : "shell-nav-item"}
              aria-current={active ? "page" : undefined}
              onClick={() => onNavigate(entry.key)}
            >
              {entry.label}
            </button>
          );
        })}
      </nav>
      <NewScanForm running={running} onStarted={onStarted} />
      {error === null ? null : <p className="shell-error">{error}</p>}
    </aside>
  );
}

/** Header: the current screen's title and the newest scan's UTC timestamp. */
function Header({ screen, newestScanAt }) {
  return (
    <header className="shell-header">
      <h1 className="shell-title">{screenLabel(screen)}</h1>
      <p className="shell-lastscan mono">
        {newestScanAt === null ? NO_SCANS : `${LAST_SCAN_PREFIX}${formatLastScan(newestScanAt)}`}
      </p>
    </header>
  );
}

/** Application shell owning navigation, the loaded scans and findings, polling and session triage state. */
export default function App() {
  const [screen, setScreen] = useState(DEFAULT_SCREEN);
  const [selectedFindingId, setSelectedFindingId] = useState(null);
  const [serverScans, setServerScans] = useState([]);
  const [pendingScans, setPendingScans] = useState([]);
  const [awaitingStart, setAwaitingStart] = useState(false);
  const [findings, setFindings] = useState([]);
  const [triage, setTriageState] = useState({});
  const [error, setError] = useState(null);
  const startSeq = useRef(0);

  const load = useCallback(async () => {
    const seq = startSeq.current;
    try {
      const [nextScans, nextFindings] = await Promise.all([listScans(), listFindings()]);
      const nextRows = Array.isArray(nextScans) ? nextScans : [];
      const reported = new Set(nextRows.map((scan) => scan?.id));
      setServerScans(nextRows);
      setPendingScans((prev) => prev.filter((scan) => !reported.has(scan.id)));
      setFindings(Array.isArray(nextFindings) ? nextFindings : []);
      if (seq === startSeq.current) {
        setAwaitingStart(false);
      }
      setError(null);
    } catch (caught) {
      setError(errorText(caught));
    }
  }, []);

  /** Upserts a just-started scan from a 202 body, marks a start as awaited and returns the refresh promise. */
  const startedScan = useCallback(
    (started) => {
      const row = startedRow(started);
      startSeq.current += 1;
      setAwaitingStart(true);
      if (row !== null) {
        setPendingScans((prev) => [row, ...prev.filter((scan) => scan.id !== row.id)]);
      }
      return load();
    },
    [load],
  );

  const scans = useMemo(() => mergeScans(serverScans, pendingScans), [serverScans, pendingScans]);

  const anyRunning = scans.some((scan) => scan?.status === RUNNING);
  const polling = anyRunning || awaitingStart;
  const wasPolling = useRef(false);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!polling) {
      return undefined;
    }
    const timer = setInterval(load, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [polling, load]);

  useEffect(() => {
    if (wasPolling.current && !polling) {
      load();
    }
    wasPolling.current = polling;
  }, [polling, load]);

  const navigate = useCallback((next) => {
    setScreen(next);
  }, []);

  const selectFinding = useCallback((id) => {
    setSelectedFindingId(id);
    setScreen(DETAIL_SCREEN);
  }, []);

  const setTriage = useCallback((id, patch) => {
    setTriageState((prev) => ({ ...prev, [id]: { ...prev[id], ...patch } }));
  }, []);

  const backToTriage = useCallback(() => {
    navigate(TRIAGE_SCREEN);
  }, [navigate]);

  const scansById = useMemo(() => {
    const index = {};
    for (const scan of scans) {
      if (scan?.id !== undefined && scan?.id !== null) {
        index[scan.id] = scan;
      }
    }
    return index;
  }, [scans]);

  const selectedFinding = useMemo(() => {
    if (selectedFindingId === null) {
      return undefined;
    }
    return findings.find((finding) => finding?.id === selectedFindingId);
  }, [findings, selectedFindingId]);

  let content = null;
  if (screen === TRIAGE_SCREEN) {
    content = (
      <EngineeringTriage
        findings={findings}
        scansById={scansById}
        triage={triage}
        onTriage={setTriage}
        onSelectFinding={selectFinding}
      />
    );
  } else if (screen === LEADERBOARD_SCREEN) {
    content = <RepoLeaderboard findings={findings} scansById={scansById} />;
  } else if (screen === DETAIL_SCREEN) {
    content = (
      <FindingDetail
        finding={selectedFinding}
        scansById={scansById}
        triage={triage}
        onTriage={setTriage}
        onBack={backToTriage}
      />
    );
  } else {
    content = (
      <ExecutiveDashboard
        scans={scans}
        findings={findings}
        scansById={scansById}
        triage={triage}
        onNavigate={navigate}
      />
    );
  }

  return (
    <div className="shell">
      <Sidebar
        screen={screen}
        running={runningSummary(scans)}
        error={error}
        onNavigate={navigate}
        onStarted={startedScan}
      />
      <main className="shell-main">
        <Header screen={screen} newestScanAt={newestStartedAt(scans)} />
        <div className="shell-content">{content}</div>
      </main>
    </div>
  );
}
