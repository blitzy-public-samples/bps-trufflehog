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
const LOAD_ERROR_PREFIX = "Could not load results: ";
const SUBMIT_ERROR_PREFIX = "Could not start scan: ";
const TARGET_PLACEHOLDER = "https://… or file:///…";
const SOURCES = ["git", "filesystem"];
const FORM_TITLE_ID = "shell-scan-title";
const SOURCE_ID = "shell-scan-source";
const TARGET_ID = "shell-scan-target";
const TARGET_ERROR_ID = "shell-scan-target-error";
const MAIN_ID = "main";
const COMPLETED = "completed";
const FAILED = "failed";

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

/** Returns the scan with the newest parseable started_at, or null when there is none. */
function newestScan(scans) {
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
    newest = scan;
    newestTime = time;
  }
  return newest;
}

/** Returns the finished outcome of the newest scan as a display line, or null while none has finished. */
function scanOutcome(scan) {
  if (scan?.status === FAILED) {
    return Number.isFinite(scan.exit_code)
      ? `Last scan failed · exit code ${scan.exit_code}`
      : "Last scan failed · no exit code";
  }
  if (scan?.status === COMPLETED) {
    const stored = Number.isFinite(scan.finding_count) ? scan.finding_count : 0;
    return `Last scan completed · ${stored} finding(s)`;
  }
  return null;
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

/** Returns true when two scan rows carry the same keys and the same primitive values. */
function sameScan(previous, next) {
  const keys = Object.keys(next);
  if (keys.length !== Object.keys(previous).length) {
    return false;
  }
  return keys.every((key) => previous[key] === next[key]);
}

/** Returns true for two findings with the same id; finding rows are inserted once and never updated. */
function sameFinding(previous, next) {
  return previous.id === next.id;
}

/** Returns the fetched rows with every unchanged row replaced by the object already in state, or the
 * previous array itself when the fetch reported no change at all. */
function mergeById(previous, next, isEqual) {
  const indexed = new Map();
  for (const row of previous) {
    if (row?.id !== undefined && row?.id !== null) {
      indexed.set(row.id, row);
    }
  }
  let reused = 0;
  const merged = next.map((row) => {
    const existing = indexed.get(row?.id);
    if (existing !== undefined && isEqual(existing, row)) {
      reused += 1;
      return existing;
    }
    return row;
  });
  return reused === merged.length && merged.length === previous.length ? previous : merged;
}

/** Returns the server scans with the locally started rows in front, taking precedence over the same id. */
function mergeScans(serverScans, pendingScans) {
  if (pendingScans.length === 0) {
    return serverScans;
  }
  const started = new Set(pendingScans.map((scan) => scan.id));
  return [...pendingScans, ...serverScans.filter((scan) => !started.has(scan?.id))];
}

/** Sidebar form that starts a scan from {running, outcome, onStarted} and reports its own submit failures. */
function NewScanForm({ running, outcome, onStarted }) {
  const [source, setSource] = useState(SOURCES[0]);
  const [target, setTarget] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState(null);

  const trimmed = target.trim();

  const handleTargetChange = (event) => {
    setTarget(event.target.value);
    setFormError(null);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (submitting || trimmed === "") {
      return;
    }
    setSubmitting(true);
    setFormError(null);
    try {
      const started = await startScan(trimmed, source);
      setTarget("");
      await onStarted(started);
    } catch (caught) {
      setFormError(`${SUBMIT_ERROR_PREFIX}${errorText(caught)}`);
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
        aria-invalid={formError === null ? undefined : true}
        aria-describedby={formError === null ? undefined : TARGET_ERROR_ID}
        onChange={handleTargetChange}
      />
      <button className="btn" type="submit" disabled={submitting || trimmed === ""}>
        Scan
      </button>
      {running.count === 0 ? null : (
        <p className="shell-scan-status">
          {`Scanning ${running.count} target(s) · ${running.findings} findings so far`}
        </p>
      )}
      {running.count > 0 || outcome === null ? null : (
        <p className="shell-scan-outcome" role="status">
          {outcome}
        </p>
      )}
      {formError === null ? null : (
        <p className="shell-error" id={TARGET_ERROR_ID} role="alert">
          {formError}
        </p>
      )}
    </form>
  );
}

/** Sidebar: wordmark, screen nav, the New scan form and the last refresh error. */
function Sidebar({ screen, running, outcome, error, onNavigate, onStarted }) {
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
      <NewScanForm running={running} outcome={outcome} onStarted={onStarted} />
      {error === null ? null : (
        <p className="shell-error" role="alert">
          {`${LOAD_ERROR_PREFIX}${error}`}
        </p>
      )}
    </aside>
  );
}

/** Header: the current screen's title, focusable through {titleRef}, and the newest scan's UTC timestamp. */
function Header({ screen, newestScanAt, titleRef }) {
  return (
    <header className="shell-header">
      <div className="shell-header-inner">
        <h1 className="shell-title" ref={titleRef} tabIndex={-1}>
          {screenLabel(screen)}
        </h1>
        <p className="shell-lastscan mono">
          {newestScanAt === null ? NO_SCANS : `${LAST_SCAN_PREFIX}${formatLastScan(newestScanAt)}`}
        </p>
      </div>
    </header>
  );
}

/** Application shell owning navigation, the loaded scans and findings, polling and session triage state. */
export default function App() {
  const [screen, setScreen] = useState(DEFAULT_SCREEN);
  const [selectedFindingId, setSelectedFindingId] = useState(null);
  const titleRef = useRef(null);
  const focusedScreen = useRef(DEFAULT_SCREEN);
  const [serverScans, setServerScans] = useState([]);
  const [pendingScans, setPendingScans] = useState([]);
  const [awaitingStart, setAwaitingStart] = useState(false);
  const [findings, setFindings] = useState([]);
  const [triage, setTriageState] = useState({});
  const [error, setError] = useState(null);
  const [loaded, setLoaded] = useState(false);
  const startSeq = useRef(0);

  const load = useCallback(async () => {
    const seq = startSeq.current;
    try {
      const [nextScans, nextFindings] = await Promise.all([listScans(), listFindings()]);
      const nextScanRows = Array.isArray(nextScans) ? nextScans : [];
      const nextFindingRows = Array.isArray(nextFindings) ? nextFindings : [];
      const reported = new Set(nextScanRows.map((scan) => scan?.id));
      setServerScans((prev) => mergeById(prev, nextScanRows, sameScan));
      setPendingScans((prev) => {
        const kept = prev.filter((scan) => !reported.has(scan.id));
        return kept.length === prev.length ? prev : kept;
      });
      setFindings((prev) => mergeById(prev, nextFindingRows, sameFinding));
      if (seq === startSeq.current) {
        setAwaitingStart(false);
      }
      setError(null);
    } catch (caught) {
      setError(errorText(caught));
    } finally {
      setLoaded(true);
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

  useEffect(() => {
    if (focusedScreen.current === screen) {
      return;
    }
    focusedScreen.current = screen;
    titleRef.current?.focus();
  }, [screen]);

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
        isLoading={!loaded}
        onTriage={setTriage}
        onSelectFinding={selectFinding}
      />
    );
  } else if (screen === LEADERBOARD_SCREEN) {
    content = <RepoLeaderboard findings={findings} scansById={scansById} isLoading={!loaded} />;
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

  const newest = newestScan(scans);

  return (
    <div className="shell">
      <a className="shell-skip-link" href={`#${MAIN_ID}`}>
        Skip to content
      </a>
      <Sidebar
        screen={screen}
        running={runningSummary(scans)}
        outcome={scanOutcome(newest)}
        error={error}
        onNavigate={navigate}
        onStarted={startedScan}
      />
      <div className="shell-column">
        <Header
          screen={screen}
          newestScanAt={newest === null ? null : newest.started_at}
          titleRef={titleRef}
        />
        <main className="shell-main" id={MAIN_ID} tabIndex={-1}>
          <div className="shell-content">{content}</div>
        </main>
      </div>
    </div>
  );
}
