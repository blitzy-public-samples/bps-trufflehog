import { aggregateByRepo, riskTier } from "../format.js";
import "./RepoLeaderboard.css";

const OWNER_PLACEHOLDER = "—";
const COLUMN_COUNT = 7;
const EMPTY_MESSAGE = "No findings yet. Start a scan to populate the leaderboard.";

const RISK_BADGE = {
  High: "badge--verified",
  Medium: "badge--unverified",
  Low: "badge--low",
};

/** Returns the badge modifier class for a risk tier. */
function riskBadgeClass(tier) {
  return RISK_BADGE[tier] ?? RISK_BADGE.Low;
}

/** Repositories ranked by finding total, from {findings, scansById}, with a derived risk badge. */
export function RepoLeaderboard({ findings, scansById }) {
  const rows = aggregateByRepo(findings, scansById);

  return (
    <section className="card board-table-card" aria-label="Repository leaderboard">
      <table className="table">
        <thead>
          <tr>
            <th scope="col">RANK</th>
            <th scope="col">REPO</th>
            <th scope="col">OWNER</th>
            <th className="board-num" scope="col">
              TOTAL
            </th>
            <th className="board-num" scope="col">
              VERIFIED
            </th>
            <th className="board-num" scope="col">
              UNVERIFIED
            </th>
            <th scope="col">RISK</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td className="board-empty" colSpan={COLUMN_COUNT}>
                {EMPTY_MESSAGE}
              </td>
            </tr>
          ) : (
            rows.map((row, index) => {
              const tier = riskTier(row.verified);
              return (
                <tr className="board-row" key={row.key}>
                  <td className="board-rank">{index + 1}</td>
                  <td className="board-repo">{row.repo}</td>
                  <td className="board-owner">{OWNER_PLACEHOLDER}</td>
                  <td className="board-num">{row.total}</td>
                  <td className="board-num">{row.verified}</td>
                  <td className="board-num">{row.unverified}</td>
                  <td className="board-risk">
                    <span className={`badge ${riskBadgeClass(tier)}`}>{tier}</span>
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </section>
  );
}

export default RepoLeaderboard;
