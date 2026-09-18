/** Native fetch wrappers for the four results-pipeline routes. */

const FALLBACK_DETAIL = "request failed";
const DETAIL_SEPARATOR = "; ";

/** Returns an error detail as one line: a string verbatim, a validation array as its messages, else JSON. */
function detailLine(detail) {
  if (typeof detail === "string") {
    return detail.trim();
  }
  if (Array.isArray(detail)) {
    return detail
      .map((item) => (typeof item === "string" ? item : item?.msg))
      .filter((message) => typeof message === "string" && message.trim() !== "")
      .map((message) => message.trim())
      .join(DETAIL_SEPARATOR);
  }
  if (detail === null || detail === undefined) {
    return "";
  }
  try {
    return JSON.stringify(detail);
  } catch {
    return "";
  }
}

/** Returns a failed response's detail text, falling back to its status text. */
async function failureDetail(response) {
  let detail = "";
  try {
    const body = await response.json();
    detail = detailLine(body?.detail);
  } catch {
    detail = "";
  }
  if (detail !== "") {
    return detail;
  }
  const statusText =
    typeof response.statusText === "string" ? response.statusText.trim() : "";
  return statusText !== "" ? statusText : FALLBACK_DETAIL;
}

/** Returns the parsed JSON body of a request, throwing "<status> <detail>" when the response is not OK. */
async function request(path, init) {
  const response = await fetch(path, init);
  if (!response.ok) {
    throw new Error(`${response.status} ${await failureDetail(response)}`);
  }
  return await response.json();
}

/** POSTs target and source to /api/scans and returns the new running scan object. */
export async function startScan(target, source = "git") {
  return request("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, source }),
  });
}

/** GETs /api/scans and returns every scan object with its finding_count, newest id first. */
export async function listScans() {
  return request("/api/scans");
}

/** GETs /api/scans/{scanId}/findings and returns that scan's finding objects, newest id first. */
export async function getScanFindings(scanId) {
  return request(`/api/scans/${scanId}/findings`);
}

/** GETs /api/findings and returns every finding object across all scans, newest id first. */
export async function listFindings() {
  return request("/api/findings");
}
