// Talking to the local recorder service on 127.0.0.1. The pairing token lives in
// chrome.storage.local and is sent only to that loopback address.

export const DEFAULT_PORT = 8770;

export async function settings() {
  const { port = DEFAULT_PORT, token = "" } = await chrome.storage.local.get(["port", "token"]);
  return { port, token };
}

export async function api(path, body, { raw = false } = {}) {
  const { port, token } = await settings();
  if (!token) throw new Error("Pair the extension with the recorder first.");
  let response;
  try {
    response = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { "X-HashCam-Token": token, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (error) {
    // The browser reports a blocked or an unreachable request only as "Failed to fetch" (a blocked
    // one is logged as a CORS error). Say which it is, and what to do.
    const allowed = await chrome.permissions.contains({ origins: ["http://127.0.0.1/*"] }).catch(() => true);
    throw new Error(allowed
      ? `HashCam cannot reach the recorder on 127.0.0.1:${port}. Is it running? (Double-click HashCam.bat.)`
      : "The browser has taken away HashCam's access to the recorder on 127.0.0.1. In the browser's extension settings, remove HashCam and load it again.");
  }
  if (raw && response.ok) return response;
  const answer = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(answer.error || `recorder answered ${response.status}`);
  return answer;
}

// The passkey challenge for one decision is derived, not fetched: it names the decision and the
// digest of the exact text the person was shown (services/recorder/passkey.py).
export function approvalChallenge(decision, summaryDigest) {
  return b64urlEncode(new TextEncoder().encode(`hashcam-approval:${decision}:${summaryDigest}`));
}

export function b64urlEncode(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text) {
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

export function hostPatterns(hosts) {
  // A passport host "shop.test" or "*.shop.test" -> the origins the extension may watch.
  const out = new Set();
  for (const h of hosts) {
    for (const scheme of ["https", "http"]) out.add(`${scheme}://${h}/*`);
  }
  return [...out];
}
