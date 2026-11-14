# HashCam Recorder (Chrome extension)

**Status:** `TESTED`: `tests/recorder/` (21 tests). One of them loads this extension into a real
Chromium, drives a scripted agent on a local test site, approves with Chrome's own WebAuthn code
through a virtual authenticator, and checks the verifier's verdict. Not tested: a real side panel
opened from the toolbar (the test opens the panel page as a tab), a physical fingerprint reader,
and any third-party AI agent product.

A flight recorder that clips onto an AI agent working in your browser. HashCam does not run
tasks; it watches the tab another agent drives, holds risky steps for you, and seals what
happened into a signed receipt anyone can verify offline.

## What it does

| Feature | What happens |
|---|---|
| **Record** | Every page load in the agent's tab is checked against the passport, then recorded with the page text's digest and a screenshot (when the tab is visible). |
| **Gate** | Every form submission and every download waits. The side panel shows who, what and where; you approve or deny with your passkey (fingerprint, face or PIN). Only then is your approver key used to sign. Nothing answered within 2 minutes stays unsent. |
| **Passport** | Per session, a signed mandate: the sites the agent may use and when it expires. A page outside it is redirected to a "blocked" page; a submit outside it is refused without even asking. |
| **Tripwire** | The page's full text, hidden parts included, goes through the project's prompt guard. A page that tries to give the agent instructions is flagged. A drift rule flags actions on sites the task does not name. Both are advisory: they lower the trust gauge and are recorded; they never allow anything. |
| **Secret shield** | A typed password or card number becomes a salted SHA-256 commitment inside the page. The value never leaves the page; the salt is thrown away. |
| **Kill switch** | Lift the cover, press KILL: the agent's tab closes, anything waiting stays unsent, and the receipt is sealed. |
| **Replay** | Scrub through the session's screenshots. |
| **Verify** | Drop a `.abbreceipt` (and its `.keys.json`) to see the offline verifier's verdict. |

## What it does not do (read this)

- **Coverage is `STEP_OBSERVED`, never `STEP_GATED`.** A page script can still send data itself
  (`fetch`, XHR, WebSocket). The extension does not intercept those.
- A page load outside the passport is recorded and redirected away, but the request may already
  have reached that site. It is not stopped before the network.
- The passkey proves a person was present at the authenticator. It is not in the receipt: the
  receipt holds the approver key's Ed25519 signature, as every HashCam approval does.
- A valid receipt means the record has not changed since it was signed. It does not mean the
  agent was honest or that a page told the truth.
- The verify page runs the local `abb verify`. A WebAssembly build of the verifier that runs
  inside the browser is **not built**.
- It watches one tab at a time and is not a security product.

## Look and feel

The panel uses the **Night Observatory** theme shared with the HashCam Console (`theme.css`, `fx3d.js`, byte-identical copies of the files in `ui/`). It shows four of the console's animation styles: the **Glow Atom** session core (events orbit by kind, a glowing outer electron means an approval is waiting), the **paper-cut** receipt roll, the **domino** verdict (a FAIL stops the row) and a small **maths** line in the approval card (what you sign). Every one has a still version for reduced motion. `TESTED`: no sideways overflow at 320, 400 and 480 px with an approval card showing.

## Run it

1. Start the local service (needs the built `abb` binaries and a PostgreSQL you can create
   databases on, as for the other demos):

   ```bash
   python tools/recorder.py --dsn postgresql://abb@127.0.0.1:55432/postgres
   ```

   It prints where it wrote the pairing token (it never prints the token).
2. In Chrome, open `chrome://extensions`, turn on **Developer mode**, **Load unpacked**, and pick
   this `extension/` folder.
3. Click the HashCam icon to open the side panel. Paste the token, register a passkey.
4. Open the tab your agent will drive, fill in the task and the passport sites, and press
   **Record this tab**. Chrome asks for access to exactly those sites.

## Permissions, and why

| Permission | Why |
|---|---|
| `sidePanel`, `storage` | The panel, and the pairing token (kept in `chrome.storage.local`, sent only to `127.0.0.1`). |
| `tabs`, `webNavigation` | Know which tab is the agent's and see its page loads before they load. |
| `scripting` | Put the content script into the passport's sites only. |
| `downloads` | Pause a download until you decide. |
| `http://127.0.0.1/*` | Talk to the local recorder. |
| optional `http(s)://*/*` | Requested per session for **the passport's sites only**. |

## Files

| File | What it is |
|---|---|
| `manifest.json` | Manifest V3. |
| `background.js` | Watches the agent's tab; reports to the recorder; holds submits and downloads. |
| `content.js` | Holds form submissions; makes secret commitments; hands page text to the tripwire. |
| `page-guard.js` | In the page's own world: routes `form.submit()` through the held path. |
| `sidepanel.html`, `panel.js`, `panel.css` | The flight-recorder side panel. |
| `blocked.html` | Where a page outside the passport is sent. |
| `vendor/` | GSAP (motion) and Plus Jakarta Sans (OFL), copied from `ui/vendor`. |

The service behind it is `services/recorder/` (`session.py`, `server.py`, `passkey.py`).
