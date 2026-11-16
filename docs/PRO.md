# HashCam Pro

Pro is a licence key that turns on a few extra tools on the website. This file says how to make a key for a
buyer, what Pro does today, and what is tested and not tested. There is no server, no payment code and no
price in the repository.

## What Pro does today

| Tool | State |
|---|---|
| Your company name and logo in the header of the locked PDF reports (Range and audit pack) | `BUILT` |
| Audit pack: many verified records in one locked PDF | `BUILT` |
| Every step as a CSV file | `BUILT` |
| Book-an-audit page (free; a person's time) | `BUILT` |
| Compare runs, Policy Studio, more levels, command-line scorer, verify widget | `PLANNED` |

Free users still see the Pro tools, greyed out, with one line on what each does.

## How the licence works

You keep a **private key** on your own computer. The matching **public key** is written into
`site/pro/pubkey.js` and deployed with the site. A licence key is a small signed note: the buyer's name, the
plan, the dates and an id. The website checks the signature in the browser with the public key.

- The check **runs in the buyer's browser**, so it is not enforced by a server. It keeps honest people
  honest. A determined person can get around any check that runs on their own computer.
- A key is kept on the buyer's own device only and is never sent anywhere.
- An expired key stops working at the end of its last day. There is no way to cancel a key early: if you need
  that, give short licences (for example one year).
- `site/pro/pubkey.js` ships with `publicKeyHex: null`. Until you run `init` below, **nothing unlocks** and the
  Pro page says licence checking is not set up yet.

## Set it up (once)

You need Python and the `cryptography` package (`pip install cryptography`).

1. From the repository folder, run:

   ```bash
   python tools/make_license.py init
   ```

   This makes the key pair. The private key is saved to `~/.hashcam/license-private.pem` (your user folder).
   The tool **refuses to save it inside the repository** and never prints it.
2. **Back that file up** somewhere safe (an encrypted drive, a password manager's file storage). If you lose
   it you cannot make new keys for this site. If it leaks, run `init --force`, commit the new
   `site/pro/pubkey.js`, deploy, and send buyers new keys (the old ones stop working).
3. Commit `site/pro/pubkey.js` (it holds only the public key) and merge. The site now accepts your keys.
4. Set the two links you own, each in one place:
   - `site/pro/config.js`: `getLicenseUrl` is the page where people buy or ask for a licence (`https://…` or
     `mailto:…`). Leave `"#"` and the Pro page says the link is not set up yet.
   - `site/audit.html`: the `mailto:` address on the "Email to book" button (replace
     `CHANGE-ME@example.com`).

## Make a key for a buyer

```bash
python tools/make_license.py sign --name "Acme Audit Ltd"
python tools/make_license.py sign --name "Acme Audit Ltd" --expires 2027-12-31
```

It prints one line starting with `HCPRO1.`. Send that line to the buyer. They open the Pro page, paste it into
"Your licence" and press **Check and save**.

To check a key someone sends you:

```bash
python tools/make_license.py check HCPRO1.…
```

How you take payment is up to you. Use a payment link from a provider and email the key after it clears. Prices
and tax are your decision and may need local advice. Nothing about them is in the code.

## Honest limits

- A report is a summary, not a proof. Anyone who wants proof should ask for the records and check them.
- A sandbox record shows it was not edited, not where it came from.
- HashCam reports help with record-keeping. They are **not legal or compliance advice**; the site never says
  they make anyone compliant.
- The Range's limits (runs per day and so on) are shown, **not enforced**. The Pro plan only changes the
  numbers shown.

## What is tested

`tests/ui/test_pro.py` (needs a browser and `pypdf`):

- The tool makes, checks and refuses keys; `init` will not write the private key inside the repository and
  never prints it; no private key file is in the repository.
- The browser accepts a good key and refuses a changed one, one from another key pair, an expired one, a
  wrong-plan one, a garbage one and every bad field (tests make their own key pair; the real one is never
  used). A refused key is not stored.
- White-label PDF: opens only with its password, shows the buyer's name, still says "Made with HashCam". A
  logo that is not a real PNG or JPEG, is too big, too large or too small is refused.
- Audit pack: a record that does not check out is listed as not included and is not in the totals or the
  sessions; the totals match the records.
- CSV: no secrets, no web-address queries, formula-looking cells made harmless, one row per step.
- Nothing is uploaded; no billing words; the audit page has no script and one mailto link; pages fit a phone.

## What is not tested

- A real licence made with your real key (that key does not exist until you run `init`).
- Browsers without Ed25519 support: the page says so and stays on Free, but this is not run here.
- Opening the PDFs in every PDF viewer (they are opened with one independent library).
