# Plans: Free, Pro and Enterprise

Three plans, one licence mechanism, no server. The numbers below are **shown and counted on the visitor's own
device**; nothing is enforced (there is no server to enforce it). Prices and payment are not in the code.

| | Free | Pro | Enterprise |
|---|---|---|---|
| Range levels | 1 to 6 | 1 to 16 | 1 to 16 |
| Runs per day (shown) | 20 | 200 | 2000 |
| Records in one audit pack (shown) | none | 20 | 500 (the pack reads up to 20 files today) |
| Locked PDF report | HashCam branding | your name and logo, "Made with HashCam" footer | your name and logo, **no HashCam footer** |
| Seats | 1 | 1 | named in the licence (shown, not counted) |

## What is built (`BUILT`) and what is not (`PLANNED`)

- `BUILT`: the plan in the signed licence (`plan`: `pro` or `enterprise`, plus optional `org` and `seats`); the three
  sets of limits (`site/range/limits.js`); a local usage meter (`site/pro/usage.js`) that counts scored runs per day in
  the browser (a date and a number only) and shows a notice past the limit; the Plans page (`/plans`); the
  organisation name and seats on the Pro page; the Enterprise report footer.
- `PLANNED` (not built): signed reports with the company's own key, private level packs, a bigger audit pack and a
  JSON Lines export, a self-host bundle, single sign-on, a central usage dashboard, server-enforced limits and seat
  counting, invoices. They are listed on the Plans page with a PLANNED tag.

## What "not enforced" means

The usage meter lives in the browser. It never blocks anything. Clearing browser data, a private window or another
device starts the count at zero, and the page says so. Seats are not counted at all. Real limits need a server
(`docs/AGENT_RANGE.md`, Phase 2).

## Make an Enterprise key

```bash
python tools/make_license.py sign --plan enterprise --name "Pat Doe" --org "Acme Ltd" --seats 25 --expires 2027-12-31
```

Send the printed `HCPRO1.` line to the buyer, who pastes it on the Pro page. Old Pro keys keep working.

## Where you set the words

`site/pro/config.js` holds, in one place: the "get a licence" link, the Enterprise contact link (https or mailto
only) and optional price text per plan. Leave a price empty and the page shows "Ask". Reports are summaries, not
proofs, and are not legal or compliance advice.

## Tested

`tests/ui/test_plans.py`: enterprise keys and bad org, seats and plan; the three sets of numbers; the Range shows
each plan's limits; the meter counts a scored run, warns past the limit, never blocks, stores only a date and a
number, ignores a tampered record and an old day, and resets; Enterprise PDFs have no "Made with HashCam" footer
and Pro PDFs do; the Plans page shows no price by default, takes price text and a safe contact link from one config,
fits a phone and makes no request. **Not tested:** a real licence made with your real key.
