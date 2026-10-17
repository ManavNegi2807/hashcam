# policy.py: har web action se pehle faisla karta hai: allow, block, ya need_approval.


class Guard:
    def __init__(self, allowed_sites, recipients, limit_inr=500,
                 sensitive_actions=("pay", "submit_form", "login")):
        self.allowed_sites = set(allowed_sites)     # sirf ye sites chalengi
        self.recipients = set(recipients)           # payment sirf inhi ko
        self.limit_inr = limit_inr                  # ek task mein max amount
        self.sensitive = set(sensitive_actions)     # inke liye human approval chahiye

    def check(self, url, action, params=None):
        params = params or {}

        if url not in self.allowed_sites:                         # rule 1: site allowlist
            return "block", f"site not allowed: {url}"

        if action == "pay":
            if params.get("recipient") not in self.recipients:    # rule 2: recipient allowlist
                return "block", "recipient not allowed"
            if params.get("amount_inr", 0) > self.limit_inr:      # rule 3: spending limit
                return "block", f"amount above limit {self.limit_inr}"

        if action in self.sensitive:                              # rule 4: human approval
            return "need_approval", f"{action} needs human approval"

        return "allow", ""
