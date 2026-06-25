"""
Example 09 — measure it: attack-success-rate before and after.
==============================================================

A defense you can't measure is a defense you can't trust — the same lesson as the
evals-deep-dive repo, pointed at security. We run the whole attack catalog against
two bots and report the **attack-success-rate** (fraction of attacks that got the
secret out): the naive baseline vs a hardened bot with input, data, and output
defenses layered.

Watch the number fall. Then note that "0% on six known attacks" is not "secure" —
it's "secure against this small, known set." Real red-teaming uses far more (and
adaptive) attacks, and the rate is something you track over time, not a box you
tick once.

Run it:

    python examples/09_redteam_eval.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

import guardrails as g

load_dotenv()
g.ensure_ready()
print(f"Provider: {g.describe()}\n")

bots = {
    "naive (no defenses)": g.SupportBot(),
    "hardened (input+data+output)": g.SupportBot(input_guard=True, output_guard=True, data_defense=True),
}

reports = {}
for label, bot in bots.items():
    report = g.run_redteam(bot)
    reports[label] = report
    print(f"=== {label} ===")
    for r in report.results:
        status = "LEAKED" if r.succeeded else ("blocked" if r.blocked else "resisted")
        print(f"  {status:>8}  {r.name}")
    print(f"  attack-success-rate: {report.success_rate:.0%}   (blocked: {report.blocked_rate:.0%})\n")

naive = reports["naive (no defenses)"].success_rate
hardened = reports["hardened (input+data+output)"].success_rate
print(f"Attack-success-rate: {naive:.0%} (naive) -> {hardened:.0%} (hardened)")
print(
    "\nThat drop is your defenses working — and it's a number you can re-run on "
    "every change. But don't read a low rate as 'solved': it's only as strong as "
    "your attack set. Treat injection like any security problem — defense in depth, "
    "measured continuously, never declared finished."
)
