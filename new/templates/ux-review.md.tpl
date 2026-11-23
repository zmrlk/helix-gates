# UX review before handoff

ASSUMPTION: draft. Run when a prototype is usable, after material flow changes and before handoff.
Use a fresh reviewer where available. Give a local/test URL, viewport and synthetic
fixtures. Ask them to infer the user goal from the interface and exercise one key
path. Avoid steering them with the expected click sequence. No runnable UI means
static review only; the audit control remains needs-runtime.
1. Product understanding, chosen goal, viewport and starting state: TODO
2. Actual path, observed final state and evidence/screenshots: TODO
3. At most three significant issues: observed fact, separate hypothesis, desired outcome: TODO
4. Check blocked progress, wrong turns, unclear next step, loading/success/error feedback,
   keyboard, recovery and mobile layout: TODO
5. Run `helix ux` and `helix consistency scan`; remediate, then verify the changed flow: TODO
6. Record completion/partial/failure, owner and unverified limits: TODO
Do not infer real-user success rates or usability from elapsed automation time.
