# Core Web Vitals budget

ASSUMPTION: draft; thresholds are project defaults, not measured results.
Field p75 targets: LCP <=2500 ms, INP <=200 ms, CLS <=0.1.
- Owner, critical mobile/web flows, device/network and measurement window: TODO
- Lighthouse command/config and lab report: TODO
- Field/RUM scope, sample count and p75 results: TODO
- Optimize LCP images, JavaScript work and reserved layout dimensions: TODO
- Connect existing k6 thresholds to slo.yaml for backend p95/error budgets: TODO
- Retain report timestamp, revision, tool version, scope and failures: TODO
Lab measurements and TBT do not establish field INP. Offline audit stays needs-runtime.
