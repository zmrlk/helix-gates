import http from 'k6/http';
import { check } from 'k6';
// slo.yaml must use JSON syntax (valid YAML):
// {"load_test":{"p95_ms":500,"error_rate":0.01}}
// Run from repository root: k6 run new/templates/ci/k6-baseline.js
const slo = JSON.parse(open('../../../slo.yaml')).load_test;
if (!(slo.p95_ms > 0) || !(slo.error_rate >= 0 && slo.error_rate < 1)) {
  throw new Error('Invalid slo.yaml load_test budgets');
}
export const options = {
  vus: 5, duration: '30s',
  thresholds: {
    http_req_duration: [`p(95)<${slo.p95_ms}`],
    http_req_failed: [`rate<=${slo.error_rate}`],
  },
};
export default function () {
  const response = http.get(__ENV.BASE_URL || 'http://localhost:3000/health');
  check(response, { healthy: r => r.status === 200 });
}
