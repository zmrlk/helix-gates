// Uruchomienie: BASE_URL=http://localhost:3000 ENDPOINTS=/health,/api/items k6 run templates/k6-api-smoke.js
import http from 'k6/http';
import { check, sleep } from 'k6';

const base = (__ENV.BASE_URL || 'http://localhost:3000').replace(/\/$/, '');
// Guard also applies when the template is executed directly, outside Helix.
if (!/^https?:\/\/(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:\d+)?(\/|$)/i.test(base)) {
  throw new Error('BASE_URL musi wskazywać localhost');
}
const endpoints = (__ENV.ENDPOINTS || '/health').split(',').map(x => x.trim());
if (endpoints.some(x => !x.startsWith('/') || x.startsWith('//') || x.includes('://') || x.includes('\\'))) {
  throw new Error('ENDPOINTS musi zawierać lokalne ścieżki zaczynające się od /');
}
export const options = {
  vus: 10,
  duration: '30s',
  thresholds: { http_req_duration: ['p(95)<500'], http_req_failed: ['rate<0.01'] },
};
export default function () {
  for (const endpoint of endpoints) {
    const response = http.get(base + endpoint, { redirects: 0 });
    check(response, { 'status 2xx': r => r.status >= 200 && r.status < 300 });
  }
  sleep(1);
}
