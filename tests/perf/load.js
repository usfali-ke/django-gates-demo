// Performance: 10 virtual users for 30s against pre-production, logged in,
// on the paths a user actually hits. verdict.py k6 decides: p95 within
// the SLO, <1% failed requests, >=99% checks passed.
import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = __ENV.BASE_URL;

export const options = {
  vus: 10,
  duration: '30s',
  // Each VU is one user who logs in once. k6's default clears the jar every
  // iteration, which would re-login (a deliberately slow password hash)
  // ~30 times a second and measure the hasher, not the app.
  noCookiesReset: true,
};

function login() {
  const page = http.get(`${BASE}/accounts/login/`);
  if (!check(page, { 'login page 200': (res) => res.status === 200 })) {
    return false;
  }
  const token = page.html().find('input[name=csrfmiddlewaretoken]').attr('value');
  const r = http.post(`${BASE}/accounts/login/`,
    { username: __ENV.USER_A, password: __ENV.PASSWORD_A, csrfmiddlewaretoken: token },
    { headers: { Origin: BASE, Referer: `${BASE}/` }, redirects: 0 });
  return check(r, { 'login 302': (res) => res.status === 302 });
}

export default function () {
  const jar = http.cookieJar();
  if (!jar.cookiesForURL(BASE).sessionid && !login()) {
    sleep(1); // counted as failed checks; don't hammer a broken login
    return;
  }
  const csrf = jar.cookiesForURL(BASE).csrftoken[0];
  const headers = { 'Content-Type': 'application/json', 'X-CSRFToken': csrf, Origin: BASE, Referer: `${BASE}/` };

  check(http.get(`${BASE}/healthz`), { 'healthz ok': (r) => r.status === 200 });
  check(http.get(`${BASE}/notes/`), { 'page 200': (r) => r.status === 200 });
  const created = http.post(`${BASE}/api/notes/`, JSON.stringify({ text: `k6 ${__VU}-${__ITER}` }), { headers });
  check(created, { 'create 201': (r) => r.status === 201 });
  check(http.get(`${BASE}/api/notes/`), { 'list 200': (r) => r.status === 200 });
  if (created.status === 201) {
    const del = http.del(`${BASE}/api/notes/${created.json('id')}/`, null, { headers });
    check(del, { 'delete 204': (r) => r.status === 204 });
  }
  sleep(0.2);
}

export function handleSummary(data) {
  return { [__ENV.SUMMARY_OUT || 'k6-summary.json']: JSON.stringify(data) };
}
