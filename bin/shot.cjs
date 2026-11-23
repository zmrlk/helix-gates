// usage: node shot.cjs <url> <out.png> <w> <h> '<actions json>'
const playwrightPath = require('./dependencies.cjs')('playwright');
const { chromium } = require(playwrightPath);
(async () => {
  const [url, out, w, h, actionsJson] = process.argv.slice(2);
  const actions = JSON.parse(actionsJson || '[]');
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: +w, height: +h } });
  await page.goto(url, { waitUntil: 'networkidle' });
  for (const a of actions) {
    if (a.click) await page.click(a.click);
    if (a.fill) await page.fill(a.fill, a.value ?? '');
    if (a.wait) await page.waitForTimeout(a.wait);
    if (a.waitFor) await page.waitForSelector(a.waitFor);
  }
  await page.screenshot({ path: out });
  let playwrightVersion = null, chromiumVersion = null;
  try { playwrightVersion = JSON.parse(require('fs').readFileSync(require('path').join(require('path').dirname(playwrightPath), 'package.json'), 'utf8')).version; } catch (_) {}
  try { chromiumVersion = await browser.version(); } catch (_) {}
  console.log('HELIX_TOOL_VERSIONS=' + JSON.stringify([
    {tool: 'node', version: process.versions.node, used: true},
    {tool: 'playwright', version: playwrightVersion, used: true},
    {tool: 'chromium', version: chromiumVersion, used: true}
  ]));
  await browser.close();
})().catch((e) => { console.error(e.message); process.exit(1); });
