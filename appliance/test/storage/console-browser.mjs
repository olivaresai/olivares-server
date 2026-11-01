// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
import { createRequire } from 'node:module';
import { readFile, writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
const require = createRequire(new URL('../../../web/package.json', import.meta.url));
const { chromium } = require('@playwright/test');
const { default: AxeBuilder } = require('@axe-core/playwright');
const [origin, credentialsPath, output] = process.argv.slice(2);
const credentials = JSON.parse(await readFile(credentialsPath, 'utf8'));
const browser = await chromium.launch({ headless: true });
let page;
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
  const login = await context.request.post(origin + '/v1/auth/login', {
    headers: { 'X-Olivares-Session': 'cookie', Origin: origin }, data: credentials,
  });
  assert.equal(login.status(), 200, 'real product sign-in through portal');
  page = await context.newPage();
  const storagePost = request => request.url().endsWith('/storage/action') && request.method() === 'POST';
  page.on('response', response => {
    if (storagePost(response.request())) console.log('Storage HTTP status:', response.status());
  });
  page.on('requestfailed', request => {
    if (storagePost(request)) console.log('Storage network failure:', request.failure()?.errorText);
  });
  async function confirmAction(name) {
    const operation = await page.locator('input[name="operation_id"]').inputValue();
    assert.match(operation, /^[0-9a-f]{32}$/);
    console.log('Storage confirmed operation:', operation);
    const [response] = await Promise.all([
      page.waitForResponse(response => storagePost(response.request()), { timeout: 180000 }),
      page.getByRole('button', { name, exact: true }).click({ timeout: 180000 }),
    ]);
    assert.equal(response.status(), 200, 'confirmed storage request must complete');
  }
  await page.goto(origin + '/storage');
  const backup = page.getByRole('form', { name: 'Use /dev/vdc for backups', exact: true });
  for (let n = 0; !(await backup.count()) && n < 30; n++) {
    await page.waitForTimeout(1000); await page.reload();
  }
  assert.equal(await backup.count(), 1, 'hot-added 20GiB disk has a backup action');
  assert.equal(await page.getByRole('form', { name: 'Use /dev/vda for backups', exact: true }).count(), 0, 'system disk has no destructive backup action');
  assert.equal(await page.getByRole('form', { name: 'Use /dev/sr0 for backups', exact: true }).count(), 0, 'read-only optical media has no destructive backup action');
  const captures = [];
  async function capture(state) {
    for (const width of [1280, 390]) {
      for (const colorScheme of ['light', 'dark']) {
        await page.setViewportSize({ width, height: 900 });
        await page.emulateMedia({ colorScheme });
        const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
        assert.deepEqual(axe.violations.map(v => ({ id: v.id, impact: v.impact })), [], `${state} ${width} ${colorScheme}: axe`);
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'page fits viewport');
        const name = `${state}-${width}-${colorScheme}.png`;
        await page.screenshot({ path: `${output}/${name}`, fullPage: true });
        captures.push(name);
      }
    }
  }
  await capture('storage');
  const planReply = page.waitForResponse(r => r.url().endsWith('/storage/action') && r.request().method() === 'POST');
  await backup.getByRole('button', { name: 'Use for backups', exact: true }).click();
  const planResponse = await planReply;
  const formHeaders = await planResponse.request().allHeaders();
  assert.equal(formHeaders.origin, new URL(origin).origin, 'native form preserves its same-origin assertion');
  if (planResponse.status() !== 200) {
    console.log('Storage plan refused:', planResponse.status(), await page.locator('body').innerText());
  }
  assert.equal(planResponse.status(), 200, 'backup plan must be admitted');
  await page.getByRole('heading', { name: 'Confirm backup disk', exact: true }).waitFor();
  assert.match(await page.locator('main').innerText(), /erases all data on \/dev\/vdc/);
  await capture('backup-confirm');
  await confirmAction('Confirm use of /dev/vdc for backups');
  await page.getByRole('status').waitFor({ timeout: 180000 });
  assert.match(await page.getByRole('status').innerText(), /configured as the backup target/, 'confirmed backup must complete');
  await capture('backup-complete');
  await page.getByRole('form', { name: 'Grow data on /dev/vda', exact: true }).getByRole('button', { name: 'Grow now', exact: true }).click();
  await page.getByRole('heading', { name: 'Confirm data growth', exact: true }).waitFor();
  await capture('grow-confirm');
  await confirmAction('Confirm growth of /dev/vda');
  await page.getByRole('status').waitFor({ timeout: 180000 });
  assert.match(await page.getByRole('status').innerText(), /data volume now uses the available space/, 'confirmed growth must complete');
  await capture('grow-complete');
  await writeFile(`${output}/browser-result.json`, JSON.stringify({ result: 'PASS', realProduct: true, realPortal: true, backupDisk: '/dev/vdc', rootDestructiveAction: 'absent', axeViolations: 0, captures }, null, 2));
  console.log('PROOF storage-browser PASS backup=confirmed grow=confirmed viewports=1280,390 schemes=light,dark axe=0');
} catch (error) {
  if (page) {
    console.log('Storage browser location:', page.url().split(/[?#]/, 1)[0]);
    console.log('Storage browser state:', await page.locator('body').innerText().catch(() => 'unavailable'));
    await page.screenshot({ path: `${output}/failure.png`, fullPage: true }).catch(() => {});
  }
  throw error;
} finally { await browser.close(); }
