/*
 * Headless screenshot helper for KAMSTRIKE.
 *
 * Reads a JSON job on stdin: {"targets":[{"url":..,"out":..}],"timeout":ms,"width":..,"height":..}
 * Writes a JSON result on stdout: {"results":[{"url":..,"out":..,"ok":bool,"title":..,"error":..}]}
 *
 * Kept as a separate process because the camera web UIs are hostile to automation - self
 * signed certs, basic-auth dialogs, frames that never finish loading - and a crashed
 * browser must not take the scan with it.
 */
'use strict';

const { chromium } = require('playwright');

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

(async () => {
  let job;
  try {
    job = JSON.parse(await readStdin());
  } catch (err) {
    process.stdout.write(JSON.stringify({ results: [], error: `bad job: ${err.message}` }));
    process.exit(0);
  }

  const targets = job.targets || [];
  const timeout = job.timeout || 12000;
  const width = job.width || 1280;
  const height = job.height || 800;
  const results = [];

  let browser;
  try {
    browser = await chromium.launch({ args: ['--ignore-certificate-errors'] });
  } catch (err) {
    process.stdout.write(JSON.stringify({ results: [], error: `launch failed: ${err.message}` }));
    process.exit(0);
  }

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width, height },
    userAgent: job.userAgent || undefined,
  });
  // an unexpected auth dialog or alert would otherwise block the page forever
  context.on('page', (page) => {
    page.on('dialog', (d) => d.dismiss().catch(() => {}));
  });

  for (const target of targets) {
    const entry = { url: target.url, out: target.out, ok: false, title: '', error: '' };
    const page = await context.newPage();
    try {
      const response = await page.goto(target.url, { timeout, waitUntil: 'domcontentloaded' });
      entry.status = response ? response.status() : null;
      await page.waitForTimeout(Math.min(1500, timeout / 4));
      entry.title = (await page.title().catch(() => '')) || '';
      await page.screenshot({ path: target.out, fullPage: false });
      entry.ok = true;
    } catch (err) {
      entry.error = String(err.message || err).split('\n')[0].slice(0, 300);
      // a navigation timeout still often leaves something rendered worth keeping
      try {
        await page.screenshot({ path: target.out, fullPage: false });
        entry.ok = true;
        entry.partial = true;
      } catch (_) { /* nothing rendered */ }
    } finally {
      await page.close().catch(() => {});
    }
    results.push(entry);
  }

  await context.close().catch(() => {});
  await browser.close().catch(() => {});
  process.stdout.write(JSON.stringify({ results }));
})();
