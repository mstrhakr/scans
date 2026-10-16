'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'site', 'releases.js'), 'utf8');

test('includes local PrintMaster branding, a home link, and the canonical Scans guide', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'site', 'index.html'), 'utf8');
  const logo = fs.readFileSync(path.join(__dirname, '..', 'site', 'logo.svg'), 'utf8');
  assert.match(logo, /viewBox="0 0 64 64"/);
  assert.match(html, /rel="icon" href="logo\.svg"/);
  assert.match(html, /href="https:\/\/printmaster\.work\/" aria-label="PrintMaster home"/);
  assert.match(html, /<img src="logo\.svg" alt="" width="40" height="40">/);
  assert.match(html, /href="https:\/\/docs\.printmaster\.work\/guides\/scans\/"/);
  assert.match(html, /Provided by PrintMaster/);
  assert.match(html, /href="#main"/);
  assert.match(html, /<main id="main">/);
});

class Element {
  constructor() { this.children = []; this.textContent = ''; this.attributes = {}; this.listeners = {}; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}

function release(version) {
  return {
    version,
    url: `https://github.com/printmaster-org/scans/releases/download/${version}/scans.ps1`,
    releaseUrl: `https://github.com/printmaster-org/scans/releases/tag/${version}`,
    sha256: 'a'.repeat(64)
  };
}

async function render(manifest, ok = true, clipboard = { writeText: async () => {} }) {
  const elements = {
    'stable-status': new Element(),
    'release-list': new Element(),
    'setup-command': new Element(),
    'setup-command-text': new Element()
  };
  elements['setup-command-text'].textContent = 'irm https://scans.printmaster.work/scans.ps1 | iex';
  const context = vm.createContext({
    navigator: { clipboard },
    document: {
      getElementById: id => elements[id],
      createElement: () => new Element()
    },
    fetch: async () => ({ ok, status: ok ? 200 : 503, json: async () => manifest })
  });
  await vm.runInContext(source, context);
  return elements;
}

test('renders stable and pinned releases with matching version commands and hashes', async () => {
  const elements = await render({ schemaVersion: 1, stable: 'v2.1.0', releases: [release('v2.1.0'), release('v2.0.3')] });
  assert.match(elements['stable-status'].textContent, /v2\.1\.0/);
  const cards = elements['release-list'].children;
  assert.equal(cards.length, 2);
  assert.match(cards[0].children[0].textContent, /stable/);
  assert.match(cards[1].children[2].children[0].children[0].textContent, /-Version 'v2\.0\.3'/);
  assert.equal(cards[1].children[1].href, release('v2.0.3').releaseUrl);
  assert.match(cards[1].children[3].textContent, new RegExp('a'.repeat(64)));
});

test('copies the exact stable and pinned commands with accessible success feedback', async () => {
  const copied = [];
  const elements = await render(
    { schemaVersion: 1, stable: 'v2.1.0', releases: [release('v2.1.0')] },
    true,
    { writeText: async text => { copied.push(text); } }
  );
  const [stableButton, stableFeedback] = elements['setup-command'].children;
  assert.equal(stableButton.type, 'button');
  assert.equal(stableButton.attributes['aria-label'], 'Copy stable setup command');
  const pending = stableButton.listeners.click();
  assert.equal(stableButton.disabled, true);
  await pending;
  assert.equal(stableButton.disabled, false);
  assert.equal(stableFeedback.textContent, 'Copied!');
  assert.equal(stableFeedback.attributes.role, 'status');
  const [, pinnedButton, pinnedFeedback] = elements['release-list'].children[0].children[2].children;
  assert.equal(pinnedButton.attributes['aria-label'], 'Copy command for v2.1.0');
  await pinnedButton.listeners.click();
  assert.equal(pinnedFeedback.textContent, 'Copied!');
  assert.deepEqual(copied, [
    'irm https://scans.printmaster.work/scans.ps1 | iex',
    "& ([scriptblock]::Create((irm https://scans.printmaster.work/scans.ps1))) -Version 'v2.1.0'"
  ]);
});

test('reports clipboard rejection or unavailable API and allows retry without hiding commands', async () => {
  for (const clipboard of [
    null,
    { writeText: async () => { throw new Error('Permission denied'); } }
  ]) {
    const elements = await render(null, false, clipboard);
    const [button, feedback] = elements['setup-command'].children;
    await button.listeners.click();
    assert.match(feedback.textContent, /Could not copy.*manually/);
    assert.equal(button.disabled, false);
    assert.equal(elements['setup-command-text'].textContent, 'irm https://scans.printmaster.work/scans.ps1 | iex');
    await button.listeners.click();
    assert.match(feedback.textContent, /Could not copy/);
  }
});

test('reports network failure rather than displaying a success-shaped release list', async () => {
  const elements = await render(null, false);
  assert.match(elements['stable-status'].textContent, /unavailable/);
  assert.match(elements['release-list'].textContent, /HTTP 503/);
});

test('rejects malformed manifests, non-release URLs, and injected versions', async () => {
  for (const manifest of [
    { schemaVersion: 9, stable: 'v2.1.0', releases: [release('v2.1.0')] },
    { schemaVersion: 1, stable: 'v9.0.0', releases: [release('v2.1.0')] },
    { schemaVersion: 1, stable: 'v2.1.0', releases: [{ ...release('v2.1.0'), releaseUrl: 'javascript:alert(1)' }] },
    { schemaVersion: 1, stable: "v2.1.0'; evil", releases: [release("v2.1.0'; evil")] }
  ]) {
    const elements = await render(manifest);
    assert.match(elements['release-list'].textContent, /Could not load/);
    assert.equal(elements['release-list'].children.length, 0);
  }
});
