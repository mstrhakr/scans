'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'site', 'releases.js'), 'utf8');

class Element {
  constructor() { this.children = []; this.textContent = ''; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
}

function release(version) {
  return {
    version,
    url: `https://github.com/printmaster-org/scans/releases/download/${version}/scans.ps1`,
    releaseUrl: `https://github.com/printmaster-org/scans/releases/tag/${version}`,
    sha256: 'a'.repeat(64)
  };
}

async function render(manifest, ok = true) {
  const elements = { 'stable-status': new Element(), 'release-list': new Element() };
  const context = vm.createContext({
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
  assert.match(cards[1].children[2].children[0].textContent, /-Version 'v2\.0\.3'/);
  assert.equal(cards[1].children[1].href, release('v2.0.3').releaseUrl);
  assert.match(cards[1].children[3].textContent, new RegExp('a'.repeat(64)));
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
