const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '..', 'site', 'embed.js'), 'utf8');

function render(search = '?embed=1', framed = true) {
  const messages = [];
  const listeners = {};
  const attributes = {};
  const external = {};
  let observer;
  const parent = { postMessage: (data, origin) => messages.push({ data, origin }) };
  const window = { parent, scrollY: 0, addEventListener: (type, fn) => { listeners[type] = fn; } };
  if (!framed) window.parent = window;
  vm.runInNewContext(source, {
    window, location: { search }, URLSearchParams,
    ResizeObserver: class {
      constructor(fn) { observer = fn; }
      observe() {}
    },
    document: {
      body: { getBoundingClientRect: () => ({ height: 1800 }) },
      documentElement: { setAttribute: (key, value) => { attributes[key] = value; } },
      querySelectorAll: () => [external],
      getElementById: id => id === 'releases' ? { getBoundingClientRect: () => ({ top: 1200 }) } : null,
      addEventListener: (type, fn) => { listeners[type] = fn; }
    }
  });
  return { messages, listeners, attributes, external, parent, resize: () => observer() };
}

test('standalone and unrequested frames never hide navigation or initialize messaging', () => {
  for (const page of [render('', true), render('?embed=1', false)]) {
    assert.equal(page.messages.length, 0);
    assert.equal(page.listeners.message, undefined);
    assert.deepEqual(page.attributes, {});
  }
});

test('embed mode requires the exact trusted parent and reports size and valid anchors', () => {
  const page = render();
  assert.equal(page.messages[0].origin, 'https://printmaster.work');
  assert.deepEqual(page.attributes, {});
  for (const event of [
    { origin: 'https://evil.example', source: page.parent },
    { origin: 'https://printmaster.work', source: {} }
  ]) page.listeners.message({ ...event, data: { type: 'printmaster:scans:init' } });
  assert.deepEqual(page.attributes, {});
  const init = hash => page.listeners.message({
    origin: 'https://printmaster.work', source: page.parent,
    data: { type: 'printmaster:scans:init', hash }
  });
  init('#releases');
  assert.equal(page.attributes['data-embedded'], '');
  assert.equal(page.external.target, '_top');
  assert.equal(page.messages[1].data.height, 1800);
  assert.equal(page.messages[2].data.top, 1200);
  assert.equal(page.messages[2].data.hash, '#releases');
  page.resize();
  assert.equal(page.messages.at(-1).data.type, 'printmaster:scans:resize');
  const count = page.messages.length;
  init('#missing');
  init('javascript:alert(1)');
  assert.equal(page.messages.length, count + 2, 'invalid targets emit size only, never scroll');
  let prevented = false;
  page.listeners.click({
    target: { closest: () => ({ getAttribute: () => '#releases' }) },
    button: 0, preventDefault: () => { prevented = true; }
  });
  assert.equal(prevented, true);
  assert.equal(page.messages.at(-1).data.type, 'printmaster:scans:anchor');
});
