const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const html = readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];

test('node form defaults, loads, disables and serializes shared identity', () => {
  assert.match(html, /id="f-sharedDeviceIdentity"/);
  const elements = new Map();
  const context = vm.createContext({
    localStorage: { getItem: () => null },
    window: {},
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, { value: '', checked: false, disabled: false, addEventListener() {} });
        return elements.get(id);
      },
    },
    setTimeout() {},
    clearTimeout() {},
  });
  vm.runInContext(script, context);
  vm.runInContext('clearNodeForm()', context);
  const shared = elements.get('f-sharedDeviceIdentity');
  assert.equal(shared.checked, false);
  assert.equal(shared.disabled, false);
  assert.equal(vm.runInContext('getNodeFormData().sharedDeviceIdentity', context), false);
  vm.runInContext('fillNodeForm({sharedDeviceIdentity:true, impersonate:true})', context);
  assert.equal(shared.checked, true);
  assert.equal(vm.runInContext('getNodeFormData().sharedDeviceIdentity', context), true);
  vm.runInContext("document.getElementById('f-impersonate').checked=false;syncImpersonateProfileState()", context);
  assert.equal(shared.disabled, true);
  assert.equal(shared.checked, true);
  vm.runInContext('fillNodeForm({})', context);
  assert.equal(shared.checked, false);
  vm.runInContext('fillNodeForm({sharedDeviceIdentity:true});clearNodeForm()', context);
  assert.equal(shared.checked, false);
});
