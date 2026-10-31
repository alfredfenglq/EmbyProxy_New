const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const html = readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];

function createContext() {
  const elements = new Map();
  const context = vm.createContext({
    localStorage: { getItem: () => null },
    window: {},
    confirm: () => true,
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, { value: '', checked: false, disabled: false, hidden: false, innerHTML: '', textContent: '', addEventListener() {}, removeAttribute() {} });
        return elements.get(id);
      },
      querySelectorAll: () => [],
    },
    setTimeout() {},
    clearTimeout() {},
  });
  vm.runInContext(script, context);
  return { context, elements };
}

test('sync modal markup is present', () => {
  assert.match(html, /id="syncModal"/);
  assert.match(html, /onclick="openSyncModal\(\)"/);
  assert.match(html, /id="sync-target-token" autocomplete="new-password"/);
  assert.doesNotMatch(html, /id="sync-include(?:Config|Telegram)"/);
});

test('sync results escape remote data and summarize changes', () => {
  const { context } = createContext();
  const output = vm.runInContext(`renderSyncResults([
    {name: '<b>target-a</b>', ok: true, added: ['n3'], updated: [{name: 'n2', fields: ['target']}], deleted: ['x9'], unchanged: 1,
     config: {changed: ['logLevel']}, telegram: {changed: []}},
    {name: 'target-b', ok: false, error: '<i>Token 错误</i>', added: [], updated: [], deleted: [], unchanged: 0},
  ], false, true)`, context);
  assert.match(output, /&lt;b&gt;target-a&lt;\/b&gt;/);
  assert.doesNotMatch(output, /<b>target-a<\/b>/);
  assert.doesNotMatch(output, /<i>/);
  assert.match(output, /计划节点：新增 1，更新 1，未变 1，删除 1/);
  assert.match(output, /~ n2（target）/);
  assert.doesNotMatch(output, /系统设置|Telegram/);
  // A target that failed before the node diff must not report a misleading node summary.
  assert.doesNotMatch(output.split('target-b')[1], /节点：/);
});

test('failed imports and skipped pruning never appear completed', () => {
  const { context } = createContext();
  const output = vm.runInContext(`renderSyncResults([
    {name: 'target-a', ok: false, error: 'import failed', added: ['new'], updated: [], deleted: ['extra'], unchanged: 0,
     completed: {added: 0, updated: 0, deleted: 0}, pruneSkipped: true, importFailures: [{name: 'new', error: 'rejected'}]},
  ], true, true)`, context);
  assert.match(output, /计划节点：新增 1，更新 0，未变 0，删除 1/);
  assert.match(output, /已确认完成：新增 0，更新 0，删除 0/);
  assert.match(output, /已跳过删除/);
  assert.match(output, /计划明细（不代表全部执行成功）/);
  assert.doesNotMatch(output, /已同步/);
});

test('partial execution uses confirmed counts and ignores legacy settings results', () => {
  const { context } = createContext();
  const output = vm.runInContext(`renderSyncResults([
    {name: 'target-a', ok: false, error: 'write failed', added: ['new'], updated: [{name:'old',fields:['target']}], deleted: ['extra'],
     completed: {added: 1, updated: 0, deleted: 0}, config: {changed:['logLevel'], applied:false}},
  ], true, true)`, context);
  assert.match(output, /已确认完成：新增 1，更新 0，删除 0/);
  assert.doesNotMatch(output, /系统设置|logLevel/);
  assert.match(output, /未确认的操作可能已执行/);
});

test('invalid sync API payload is a boundary error, not an empty success', async () => {
  const { context } = createContext();
  vm.runInContext(`syncTargets = [{id:'a',name:'A'}]; messages=[]; api=async()=>({ok:true}); toast=(msg)=>messages.push(msg);`,context);
  await vm.runInContext('runSync(true)',context);
  assert.match(vm.runInContext('messages.join()',context), /同步响应无效/);
  assert.doesNotMatch(vm.runInContext('messages.join()',context), /同步完成/);
});

test('runSync sends only selected targets with the chosen options', async () => {
  const { context, elements } = createContext();
  vm.runInContext(`
    syncTargets = [{id: 'a', name: 'A'}, {id: 'b', name: 'B'}];
    syncUnchecked = new Set(['b']);
    calls = [];
    api = async (action, data) => { calls.push({action, data}); return {ok: true, results: []}; };
    toast = () => {};
  `, context);
  context.document.getElementById('sync-prune').checked = true;
  await vm.runInContext('runSync(false)', context);
  await vm.runInContext('runSync(true)', context);
  const calls = JSON.parse(JSON.stringify(vm.runInContext('calls', context)));
  assert.deepEqual(calls, [
    { action: 'sync.preview', data: { ids: ['a'], prune: true } },
    { action: 'sync.run', data: { ids: ['a'], prune: true } },
  ]);
  assert.equal(elements.get('syncRunBtn').disabled, false);
});

test('resetting the protected UI clears an unsaved remote token', () => {
  const { context, elements } = createContext();
  vm.runInContext(`syncTargets = [{id: 'a', name: 'target-a', url: 'https://proxy.example.com', tokenReadable: true}]; editSyncTarget('a')`, context);
  context.document.getElementById('sync-target-token').value = 'remote-secret';
  context.document.getElementById('syncResults').innerHTML = '<div>target-a</div>';
  vm.runInContext('resetProtectedUI()', context);
  assert.equal(elements.get('sync-target-token').value, '');
  assert.equal(elements.get('sync-target-name').value, '');
  assert.equal(elements.get('syncResults').innerHTML, '');
  assert.equal(vm.runInContext('syncTargets.length + editingSyncTargetId.length', context), 0);
});

test('editing a target keeps the token field empty', () => {
  const { context, elements } = createContext();
  vm.runInContext(`syncTargets = [{id: 'a', name: 'target-a', url: 'https://proxy.example.com', tokenReadable: true}]; editSyncTarget('a')`, context);
  assert.equal(elements.get('sync-target-name').value, 'target-a');
  assert.equal(elements.get('sync-target-token').value, '');
  assert.match(elements.get('sync-target-token').placeholder, /留空/);
  assert.equal(vm.runInContext('editingSyncTargetId', context), 'a');
  vm.runInContext('resetSyncTargetForm()', context);
  assert.equal(vm.runInContext('editingSyncTargetId', context), '');
});
