const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor(tag = 'div') { this.tag = tag; this.children = []; this.dataset = {}; this.handlers = {}; this.className = ''; this.value = ''; this.hidden = false; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; }
  setAttribute(name, value) { (this.attributes ||= {})[name] = value; }
  focus() {}
  addEventListener(name, handler) { this.handlers[name] = handler; }
  querySelectorAll() { return this.children.flatMap(e => [ ...(e.tag === 'button' ? [e] : []), ...e.querySelectorAll() ]); }
}
async function main() {
  const html = fs.readFileSync(require('node:path').join(__dirname, 'index.html'), 'utf8');
  const elements = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(m => [m[1], new Element()]));
  const calls = [];
  const wdttUser = { id: 'f'.repeat(64), label: '<script>Phone</script>', status: 'active', shared: true,
    password: 'test-client-secret', ports: '56000,56001,1080', vk_hash: 'hash', link: 'wdtt://connect?test',
    devices: [{ name: 'Phone', last_seen_at: 100 }], traffic: { all: { down: 1024, up: 2048 } } };
  let rejectSession = false;
  let rejectWdtt = false;
  let rejectSource = false;
  const state = { csrf: 'test-csrf', busy: false, candidate: null, profiles: [], previous: false,
    fallback_enabled: false, mode: 'auto', active: { source: 'primary', nodes: 1 }, message: 'Ready',
    catalog: { free: { name: 'Parsabrg', enabled: true, next_refresh: 100000 }, 'free-second': { name: 'Second', enabled: false } },
    sources: { primary: { nodes: 1 }, free: { nodes: 1 } }, connections: [
      { source: 'primary', id: 'a'.repeat(64), name: 'Primary', transport: 'tcp' },
      { source: 'free', id: 'a'.repeat(64), name: 'Free', transport: 'ws' }
    ] };
  const context = vm.createContext({
    window: { scrollTo() {} },
    document: { getElementById: id => elements[id], activeElement: null,
      addEventListener: () => {},
      createElement: tag => new Element(tag),
      querySelectorAll: () => elements.connections.querySelectorAll() },
    fetch: async (url, options) => {
      calls.push({ url, options });
      if (url === '/api/save-source' && rejectSource) return { ok: false, status: 400, json: async () => ({ error: 'Проверьте ссылку' }) };
      if (url === '/api/wdtt/users') return { ok: true, status: 200, json: async () => ({ users: [wdttUser], default_ports: wdttUser.ports }) };
      if (url === '/api/wdtt/user' && rejectWdtt) return { ok: false, status: 400, json: async () => ({ error: 'Срок истёк' }) };
      if (url === '/api/wdtt/user') return { ok: true, status: 200, json: async () => ({ user: wdttUser, message: 'Готово' }) };
      if (url === '/api/status' && rejectSession) return { ok: false, status: 401, json: async () => ({ error: 'Войдите в панель.' }) };
      return { ok: true, status: 200, json: async () => url === '/api/status' ? state : { accepted: true } };
    },
    setTimeout: () => 1, clearTimeout: () => {}, Date, console
  });
  vm.runInContext(html.split('<script>')[1].split('</script>')[0], context);
  const settle = () => new Promise(resolve => setImmediate(resolve));
  await settle();
  assert.equal(elements.panel.hidden, false);
  elements['nav-subs'].handlers.click();
  assert.equal(elements['view-home'].hidden, true);
  assert.equal(elements['view-subs'].hidden, false);
  assert.equal(elements['nav-subs'].attributes['aria-current'], 'page');
  elements.subsFreeTab.handlers.click();
  assert.equal(elements.subsPersonal.hidden, true);
  assert.equal(elements.subsFree.hidden, false);
  elements.addSource.handlers.click();
  assert.equal(elements.sourceEditor.hidden, false);
  elements.sourceClose.handlers.click();
  assert.equal(elements.sourceEditor.hidden, true);
  elements.replacePrimary.handlers.click();
  assert.equal(elements.primaryEditor.hidden, false);
  elements.primaryClose.handlers.click();
  assert.equal(elements.primaryEditor.hidden, true);
  assert.equal(elements.connections.children.length, 1);
  assert.equal(elements.sourceFilter.value, 'primary');
  elements.sourceFilter.value = '';
  await vm.runInContext('status()', context);
  assert.equal(elements.connections.children.length, 2);
  assert.match(elements.activeSource.textContent, /Основная/);
  elements.toggleFallback.handlers.click();
  await settle();
  let call = calls.find(c => c.url === '/api/settings');
  assert.deepEqual(JSON.parse(call.options.body), { enabled: true });
  assert.equal(call.options.headers['X-CSRF-Token'], 'test-csrf');
  elements.refreshFree.handlers.click();
  await settle();
  assert(calls.some(c => c.url === '/api/refresh-free'));
  const button = elements.connections.querySelectorAll().find(b => b.dataset.source === 'free' && b.dataset.action === 'select');
  elements.connections.handlers.click({ target: { closest: () => button } });
  // action() disabled the controls, so emulate the next status poll before clicking.
  await vm.runInContext('status()', context);
  elements.connections.handlers.click({ target: { closest: () => button } });
  await settle();
  call = calls.find(c => c.url === '/api/select');
  assert.deepEqual(JSON.parse(call.options.body), { id: 'a'.repeat(64), source: 'free' });
  state.connections[0].manual = true;
  state.connections[0].selected = true;
  state.mode = 'manual';
  await vm.runInContext('status()', context);
  const starred = elements.connections.querySelectorAll().find(b => b.dataset.source === 'primary' && b.dataset.action === 'select');
  assert.match(starred.textContent, /★/);
  assert.equal(starred.attributes['aria-pressed'], 'true');
  assert.match(starred.className, /priority-active/);
  assert.match(elements.connectionMode.textContent, /приоритетный узел/);
  elements.connections.handlers.click({ target: { closest: () => starred } });
  await settle();
  assert.deepEqual(JSON.parse(calls.filter(c => c.url === '/api/select').at(-1).options.body), { id: null, source: 'primary' });
  state.connections[0].manual = false;
  state.mode = 'auto';
  await vm.runInContext('status()', context);
  const emptyStar = elements.connections.querySelectorAll().find(b => b.dataset.source === 'primary' && b.dataset.action === 'select');
  assert.match(emptyStar.textContent, /☆/);
  assert.equal(emptyStar.attributes['aria-pressed'], 'false');
  elements.connections.handlers.click({ target: { closest: () => emptyStar } });
  await settle();
  assert.deepEqual(JSON.parse(calls.filter(c => c.url === '/api/select').at(-1).options.body), { id: 'a'.repeat(64), source: 'primary' });
  await vm.runInContext('status()', context);
  assert.equal(elements.freeSources.children.length, 2);
  const sourceButtons = elements.freeSources.querySelectorAll();
  const feedPing = sourceButtons.find(b => b.dataset.source === 'free' && b.dataset.action === 'ping');
  elements.freeSources.handlers.click({ target: { closest: () => feedPing } });
  await settle();
  assert(calls.some(c => c.url === '/api/ping' && JSON.parse(c.options.body).source === 'free'));
  await vm.runInContext('status()', context);
  const edit = elements.freeSources.querySelectorAll().find(b => b.dataset.action === 'edit');
  elements.freeSources.handlers.click({ target: { closest: () => edit } });
  assert.equal(elements.sourceName.value, 'Parsabrg');
  elements.sourceName.value = 'Renamed';
  elements.sourceForm.handlers.submit({ preventDefault() {} });
  await settle();
  assert(calls.some(c => c.url === '/api/save-source' && JSON.parse(c.options.body).name === 'Renamed'));
  assert.equal(elements.sourceUrl.value, '');
  // Private reserves have their own ordered list, editor and movement controls.
  state.catalog['private-a'] = { name: 'My reserve', kind: 'personal', enabled: true, profile: 1 };
  state.sources['private-a'] = { nodes: 3 };
  await vm.runInContext('status()', context);
  assert.equal(elements.personalSources.children.length, 1);
  assert.equal(elements.freeSources.children.length, 2);
  const up = elements.personalSources.querySelectorAll().find(b => b.dataset.action === 'up');
  elements.personalSources.handlers.click({ target: { closest: () => up } });
  await settle();
  assert(calls.some(c => c.url === '/api/move-source' && JSON.parse(c.options.body).direction === 'up'));
  await vm.runInContext('status()', context);
  const privateEdit = elements.personalSources.querySelectorAll().find(b => b.dataset.action === 'edit');
  elements.personalSources.handlers.click({ target: { closest: () => privateEdit } });
  assert.equal(elements.sourceKind.value, 'personal');
  assert.equal(elements.sourceKind.disabled, true);
  assert.equal(elements.sourceProfile.value, '2');
  elements.sourceForm.handlers.submit({ preventDefault() {} });
  await settle();
  assert(calls.some(c => c.url === '/api/save-source' && JSON.parse(c.options.body).kind === 'personal' && JSON.parse(c.options.body).profile === 1));
  state.message = 'Источник сохранён.';
  await vm.runInContext('status()', context);
  assert.equal(elements.sourceKind.disabled, false);
  assert.equal(elements.sourceEditor.hidden, true);
  elements.sourceName.value = 'New reserve';
  elements.sourceUrl.value = 'https://reserve.example.com/sub';
  elements.sourceForm.handlers.submit({ preventDefault() {} });
  await settle();
  assert(calls.some(c => c.url === '/api/save-source' && JSON.parse(c.options.body).name === 'New reserve' && JSON.parse(c.options.body).kind === 'personal'));
  rejectSource = true;
  elements.addSource.handlers.click();
  elements.sourceName.value = 'Draft';
  elements.sourceUrl.value = 'https://draft.example.com/sub';
  await elements.sourceForm.handlers.submit({ preventDefault() {} });
  assert.equal(elements.sourceEditor.hidden, false);
  assert.equal(elements.sourceUrl.value, 'https://draft.example.com/sub');
  assert.equal(elements.sourceError.textContent, 'Проверьте ссылку');
  rejectSource = false;
  elements.sourceClose.handlers.click();
  elements.sourceFilter.value = 'primary';
  await vm.runInContext('status()', context);
  assert.equal(elements.connections.children.length, 1);
  elements.sourceFilter.value = '';
  state.busy = true;
  await vm.runInContext('status()', context);
  assert.equal(elements.toggleFallback.disabled, true);
  assert.equal(elements.refreshFree.disabled, true);
  assert(elements.personalSources.querySelectorAll().every(b => b.disabled));
  assert(elements.connections.querySelectorAll().every(b => b.disabled));
  await vm.runInContext('loadWdtt()', context);
  assert.equal(elements.wdttUsers.children.length, 1);
  assert.equal(elements.wdttUsers.children[0].children[0].children[0].textContent, wdttUser.label);
  await vm.runInContext("wdttAction('details',{id:'" + wdttUser.id + "'})", context);
  assert.equal(elements.wdttSecret.value, 'test-client-secret');
  assert.equal(elements.wdttShared.value, 'true');
  assert.equal(elements.wdttLink.value, wdttUser.link);
  assert.equal(elements.userAccess.hidden, false);
  assert.equal(elements.userSettings.hidden, true);
  elements.userSettingsTab.handlers.click();
  assert.equal(elements.userSettings.hidden, false);
  assert.equal(elements.userAccess.hidden, true);
  elements.userActivityTab.handlers.click();
  assert.equal(elements.userActivity.hidden, false);
  assert.equal(elements.userSettings.hidden, true);
  elements.wdttLabel.value = 'Unsaved name';
  await vm.runInContext('status()', context);
  assert.equal(elements.wdttLabel.value, 'Unsaved name');
  elements.wdttLabel.value = wdttUser.label;
  elements.wdttForm.handlers.submit({ preventDefault() {} });
  await settle();
  const update = calls.find(c => c.url === '/api/wdtt/user' && JSON.parse(c.options.body).operation === 'update');
  assert.equal(JSON.parse(update.options.body).shared, true);
  assert.equal(update.options.headers['X-CSRF-Token'], 'test-csrf');
  rejectWdtt = true;
  await vm.runInContext("wdttAction('activate')", context);
  assert.equal(elements.wdttError.textContent, 'Срок истёк');
  rejectWdtt = false;
  elements.wdttSearch.value = 'missing';
  elements.wdttSearch.handlers.input();
  assert.match(elements.wdttSummary.textContent, /показано: 0/);
  state.busy = false;
  state.egress = { mode: 'warp', origin: 'manual', configured: true, fallback_enabled: true,
    warp: { healthy: true, ip: '1.1.1.1', latency: 42, checked: 1000 } };
  await vm.runInContext('status()', context);
  assert.equal(elements.activeSource.textContent, 'Cloudflare WARP');
  assert.match(elements.warpStatus.textContent, /42 мс/);
  assert.equal(elements.egressWarp.disabled, true);
  assert.equal(elements.egressSubscriptions.disabled, false);
  assert(elements.connections.querySelectorAll().filter(b => b.dataset.action === 'select').every(b => b.disabled));
  elements.warpCheck.handlers.click();
  await settle();
  assert(calls.some(c => c.url === '/api/warp-check' && c.options.headers['X-CSRF-Token'] === 'test-csrf'));
  await vm.runInContext('status()', context);
  elements.egressSubscriptions.handlers.click();
  await settle();
  assert(calls.some(c => c.url === '/api/egress' && JSON.parse(c.options.body).mode === 'subscriptions'));
  state.egress.warp = { healthy: false, error: '<script>blocked</script>', checked: 1000 };
  await vm.runInContext('status()', context);
  assert.match(elements.warpStatus.textContent, /WARP недоступен/);
  assert.match(elements.warpStatus.textContent, /<script>blocked<\/script>/);
  elements.warpFallback.handlers.click();
  await settle();
  assert(calls.some(c => c.url === '/api/warp-settings' && JSON.parse(c.options.body).enabled === false));
  state.busy = true;
  await vm.runInContext('status()', context);
  for (const id of ['egressSubscriptions', 'egressWarp', 'warpCheck', 'warpFallback']) assert.equal(elements[id].disabled, true);
  state.busy = false;
  rejectSession = true;
  await vm.runInContext('status(true)', context);
  assert.equal(elements.login.hidden, false);
  assert.equal(elements.panel.hidden, true);
  assert.equal(elements.wdttSecret.value, '');
  assert.equal(elements.wdttLink.value, '');
  assert.equal(elements.wdttUsers.children.length, 0);
  assert.match(elements.error.textContent, /Вход не сохранился/);
  console.log('Panel UI: catalog, editing, per-source probes, filters, selection, CSRF, busy-state and login passed');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
