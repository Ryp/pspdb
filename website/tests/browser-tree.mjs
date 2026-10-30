// Real-browser check of the viewer against a served catalog. With PSPDB served on
// :8000 and Chromium started with --remote-debugging-port=9333:
//   node website/tests/browser-tree.mjs
// PSPDB_SITE_URL / PSPDB_DEBUG_URL override the site and the DevTools endpoint;
// PSPDB_BROWSER_QUICK=1 skips the exhaustive first sweep over all 7.6 M rows (minutes).
// Each check runs inside the page against the live typed-array occurrence tree.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {encodeFixture} from './viewer-support.mjs';

const site = process.env.PSPDB_SITE_URL || 'http://127.0.0.1:8000';
const pages = await (await fetch((process.env.PSPDB_DEBUG_URL || 'http://127.0.0.1:9333') + '/json')).json();
const ws = new WebSocket(pages.find(t => t.type === 'page').webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r, {once: true}));
let next = 0;
const pending = new Map();
ws.addEventListener('message', e => { const m = JSON.parse(e.data); if (m.id) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.reject(m.error) : p.resolve(m.result); } });
const cmd = (method, params = {}) => new Promise((resolve, reject) => { const id = ++next; pending.set(id, {resolve, reject}); ws.send(JSON.stringify({id, method, params})); });
async function evaluate(expression) {
  const r = await cmd('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true});
  if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails.exception?.description ?? r.exceptionDetails));
  return r.result.value;
}
// Run a function in the page; arguments are passed as JSON.
const inPage = (fn, ...args) => evaluate(`(${fn})(...${JSON.stringify(args)})`);
async function load(url = site) {
  // Always a fresh document: navigating between URLs that differ only by hash would not reload.
  await cmd('Page.navigate', {url: 'about:blank'});
  await cmd('Page.navigate', {url});
  for (let i = 0; i < 1200; i++) {
    if (await evaluate('!!document.querySelector("#browser:not([hidden]) tr.node")')) break;
    await new Promise(r => setTimeout(r, 50));
  }
}
await cmd('Page.enable'); await cmd('Runtime.enable');
await cmd('Emulation.setDeviceMetricsOverride', {width: 1440, height: 940, deviceScaleFactor: 1, mobile: false});
await load();

const result = process.env.PSPDB_BROWSER_QUICK ? {rows: 1, result: 'SKIP: exhaustive tree sweep (PSPDB_BROWSER_QUICK)'} : await inPage(async () => {
  const check = (value, message) => { if (!value) throw new Error(message); };
  await searchReady;
  const C = catalog, N = C.count;
  const descendantsOf = node => { const out = []; for (let i = node + 1; i < C.end[node]; i++) out.push(i); return out; };
  const collapsedKey = () => { const out = []; for (let i = 0; i < N; i++) if (collapsed[i]) out.push(i); return out.join('|'); };
  const find = predicate => { for (let i = 0; i < N; i++) if (predicate(i)) return i; return -1; };
  const rowOf = node => rows.get(node)?.row;
  const press = key => document.dispatchEvent(new KeyboardEvent('keydown', {key, bubbles: true}));
  check(document.querySelector('header').getBoundingClientRect().height <= 48, 'Compact header');
  check(!document.querySelector('header button:not(#clear-search), .brand-dot, .subtitle'), 'Header decorations and bulk controls removed');
  check(document.querySelector('header .search-bar'), 'Search lives in the header');
  check(visible.every(n => C.isVirtual(n)), 'Initially show only virtual groups, not source files');
  for (const group of visible.filter(n => C.isVirtual(n) && C.parent[n] >= 0 && !C.children(n).some(child => C.isVirtual(child)))) {
    check(rowOf(group).getAttribute('aria-expanded') === 'false', 'Leaf virtual groups start folded');
    check(C.children(group).every(child => !visible.includes(child)), 'Folded group hides source rows');
  }
  for (let i = 0; i < N; i++) {
    if (!C.isFile(i) && !C.isVirtual(i)) check(!collapsed[i], 'Real inventory folders remain expanded by default');
    if (C.isContainer(i)) check(collapsed[i], 'Extracted files collapsed locally by default');
  }
  for (const item of Array.from(C.attrs.keys()).filter(n => C.attrsOf(n).displayName && C.isContainer(n))) {
    jump(item);
    press('l');
    const descendants = descendantsOf(item);
    check(C.children(item).every(n => visible.includes(n)), 'Opening source reveals contents');
    for (const nested of descendants.filter(n => C.isContainer(n))) {
      check(collapsed[nested], 'Opening parent keeps nested extracted files collapsed');
      check(C.children(nested).every(n => !visible.includes(n)), 'Nested extracted contents stay hidden');
    }
    const nestedFolder = descendants.find(n => !C.isFile(n) && C.hasChildren(n));
    if (nestedFolder !== undefined) {
      toggle(nestedFolder); toggle(item); toggle(item);
      check(collapsed[nestedFolder] && C.children(nestedFolder).every(n => !visible.includes(n)), 'Reopening preserves nested collapse choices');
    }
  }
  collapsed.fill(0); render(); select(selected >= 0 ? selected : visible[0]);
  check(formatSize(0) === '0 B' && formatSize(1023) === '1,020 B', 'Rounded byte sizes');
  check(formatSize(1024) === '1 KiB' && formatSize(1536) === '1.5 KiB', 'Binary size conversion');
  check(formatSize(1024 ** 2) === '1 MiB' && formatSize(1024 ** 3) === '1 GiB', 'Larger units');
  check(formatSize(123.456 * 1024 ** 2) === '123 MiB' && formatSize(12.3456 * 1024 ** 2) === '12.3 MiB', 'Three significant digits');
  const sizeNode = find(n => C.isFile(n) && C.size[n] > 1024);
  jump(sizeNode);
  check(rowOf(sizeNode).querySelector('.size').textContent === formatSize(C.size[sizeNode]), 'Rendered readable sizes');
  check(rowOf(sizeNode).querySelector('.size').title === number.format(C.size[sizeNode]) + ' bytes', 'Exact byte tooltip');
  const initial = visible.length;
  const branch = find(n => C.depth(n) > 3 && C.children(n).some(c => !C.isFile(c) && C.children(c).length > 3));
  const nested = C.children(branch).find(c => !C.isFile(c) && C.children(c).length > 3);
  const leaf = C.children(nested)[0];
  jump(nested);
  rowOf(nested).querySelector('.toggle').click();
  check(collapsed[nested], 'Nested folder should collapse');
  check(!visible.includes(leaf), 'Nested contents should hide');
  jump(branch); rowOf(branch).querySelector('.toggle').click();
  check(!visible.includes(nested), 'Parent should hide nested folder');
  rowOf(branch).querySelector('.toggle').click();
  check(visible.includes(nested), 'Parent should restore nested folder');
  check(!visible.includes(leaf), 'Nested collapse state must survive parent toggle');
  jump(nested);
  check(rowOf(nested).getAttribute('aria-expanded') === 'false', 'Disclosure aria state');
  select(nested);
  press('j');
  check(!rowOf(selected).hidden && selected !== leaf, 'j must skip hidden descendants');
  for (let i = 0; i < N; i++) if (C.expandable(i)) collapsed[i] = 1;
  render(); select(visible[0]);
  check(visible.length === 1 && selected === 0, 'Collapse all retains the aggregate root');
  press('h');
  check(selected === visible[0], 'Top-level boundary');
  jump(leaf);
  check(!rowOf(leaf).hidden, 'Jump must reveal collapsed ancestors');
  check(document.getElementById('tree').getAttribute('aria-activedescendant') === `node-${leaf}`, 'Active row');
  check(![...rows.values()].some(p => p.row.querySelector('a:not(.download-link):not(.redump-link):not(.umdatabase-link):not(.serialstation-link):not(.coverage-chip)')), 'No cross-tree links');
  for (const node of Array.from(C.attrs.keys()).filter(n => (C.attrsOf(n).redump || []).length)) {
    jump(node);
    const matches = C.attrsOf(node).redump;
    const links = [...rowOf(node).querySelectorAll('.redump-link')];
    check(links.length === matches.length, 'Exact matches appear on ISO rows');
    links.forEach((link, i) => {
      check(link.href === 'http://redump.org/disc/' + matches[i].id + '/', 'Numeric Redump URL');
      check(link.target === '_blank' && link.rel.includes('noopener'), 'External link isolation');
      const before = selected;
      link.addEventListener('click', event => event.preventDefault(), {once: true});
      link.click();
      check(selected === before, 'Redump click does not select or toggle tree');
    });
  }
  for (const node of Array.from(C.attrs.keys()).filter(n => C.attrsOf(n).serialstation)) {
    jump(node);
    const link = rowOf(node).querySelector('.serialstation-link');
    check(link.href === 'https://serialstation.com/pkgs/' + C.attrsOf(node).serialstation.id + '/', 'SerialStation package UUID URL');
    check(link.target === '_blank' && link.rel.includes('noopener'), 'SerialStation external link isolation');
    const before = selected;
    link.addEventListener('click', event => event.preventDefault(), {once: true});
    link.click();
    check(selected === before, 'SerialStation click preserves selection');
  }
  const games = C.children(C.find('umd/game'));
  check(games.every(n => !(C.attrsOf(n)?.redump || []).length), 'UMD rows never link Redump directly');
  for (const node of games.filter(n => (C.attrsOf(n)?.serialstation_discs || []).length).slice(0, 3)) {
    jump(node);
    const discs = C.attrsOf(node).serialstation_discs;
    const links = [...rowOf(node).querySelectorAll('.serialstation-link')];
    check(links.length === discs.length && links.every((link, i) => link.href === 'https://serialstation.com/discs/' + discs[i].id), 'SerialStation disc UUID URL');
  }
  for (const node of Array.from(C.attrs.keys()).filter(n => (C.attrsOf(n).umdatabase || []).length)) {
    jump(node);
    const matches = C.attrsOf(node).umdatabase;
    const links = [...rowOf(node).querySelectorAll('.umdatabase-link')];
    check(links.length === matches.length, 'UMDatabase matches appear on ISO rows');
    links.forEach((link, i) => {
      check(link.href === 'https://umdatabase.net/view.php?id=' + matches[i].id, 'UMDatabase entry URL');
      check(link.target === '_blank' && link.rel.includes('noopener'), 'UMDatabase external link isolation');
      const before = selected;
      link.addEventListener('click', event => event.preventDefault(), {once: true});
      link.click();
      check(selected === before, 'UMDatabase link does not toggle or select the ISO');
    });
  }
  check(C.path(0) === '' && url(0) === '#', 'Aggregate root preserves category URL paths');
  check(C.children(0).every(n => C.depth(n) === 1), 'Categories are children of the aggregate root');

  collapsed.fill(0); render(); select(selected >= 0 ? selected : visible[0]);
  check(visible.length === initial, 'Expand all restores every row');
  check(Array.from(rows.values()).every(p => !p.row.hidden), 'All expanded rows displayed');
  check(Number(document.getElementById('tree').getAttribute('aria-rowcount')) === visible.length + 1, 'Accessible row count');
  const search = document.getElementById('tree-search');
  const query = async value => { search.value = value; search.dispatchEvent(new Event('input', {bubbles: true})); await searchSettled; };
  jump(nested); toggle(nested);
  const before = {selected, collapsed: collapsedKey(), scroll: document.getElementById('table-scroll').scrollTop};
  await query('EBOOT.BIN');
  check(document.querySelector('header').getBoundingClientRect().height <= 48, 'Match count stays inline without growing the header');
  check(visible.some(n => C.isFile(n) && C.nameOf(n) === 'EBOOT.BIN'), 'Find files in collapsed branches');
  check(visible.every(n => C.isFile(n) && C.displayPath(n).toLowerCase().includes('eboot.bin')), 'Flat results contain matching files without ancestor rows');
  const resultNode = visible[0], resultRow = rowOf(resultNode);
  const resultAncestors = []; for (let node = C.parent[resultNode]; node > 0; node = C.parent[node]) resultAncestors.push(node);
  check(rows.get(resultNode).name.textContent === C.displayPath(resultNode) && resultAncestors.some(n => C.attrsOf(n)?.displayName && C.displayPath(resultNode).includes(label(n))), 'One-line path uses readable ISO label');
  check(resultRow.getAttribute('aria-level') === '1', 'Flat result accessibility level');
  check(getComputedStyle(resultRow.querySelector('.name-cell')).paddingLeft === '12px', 'Flat results have no tree indentation');
  check(document.querySelectorAll('mark').length > 0, 'Highlight matches');
  const sourceTerms = label(resultAncestors.find(n => C.attrsOf(n)?.displayName)).toLowerCase().split(/\s+/).filter(term => !/^[0-9a-f]{8,64}$/.test(term));
  const sourceTitle = sourceTerms.join(' ');
  await query(sourceTitle.toUpperCase() + ' EBOOT');
  check(visible.some(n => C.isFile(n)), 'Combined title and filename query');
  check(visible.every(n => sourceTerms.every(term => C.displayPath(n).toLowerCase().includes(term)) && C.displayPath(n).toLowerCase().includes('eboot')), 'AND matching across ancestor title and filename');
  const file = visible.find(n => C.isFile(n)); select(file);
  press('l');
  check(selected === file, 'Flat results do not navigate to hidden tree nodes');
  await query(sourceTitle.toUpperCase());
  check(visible.filter(n => C.isFile(n)).length > 1, 'Game match includes contents');
  const collator = new Intl.Collator('en', {numeric: true, sensitivity: 'base'});
  const prefixOf = n => C.slot[n] >= 0 ? C.prefixHex(n, 16) : '';
  const orderChecks = {name: (a, b) => collator.compare(label(a), label(b)), size: (a, b) => C.size[a] - C.size[b], hash: (a, b) => prefixOf(a).localeCompare(prefixOf(b))};
  const pathsOf = () => Array.from(visible, n => C.path(n));
  const defaultPaths = pathsOf().join('|');
  check(['name', 'size', 'hash'].every(key => !document.getElementById('sort-' + key).querySelector('span').textContent), 'Default sorting has no icons');
  const matchingPaths = pathsOf().sort().join('|');
  for (const key of ['size', 'hash', 'name']) {
    const button = document.getElementById('sort-' + key);
    check(!button.disabled, 'Search enables sorting');
    button.click(); await searchSettled;
    check(visible.every((n, i) => !i || orderChecks[key](visible[i - 1], n) <= 0), 'Ascending ' + key + ' order');
    check(document.getElementById('heading-' + key).getAttribute('aria-sort') === 'ascending', 'Accessible ascending sort');
    button.click(); await searchSettled;
    check(visible.every((n, i) => !i || orderChecks[key](visible[i - 1], n) >= 0), 'Descending ' + key + ' order');
    check(document.getElementById('heading-' + key).getAttribute('aria-sort') === 'descending', 'Accessible descending sort');
    check(pathsOf().sort().join('|') === matchingPaths, 'Sorting preserves matching occurrences');
    button.click(); await searchSettled;
    check(pathsOf().join('|') === defaultPaths, 'Third click restores default order');
    check(['name', 'size', 'hash'].every(k => !document.getElementById('sort-' + k).querySelector('span').textContent), 'Default order clears every sort icon');
    check(document.getElementById('heading-' + key).getAttribute('aria-sort') === 'none', 'Accessible default sort');
  }
  check(selected === file, 'Sorting preserves selection');
  // Hash terms are prefix-anchored; digits past the 8-byte prefix are verified against fetched digests.
  const fileHash = await fullHash(file);
  await query(fileHash);
  check(visible.includes(file), 'Full hash search');
  await query(fileHash.toUpperCase());
  check(visible.includes(file), 'Case-insensitive hash search');
  await query(fileHash.slice(0, 12));
  check(visible.includes(file), 'Short hash search');
  await query(fileHash.slice(0, 24));
  check(visible.includes(file), 'Hash search past the stored prefix is verified against full digests');
  await query(fileHash.slice(0, 63) + (fileHash.endsWith('0') ? '1' : '0'));
  check(visible.length === 0, 'A long hash with a wrong tail matches nothing');
  await query(fileHash.slice(2, 14));
  check(visible.length === 0, 'Hash terms are anchored at the start of the digest');
  const container = find(n => C.knownHash(n) && C.hasChildren(n) && C.nameOf(n).includes(C.knownHash(n)));
  const containerHash = C.knownHash(container);
  const exactOccurrences = []; for (let i = 0; i < N; i++) if (C.isFile(i) && C.slot[i] === C.slot[container]) exactOccurrences.push(i);
  await query(containerHash);
  check(visible.length === exactOccurrences.length && exactOccurrences.every(n => visible.includes(n)), 'Container hash finds only exact file occurrences, not descendants');
  await query(containerHash.slice(0, 12).toUpperCase());
  check(visible.includes(container) && visible.every(n => C.prefixHex(n, 12) === containerHash.slice(0, 12)), 'Short container hash excludes inherited subtree matches');
  await query(containerHash);
  await query(C.nameOf(container));
  check(descendantsOf(container).filter(n => C.isFile(n)).every(n => visible.includes(n)), 'Changing hash query to filename restores ancestor-text matching');
  const folder = find(n => C.nameOf(n) === 'SYSDIR' && C.hasChildren(n));
  await query('SYSDIR');
  check(C.children(folder).filter(n => C.isFile(n)).every(n => visible.includes(n)) && !visible.includes(folder), 'Folder query lists contained files without a folder row');
  await query('<img src=x onerror=alert(1)>');
  check(visible.length === 0 && !document.getElementById('search-empty').hidden, 'Empty state');
  check(!document.getElementById('search-empty').querySelector('img'), 'Query rendered as text');
  press('j');
  search.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape', bubbles: true}));
  check(document.getElementById('sort-size').disabled, 'Tree mode disables search sorting');
  check(selected === before.selected, 'Clear restores selection');
  check(!document.getElementById('tree').classList.contains('search-results'), 'Clear restores tree presentation');
  check(rows.get(selected).name.textContent === label(selected), 'Clear restores short names');
  check(collapsedKey() === before.collapsed, 'Clear restores expansion');
  check(document.getElementById('table-scroll').scrollTop === before.scroll, 'Clear restores scroll');
  check(document.querySelectorAll('mark').length === 0, 'Clear removes highlights');
  press('/');
  check(document.activeElement === search, 'Slash focuses search');
  await query('eboot');
  search.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true}));
  check(document.activeElement === document.getElementById('tree'), 'Enter returns to navigation');
  document.getElementById('clear-search').click();
  for (const target of [file, find(n => C.isContainer(n) && C.parent[n] !== 0)]) {
    for (let i = 0; i < N; i++) if (C.expandable(i)) collapsed[i] = 1;
    render(); select(visible[0]);
    const beforeJump = collapsed.slice();
    await query(await fullHash(target));
    document.getElementById('sort-size').click(); await searchSettled;
    select(target);
    rows.get(target).hash.dispatchEvent(new MouseEvent('dblclick', {bubbles: true}));
    check(filterNodes !== null, 'Double-clicking the hash button preserves search');
    // Large catalogs exercise hundreds of jumps above; browsers may rate-limit
    // history updates. Check the requested URL without relying on that quota.
    const replaceState = history.replaceState; let destination;
    history.replaceState = function (...args) { destination = args[2]; return replaceState.apply(this, args); };
    try { rows.get(target).name.dispatchEvent(new MouseEvent('dblclick', {bubbles: true})); }
    finally { history.replaceState = replaceState; }
    check(search.value === '' && filterNodes === null && savedTree === null, 'Double-click leaves search');
    check(selected === target, 'Double-click selects the exact occurrence, even with shared hashes');
    check(document.activeElement === document.getElementById('tree'), 'Double-click focuses tree navigation');
    check(destination === url(target), 'Double-click updates the selected item URL');
    const ancestors = new Set();
    for (let parent = C.parent[target]; parent >= 0; parent = C.parent[parent]) ancestors.add(parent);
    check([...ancestors].every(p => !collapsed[p]), 'Double-click reveals every ancestor');
    for (let i = 0; i < N; i++) if (beforeJump[i] && !ancestors.has(i)) check(collapsed[i], 'Double-click preserves other collapse choices, including the target');
    const rect = rowOf(target).getBoundingClientRect();
    check(rect.top >= document.querySelector('thead').getBoundingClientRect().bottom - 1 && rect.bottom <= document.getElementById('table-scroll').getBoundingClientRect().bottom + 1, 'Double-click scrolls the selected row into view');
    check(rowOf(target).getAttribute('aria-selected') === 'true', 'Double-click announces selection');
  }
  collapsed.fill(0); render(); select(selected >= 0 ? selected : visible[0]);
  document.getElementById('tree').focus();
  press('End');
  check(selected === visible[visible.length - 1] && rowOf(selected).isConnected, 'End mounts last row');
  const lastRect = rowOf(selected).getBoundingClientRect();
  const hostRect = document.getElementById('table-scroll').getBoundingClientRect();
  check(lastRect.bottom <= hostRect.bottom + 1 && lastRect.top >= hostRect.top, 'Last row scrolls into view');
  check(document.querySelectorAll('tr.node').length < 150, 'Viewport limits mounted rows');
  check(Math.abs(lastRect.height - 21) < 0.1, 'Virtual row height matches layout');
  press('Home');
  check(selected === visible[0] && rowOf(selected).isConnected, 'Home mounts first row');
  const topRect = rowOf(selected).getBoundingClientRect();
  check(topRect.top >= document.querySelector('thead').getBoundingClientRect().bottom - 1, 'First row below sticky header');
  return {rows: initial, nodes: N, files: C.files, result: 'PASS: nested fold state, hidden-row keyboard skipping, root boundary, jump reveal, expand/collapse all, aria state, async search, title/path/hash matching, filtered navigation, empty state, search shortcuts and restoration'};
});
assert.ok(result.rows > 0);
console.log(JSON.stringify(result));

// Digests are fetched lazily: a catalog browse reads a handful of 128 KiB chunks, not the 40 MB table.
const chunks = await evaluate(`performance.getEntriesByType('resource').filter(e => /\\/hashes\\/|api\\/hashes/.test(e.name)).map(e => [e.name.split('/').slice(-2).join('/'), e.decodedBodySize])`);
assert.ok(chunks.every(([, size]) => size <= 4096 * 32), 'chunks never exceed 4096 digests');
console.log(`PASS: ${chunks.length} digest chunk(s) fetched for the whole session`);

const download = await inPage(async () => {
  const untilDownload = async node => {
    // A busy store can exceed the 15 s check deadline; the page then says "Check failed" and a new check may be asked for.
    for (let i = 0, failures = 0; i < 1200 && !rows.get(node).download.querySelector('a'); i++) {
      if (rows.get(node).download.textContent === 'Check failed' && failures++ < 3) { availability.delete(hashOf(node)); refreshDownloads(); }
      await new Promise(r => setTimeout(r, 50));
    }
  };
  if (!downloadsEnabled) {
    if (!document.getElementById('download-heading').hidden) throw new Error('Download heading should be hidden');
    return null;
  }
  if (document.getElementById('download-heading').hidden) throw new Error('Download heading missing');
  let file = -1;
  for (let i = 0; i < catalog.count && file < 0; i++) if (catalog.isFile(i) && catalog.size[i] > 0 && catalog.size[i] < 100000 && catalog.nameOf(i).endsWith('.PNG')) file = i;
  jump(file);
  await untilDownload(file);
  const link = rows.get(file).download.querySelector('a');
  if (!link || link.download !== catalog.nameOf(file)) throw new Error('Missing download or wrong filename');
  if (rows.get(file).row.children.length !== 4) throw new Error('Download column missing');
  if ([...rows.values()].some(p => p.row.classList.contains('folder') && p.row.querySelector('.download-link'))) throw new Error('Folder download link');
  return {url: link.href, hash: await fullHash(file), size: catalog.size[file], name: catalog.nameOf(file)};
});
if (download) {
  const response = await fetch(download.url);
  assert.equal(response.status, 200);
  const bytes = Buffer.from(await response.arrayBuffer());
  assert.equal(bytes.length, download.size);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), download.hash);
  assert.ok(response.headers.get('content-disposition').includes('attachment;'));
  console.log('PASS: live store download matches catalog SHA-256 and size, filename preserved (digest resolved through its chunk)');
}
const extractedDownload = await inPage(async () => {
  const untilDownload = async node => {
    // A busy store can exceed the 15 s check deadline; the page then says "Check failed" and a new check may be asked for.
    for (let i = 0, failures = 0; i < 1200 && !rows.get(node).download.querySelector('a'); i++) {
      if (rows.get(node).download.textContent === 'Check failed' && failures++ < 3) { availability.delete(hashOf(node)); refreshDownloads(); }
      await new Promise(r => setTimeout(r, 50));
    }
  };
  const sources = []; for (let i = 0; i < catalog.count; i++) if (catalog.isContainer(i)) sources.push(i);
  if (!sources.length) return null;
  for (let i = 0; i < catalog.count; i++) if (catalog.expandable(i)) collapsed[i] = 1;
  render(); select(visible[0]);
  // Prefer a source whose contents include a hashed file with a store copy to download.
  const source = sources[0]; jump(source);
  const row = rows.get(source).row;
  if (!row.classList.contains('file') || !row.classList.contains('container')) throw new Error('Extractable file styling');
  if (row.querySelector('.size').textContent !== formatSize(catalog.size[source])) throw new Error('Source size must remain exact');
  const first = catalog.children(source)[0];
  document.dispatchEvent(new KeyboardEvent('keydown', {key: 'ArrowRight', bubbles: true}));
  if (collapsed[source] || (first !== undefined && !visible.includes(first))) throw new Error('Cannot expand extracted file');
  document.dispatchEvent(new KeyboardEvent('keydown', {key: 'ArrowLeft', bubbles: true}));
  if (!collapsed[source] || (first !== undefined && visible.includes(first))) throw new Error('Cannot collapse extracted file');
  let child = -1;
  for (let i = source + 1; i < catalog.end[source] && child < 0; i++) if (catalog.isFile(i) && !catalog.isContainer(i) && catalog.size[i] > 0 && catalog.slot[i] >= 0) child = i;
  const childHash = await fullHash(child);
  document.getElementById('tree-search').value = childHash; await applySearch();
  if (!visible.includes(child)) throw new Error('Extracted hash search');
  clearSearch(); jump(child);
  if (!downloadsEnabled) return null;
  await untilDownload(child);
  const link = rows.get(child).download.querySelector('a');
  if (!link || link.download !== catalog.nameOf(child)) throw new Error('Extracted file download missing');
  return {url: link.href, hash: childHash, size: catalog.size[child], occurrences: sources.length};
});
if (extractedDownload) {
  const response = await fetch(extractedDownload.url);
  assert.equal(response.status, 200);
  const bytes = Buffer.from(await response.arrayBuffer());
  assert.equal(bytes.length, extractedDownload.size);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), extractedDownload.hash);
  console.log('PASS: extraction styling, exact source size, keyboard folding, hash search and verified child download; occurrences=' + extractedDownload.occurrences);
}
const availabilityTimeout = await inPage(async () => {
  if (!downloadsEnabled) return 'SKIP: store not configured';
  let file = -1;
  for (let i = 0; i < catalog.count && file < 0; i++) if (catalog.isFile(i) && catalog.slot[i] >= 0) file = i;
  const hash = await fullHash(file);
  const originalFetch = window.fetch;
  window.fetch = (url, options) => String(url).startsWith('api/availability?')
    ? new Promise((resolve, reject) => options?.signal?.addEventListener('abort', () => reject(options.signal.reason), {once: true}))
    : originalFetch(url, options);
  try {
    availability.delete(hash);
    jump(file);
    refreshDownloads();
    for (let i = 0; i < 400 && rows.get(file).download.textContent !== 'Check failed'; i++) await new Promise(r => setTimeout(r, 50));
    if (rows.get(file).download.textContent !== 'Check failed') throw new Error('Stalled store check never settled');
  } finally {
    window.fetch = originalFetch;
  }
  availability.delete(hash);
  await refreshDownloads();
  if (!['Download', 'Missing'].includes(rows.get(file).download.textContent)) throw new Error('Store checks did not resume after timeout');
  return 'PASS: stalled store checks report failure and subsequent real checks complete';
});
console.log(availabilityTimeout);

// Copy goes through the chunk fetch: a row whose digest is not loaded yet still copies the exact SHA-256.
const copied = await inPage(async () => {
  const written = [];
  navigator.clipboard.writeText = async text => { written.push(text); };
  let target = -1;
  for (let i = catalog.count - 1; i > 0 && target < 0; i--) if (catalog.isFile(i) && catalog.slot[i] >= 0 && !hashOf(i)) target = i;
  const chunk = Math.floor(catalog.slot[target] / 4096);
  const loaded = hashStore.loaded.has(chunk);
  jump(target);
  document.getElementById('copy-selected').click();
  for (let i = 0; i < 100 && !written.length; i++) await new Promise(r => setTimeout(r, 50));
  const full = hashOf(target);
  if (written[0] !== full || !/^[0-9a-f]{64}$/.test(full) || !full.startsWith(catalog.prefixHex(target, 16))) throw new Error('Copy hash mismatch');
  if (document.getElementById('notice').textContent !== 'SHA-256 copied') throw new Error('Missing copy notice');
  // The row button copies too, and shows the prefix only.
  const button = rows.get(target).hash;
  if (button.textContent !== full.slice(0, 12) || !button.title.startsWith(full)) throw new Error('Hash column shows the first 12 hex digits');
  written.length = 0; button.click();
  for (let i = 0; i < 100 && !written.length; i++) await new Promise(r => setTimeout(r, 50));
  if (written[0] !== full) throw new Error('Row copy mismatch');
  return {chunk, loadedBefore: loaded};
});
console.log('PASS: copy hash resolves the full digest lazily (chunk ' + copied.chunk + (copied.loadedBefore ? ', already cached)' : ', fetched on demand)'));

const extractionErrors = await (async () => {
  const packageHash = 'a'.repeat(64), edatHash = 'b'.repeat(64), inlineHash = 'c'.repeat(64), childHash = 'd'.repeat(64), nestedHash = 'e'.repeat(64), deepHash = 'f'.repeat(64);
  const hostile = '<img src=x onerror=alert(1)> ' + 'long-error-detail-'.repeat(150);
  const file = (path, hash, extra = {}) => ({path, type: 'file', sha256: hash, size_bytes: 10, ...extra});
  const tree = (hash, entries, error) => ({sha256: hash, size_bytes: 10, extractor: {name: 'extractor', version: '1'}, entries, ...(error ? {error} : {})});
  const fixture = {records: {pkg: [{sha256: packageHash, size_bytes: 10, metadata: {title: 'Error visibility'}}]}, trees: {
    pkg: {[packageHash]: tree(packageHash, [
      file('ISO.BIN.EDAT', edatHash),
      file('DATA.PSP', inlineHash, {extraction: tree(inlineHash, [file('decoded.bin', childHash)], hostile)}),
      file('NESTED.PSP', nestedHash, {extraction: tree(nestedHash, [file('inner/ISO.BIN.EDAT', deepHash)])}),
      file('UNCHANGED.PSP', inlineHash),
      ...Array.from({length: 200}, (_, i) => file('sibling-' + String(i).padStart(3, '0') + '.bin', childHash)),
    ], 'Partial package extraction')},
    edat: {[edatHash]: tree(edatHash, [], 'UnsupportedEdat'), [deepHash]: tree(deepHash, [], 'MissingEdatRap')},
  }};
  const bytes = Buffer.from(encodeFixture(fixture).bytes).toString('base64');
  return inPage(async (base64, packageHash, hostile) => {
    const check = (value, message) => { if (!value) throw new Error(message); };
    const C0 = PspdbCatalog;
    clearSearch();
    await build(C0.buildCatalog(C0.parseContainer(Uint8Array.from(atob(base64), c => c.charCodeAt(0)))));
    await searchReady;
    const C = catalog;
    for (let i = 0; i < C.count; i++) if (C.isContainer(i)) collapsed[i] = 1;
    render();
    const rowOf = node => rows.get(node)?.row;
    let pkg = -1; for (let i = 0; i < C.count; i++) if (C.knownHash(i) === packageHash) pkg = i;
    const named = (node, name) => C.children(node).find(n => C.nameOf(n) === name);
    const edat = named(pkg, 'ISO.BIN.EDAT'), inline = named(pkg, 'DATA.PSP'), sibling = named(pkg, 'UNCHANGED.PSP');
    for (const node of [pkg, edat, inline]) {
      jump(node);
      const row = rowOf(node), diagnostic = row.querySelector('.extraction-error');
      const error = C.extraction(node).error;
      check(diagnostic && diagnostic.getBoundingClientRect().width > 0, 'Error is visible on its source row');
      check(diagnostic.querySelector('.error-icon').getAttribute('aria-hidden') === 'true', 'Error icon does not duplicate accessible text');
      check(document.getElementById(row.getAttribute('aria-describedby')).textContent.includes(error), 'Accessible source error');
      check(!document.getElementById('selected-error').hidden && document.getElementById('selected-error-message').textContent.includes(error), 'Selected source shows full error without hover');
      check(Math.abs(row.getBoundingClientRect().height - 21) < 0.1, 'Errors preserve virtual row height');
    }
    check(!rowOf(sibling).querySelector('.extraction-error'), 'Inline failure does not leak to same-hash sibling');
    check(!document.querySelector('.extraction-error img, #selected-error img'), 'Error HTML stays inert text');
    check(document.getElementById('selected-error-message').textContent.includes(hostile), 'Long error is not truncated in selection details');
    const panel = document.getElementById('selected-error');
    check(panel.scrollWidth <= panel.clientWidth + 1, 'Long errors wrap within the selected panel');
    panel.focus();
    panel.dispatchEvent(new KeyboardEvent('keydown', {key: 'ArrowDown', bubbles: true}));
    check(selected === inline, 'Error detail scrolling does not navigate the tree');
    toggle(inline);
    check(visible.includes(C.children(inline)[0]), 'Trustworthy children remain navigable after failure');
    const children = C.children(pkg);
    jump(children[children.length - 1]);
    check(!rowOf(edat)?.isConnected, 'Distant failed source is virtualized');
    document.getElementById('tree-search').value = 'UnsupportedEdat'; await applySearch();
    check(visible.length === 1 && visible[0] === edat, 'Error search finds an empty failed extraction');
    check(rowOf(edat).querySelector('.error-message mark')?.textContent === 'UnsupportedEdat', 'Error matches highlight after remount');
    check(!document.getElementById('selected-error').hidden, 'Search selection retains full error details');
    const input = document.getElementById('tree-search');
    input.value = 'sibling'; const superseded = applySearch();
    input.value = 'UnsupportedEdat'; await applySearch(); await superseded;
    check(visible.length === 1 && visible[0] === edat, 'Older worker results never replace newer input');
    input.value = 'sibling'; const cancelled = applySearch(); clearSearch(); await cancelled;
    // Wait for a later worker reply to prove pending work cannot overwrite clear.
    const worker = searchWorker, handler = worker.onmessage;
    await new Promise(resolve => {
      worker.onmessage = event => {
        if (event.data.type === 'results' && event.data.version === searchVersion) { worker.onmessage = handler; resolve(); }
        else handler(event);
      };
      worker.postMessage({type: 'search', version: searchVersion, terms: ['sibling'], sort: null, direction: 1});
    });
    check(filterNodes === null && input.value === '' && !document.getElementById('tree').classList.contains('search-results'), 'Cleared search remains in tree mode after pending results settle');
    clearSearch(); jump(sibling);
    check(document.getElementById('selected-error').hidden, 'Successful selection clears error details');
    const nested = named(pkg, 'NESTED.PSP');
    jump(nested);
    const contained = rowOf(nested).querySelector('.extraction-error.contained');
    check(contained && contained.getBoundingClientRect().width > 0, 'Collapsed container shows that it contains a failure');
    check(!C.extraction(nested).error && contained.querySelector('.error-message') === null, 'Contained badge is icon-only, with no borrowed message');
    check(contained.title.includes('1') && contained.getAttribute('aria-label') === contained.title, 'Contained badge announces how many failures it hides');
    check(document.getElementById('selected-error').hidden, 'A container that only contains failures has no error of its own');
    toggle(nested);
    const innerDirectory = C.children(nested).find(n => C.nameOf(n) === 'inner');
    check(!rowOf(innerDirectory)?.querySelector('.extraction-error'), 'Plain directories do not repeat the contained badge');
    return 'PASS: source-scoped errors, contained-failure badges, empty failures, partial children, inert long text, accessibility, search and virtual remount';
  }, bytes, packageHash, hostile);
})();
console.log(extractionErrors);

// Earlier blocks rebuilt the tree from fixtures; coverage needs the served catalog.
await load();
const views = await inPage(async () => {
  const check = (value, message) => { if (!value) throw new Error(message); };
  const C = catalog;
  check(!document.querySelector('[role="tablist"], #view-browse, #view-coverage, #coverage, #coverage-toggle'), 'No separate coverage view, drawer or header toggle remains');
  check(!document.getElementById('browser').hidden, 'The tree owns the viewport');
  check(/^[\d,]+ files$/.test(document.getElementById('catalog-count').textContent), 'Header states only the total file count');
  const groups = Array.from(C.attrs.keys()).filter(n => C.attrsOf(n).coverage);
  if (!groups.length) return {coverage: 'absent', path: C.path(selected >= 0 ? selected : visible[0])};
  check(groups.every(n => C.isVirtual(n) && C.depth(n) === 1 && C.attrsOf(n).coverage.total > 0), 'Only the top-level source groups carry coverage');
  check(groups.every(n => C.path(n) === 'umd' || C.path(n) === 'psn'), 'Coverage sits on umd and psn, never on a subgroup');
  const sources = groups.map(n => C.attrsOf(n).coverage.source);
  check(new Set(sources).size === sources.length, 'One chip per reference population');
  for (const group of groups) {
    const coverage = C.attrsOf(group).coverage;
    jump(group);
    const content = rows.get(group).row.querySelector('.name-content');
    const chip = content.querySelector('.coverage-chip');
    check(chip, 'Source groups show their held share inline');
    check(chip === content.lastElementChild && getComputedStyle(chip).marginLeft === 'auto' || chip.getBoundingClientRect().right > content.querySelector('.name').getBoundingClientRect().right, 'Coverage is right-aligned in the name column');
    check(chip.querySelector('.coverage-source').textContent === coverage.source, 'Inline chip names its reference source');
    const figure = chip.querySelector('.coverage-figure').textContent + chip.querySelector('.coverage-count').textContent;
    check(figure.includes(coverage.total.toLocaleString('en-US')) && !figure.includes('NaN'), 'Inline chip states the held share over its population');
    check(chip.getAttribute('aria-label').includes(coverage.source), 'Inline chip is announced with its source');
    const expected = {Redump: 'http://redump.org/discs/system/psp/', NoPayStation: 'https://nopaystation.com/'};
    check(chip.tagName === 'A' && chip.href === expected[coverage.source], 'Chip opens its source population listing');
    check(chip.target === '_blank' && chip.rel.includes('noopener'), 'Source link isolation');
    check(chip.getAttribute('aria-label').includes('open ' + coverage.source), 'Chip announces that it opens the source');
    const before = selected, expansion = collapsed.join('');
    chip.addEventListener('click', event => event.preventDefault(), {once: true});
    chip.click();
    check(selected === before && collapsed.join('') === expansion, 'Chip click neither selects nor toggles its row');
  }
  check([...new Set(sources)].every(s => s === 'Redump' || s === 'NoPayStation'), 'Only supplied reference populations are named');
  check(!document.querySelector('tr.node .coverage-chip ~ .coverage-chip'), 'No row carries two chips');
  return {coverage: 'rendered', sources: [...new Set(sources)], path: C.path(selected)};
});
console.log('PASS: coverage reads inline on its grouping rows, with no separate view (' + views.coverage + (views.sources ? ': ' + views.sources.join(', ') : '') + ')');

// Deep links, the ?q= state and a narrow viewport (hash column folds away; copy stays on the selection bar).
const deep = await inPage(async () => {
  const check = (value, message) => { if (!value) throw new Error(message); };
  const C = catalog;
  let game = -1; for (const n of C.children(C.find('umd/game'))) if (C.isContainer(n)) { game = n; break; }
  const target = C.find(C.path(game) + '/PSP_GAME/SYSDIR/EBOOT.BIN');
  return {path: C.path(target >= 0 ? target : game)};
});
await load(site + '/#' + deep.path.split('/').map(encodeURIComponent).join('/'));
await inPage(async expected => {
  const check = (value, message) => { if (!value) throw new Error(message); };
  await searchReady;
  check(document.getElementById('selected-path').textContent === expected, 'Deep link selects its occurrence');
  check(document.querySelector('tr.node.selected'), 'Deep link scrolls its row into view');
  check(location.hash === '#' + expected.split('/').map(encodeURIComponent).join('/'), 'Deep link URL kept');
}, deep.path);
console.log('PASS: deep link selects and reveals the exact occurrence');
await load(site + '/?q=eboot.bin');
const queryState = await inPage(async () => {
  await searchReady; await searchSettled;
  for (let i = 0; i < 100 && !/matching files/.test(document.getElementById('search-count').textContent); i++) await new Promise(r => setTimeout(r, 50));
  return {value: document.getElementById('tree-search').value, count: document.getElementById('search-count').textContent};
});
assert.equal(queryState.value, 'eboot.bin');
assert.match(queryState.count, /matching files/);
console.log('PASS: ?q= restores a search on load (' + queryState.count + ')');
await cmd('Emulation.setDeviceMetricsOverride', {width: 390, height: 844, deviceScaleFactor: 2, mobile: true});
await new Promise(r => setTimeout(r, 500));
const narrow = await inPage(async () => {
  const check = (value, message) => { if (!value) throw new Error(message); };
  check(getComputedStyle(document.getElementById('heading-hash')).display === 'none', 'Hash column folds away on narrow screens');
  check(document.querySelector('tr.node'), 'Rows render on narrow screens');
  check(document.documentElement.scrollWidth <= window.innerWidth + 1, 'No horizontal page overflow');
  const written = []; navigator.clipboard.writeText = async t => { written.push(t); };
  select(visible[0]);
  document.getElementById('copy-selected').click();
  for (let i = 0; i < 100 && !written.length; i++) await new Promise(r => setTimeout(r, 50));
  check(/^[0-9a-f]{64}$/.test(written[0]), 'Copy SHA-256 on the selection bar resolves the full digest');
  return {rowHeight: document.querySelector('tr.node').getBoundingClientRect().height, rows: document.querySelectorAll('tr.node').length};
});
console.log('PASS: narrow viewport keeps rows usable and copies the full hash from the selection bar ' + JSON.stringify(narrow));
await cmd('Emulation.setDeviceMetricsOverride', {width: 1440, height: 940, deviceScaleFactor: 1, mobile: false});

// A catalog the server replaced (409) reloads instead of mixing digests across generations.
await load();
const stale = await inPage(async () => {
  await searchReady;
  const original = catalog.generation;
  catalog.generation = '0'.repeat(16);
  let target = -1; for (let i = catalog.count - 1; i > 0 && target < 0; i--) if (catalog.isFile(i) && catalog.slot[i] >= 0 && !hashOf(i)) target = i;
  window.__marker = 'before-reload';
  try { await fullHash(target); return {error: 'resolved a digest for the wrong generation'}; }
  catch (error) { return {name: error.name, notice: document.getElementById('notice').textContent, original}; }
});
assert.equal(stale.name, 'StaleCatalogError', JSON.stringify(stale));
assert.match(stale.notice, /reloading/);
for (let i = 0; i < 60 && await evaluate('window.__marker === "before-reload"').catch(() => true); i++) await new Promise(r => setTimeout(r, 100));
await load();
assert.equal(await evaluate('window.__marker'), undefined, 'the page reloaded');
console.log('PASS: a 409 for the digest generation reloads the catalog');
await cmd('Page.navigate', {url: site});
ws.close();
