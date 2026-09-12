// Exercise ISO identity and grouping without requiring a running browser/site.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const el = {addEventListener(){}, setAttribute(){}};
const context = vm.createContext({
  document: {documentElement:{dataset:{catalog:'api/catalog'}}, getElementById:()=>el, addEventListener(){}},
  window: {addEventListener(){}},
  ResizeObserver: class {observe(){}},
  fetch: ()=>new Promise(()=>{}),
});
vm.runInContext(fs.readFileSync(new URL('../pspdb/web/app.js', import.meta.url), 'utf8'), context);
const metadata = {disc_id:'ULJS00009', identifier:'ULJS-00009', title:'AI Shogi', disc_version:'1.00', umd_uid:'4997E9C6184F3200', media_code:'G'};
const entries = [{path:'UMD_DATA.BIN',type:'file',size_bytes:48,sha256:'c'.repeat(64)}];
function catalog(isos) {
  const trees = {};
  const records = {iso:isos.map(({entries, ...record}) => {
    trees[record.sha256] = {size_bytes:record.size_bytes,extractor:{name:'iso'},entries};
    return record;
  })};
  return {records,trees};
}
context.fixture = catalog(['a','b'].map(char=>({sha256:char.repeat(64),metadata,entries,size_bytes:2048,redump:char==='a'?[{id:123,name:'Example'}]:[]})));
vm.runInContext('build(fixture)', context);
const nodes = JSON.parse(vm.runInContext('JSON.stringify(root.children[0].children[0].children.map(n=>({label:label(n),hash:n.hash,redump:n.redump,path:n.path,file:n.children[0].hash})))', context));
assert.equal(nodes.length, 2);
assert.equal(nodes[0].label, 'ULJS-00009/1.00 AI Shogi');
assert.equal(nodes[1].label, 'ULJS-00009/1.00 AI Shogi');
assert.equal(nodes[0].hash, 'a'.repeat(64));
assert.equal(nodes[1].hash, 'b'.repeat(64));
assert.notEqual(nodes[0].path, nodes[1].path);
assert.equal(nodes[0].file, nodes[1].file);
assert.equal(nodes[0].redump[0].id, 123);
assert.deepEqual(nodes[1].redump, []);
console.log('PASS: independent ISO roots, identical inventories, metadata labels, ISO and file hashes.');

context.videoFixture = catalog([{size_bytes:2048,sha256:'d'.repeat(64),metadata:{identifier:'ICE_AGE   ',title:'Ice Age',media_code:'V'},entries:[]}]);
vm.runInContext('build(videoFixture)', context);
assert.equal(vm.runInContext('label(root.children[0].children[0].children[0])', context), 'Ice Age');
assert.equal(vm.runInContext('root.children[0].children[0].children[0].hash', context), 'd'.repeat(64));
console.log('PASS: video label uses its SFO title and retains its hash.');

// A single hash-keyed extraction attaches to both occurrences, without replacing
// the original file's identity or counting expanded bytes in its parent's size.
Object.assign(context.fixture.trees, {
  ['c'.repeat(64)]: {size_bytes:48,extractor:{name:'pspdecrypt'},entries:[
    {path:'F0/module.prx',type:'file',size_bytes:1024,sha256:'e'.repeat(64)},
    {path:'again.bin',type:'file',size_bytes:48,sha256:'c'.repeat(64)},
  ]},
});
vm.runInContext('build(fixture)', context);
const expanded = JSON.parse(vm.runInContext(`JSON.stringify(root.children[0].children[0].children.map(iso=>({
  size:iso.size, source:iso.children[0].hash, type:iso.children[0].type,
  expandable:expandable(iso.children[0]), children:iso.children[0].children.length,
  leaf:iso.children[0].children[0].children[0].hash,
  cycleChildren:iso.children[0].children[1].children.length,
  searchable:iso.children[0].children[0].children[0].searchText,
})))`, context));
for (const iso of expanded) {
  assert.equal(iso.size,2048);
  assert.equal(iso.source,'c'.repeat(64));
  assert.equal(iso.type,'file');
  assert.equal(iso.expandable,true);
  assert.equal(iso.children,2);
  assert.equal(iso.leaf,'e'.repeat(64));
  assert.equal(iso.cycleChildren,0);
  assert.ok(iso.searchable.includes('e'.repeat(64)));
}
console.log('PASS: shared extraction subtrees, source sizes/hashes, searchable children, cycle termination.');

context.namingFixture = catalog([{sha256:'a'.repeat(64),metadata,size_bytes:2048,entries:[
  {path:'OPNSSMP.BIN',type:'file',size_bytes:48,sha256:'c'.repeat(64)},
  {path:'ALIAS.BIN',type:'file',size_bytes:48,sha256:'c'.repeat(64)},
]}]);
Object.assign(context.namingFixture.trees, {
  ['c'.repeat(64)]: {size_bytes:48,extractor:{name:'pspdecrypt'},name_rule:'source_stem',entries:[
    {path:'module.prx.gz',type:'file',size_bytes:32,sha256:'e'.repeat(64)},
  ]},
  ['e'.repeat(64)]: {size_bytes:32,extractor:{name:'gzip'},name_rule:'strip_suffix',entries:[
    {path:'module.prx',type:'file',size_bytes:64,sha256:'f'.repeat(64)},
  ]},
});
vm.runInContext('build(namingFixture)', context);
const named = JSON.parse(vm.runInContext(`JSON.stringify([...nodes.values()].filter(n=>n.hash==='e'.repeat(64)||n.hash==='f'.repeat(64)).map(n=>n.name))`,context));
assert.deepEqual(named,['OPNSSMP.prx.gz','OPNSSMP.prx','ALIAS.prx.gz','ALIAS.prx']);
console.log('PASS: shared executable trees inherit each occurrence name through decompression.');
