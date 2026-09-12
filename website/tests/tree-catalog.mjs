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

context.untitledVideoFixture = catalog([{size_bytes:2048,sha256:'d'.repeat(64),
  metadata:{identifier:'UMDV-00001',media_code:'V'},entries}]);
vm.runInContext('build(untitledVideoFixture)', context);
const untitledVideo = JSON.parse(vm.runInContext(`JSON.stringify((()=> {
  const node = root.children[0].children[0].children[0];
  return {label:label(node),path:node.path,child:node.children[0].name};
})())`, context));
assert.deepEqual(untitledVideo, {label:'UMDV-00001',path:'umd/video/'+'d'.repeat(64)+'.iso',child:'UMD_DATA.BIN'});
console.log('PASS: video without optional SFO title retains its identifier and navigable inventory.');

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

// PSN packages are root siblings of UMD and retain their exact package hash.
context.pkgFixture = {records:{iso:[],pkg:[{sha256:'9'.repeat(64),size_bytes:123,
  metadata:{content_id:'UP9000-NPUG00001_00-FIXTURE',title:'Demo'}}]},trees:{
    ['9'.repeat(64)]:{size_bytes:123,extractor:{name:'pspdb-ingest'},entries:[{path:'PARAM.SFO',type:'file',size_bytes:10,sha256:'8'.repeat(64)}]}}};
vm.runInContext('build(pkgFixture)',context);
const psn = JSON.parse(vm.runInContext(`JSON.stringify((()=>{const n=root.children.find(n=>n.name==='psn').children[0];
  return {path:n.path,hash:n.hash,size:n.size,label:label(n),child:n.children[0].name};})())`,context));
assert.equal(psn.path, 'psn/'+'9'.repeat(64)+'.pkg');
assert.equal(psn.hash,'9'.repeat(64));
assert.equal(psn.size,123);
assert.equal(psn.label,'NPUG-00001 Demo');
assert.equal(psn.child,'PARAM.SFO');
console.log('PASS: PSN package grouping, identity, label, and attached inventory.');

context.labelPackages = [
  {sha256:'aaaaaaaa0'+'0'.repeat(55),metadata:{title:' Demo  title ',title_id:'NPUG00001'}},
  {sha256:'aaaaaaaa1'+'0'.repeat(55),metadata:{title:'Demo title',content_id:'UP9000-NPUG00001_00-OTHER'}},
  {sha256:'b'.repeat(64),metadata:{}},
];
const labels = JSON.parse(vm.runInContext('JSON.stringify([...packageLabels(labelPackages).values()])',context));
assert.deepEqual(labels,['NPUG-00001 Demo title · aaaaaaaa0','NPUG-00001 Demo title · aaaaaaaa1','Untitled package · bbbbbbbb']);
assert.ok(vm.runInContext("root.children.find(n=>n.name==='psn').children[0].searchText.includes('up9000-npug00001_00-fixture')",context));
console.log('PASS: compact package titles, unique collision suffixes, metadata fallback and full content-ID search.');

assert.equal(vm.runInContext("packageSerial({title_id:'npug80135'})", context), 'NPUG-80135');
assert.equal(vm.runInContext("packageSerial({title_id:'NPUG-80135'})", context), 'NPUG-80135');
assert.equal(vm.runInContext("root.children.find(n=>n.name==='psn').children[0].gamePrefix", context), 'NPUG-00001');
console.log('PASS: serial-first package labels share UMD ID formatting and prefix styling.');

// Contextual output is bound to one file occurrence, not globally to its hash.
const sourceHash = '1'.repeat(64), payloadHash = '2'.repeat(64);
const inlineTree = {sha256:sourceHash,size_bytes:14,extractor:{name:'pops'},name_rule:'source_stem',entries:[
  {path:'payload.gz',type:'file',sha256:payloadHash,size_bytes:7},
]};
context.contextFixture = catalog([{sha256:'3'.repeat(64),size_bytes:100,metadata,entries:[
  {path:'DATA.BIN',type:'file',sha256:'4'.repeat(64),size_bytes:50},
  {path:'DATA.PSP',type:'file',sha256:sourceHash,size_bytes:14,extraction:inlineTree},
  {path:'OTHER.PSP',type:'file',sha256:sourceHash,size_bytes:14},
  {path:'WRONG.PSP',type:'file',sha256:'5'.repeat(64),size_bytes:14,extraction:inlineTree},
]}]);
vm.runInContext('build(contextFixture)',context);
const scoped = JSON.parse(vm.runInContext(`JSON.stringify(root.children[0].children[0].children[0].children.map(n=>({name:n.name,hash:n.hash,children:n.children.map(c=>({name:c.name,hash:c.hash}))})))`,context));
assert.deepEqual(scoped.find(n=>n.name==='DATA.PSP').children,[{name:'DATA.gz',hash:payloadHash}]);
for (const name of ['DATA.BIN','OTHER.PSP','WRONG.PSP']) assert.deepEqual(scoped.find(n=>n.name===name).children,[]);
console.log('PASS: PBP-scoped output attaches only to its matching DATA.PSP occurrence.');

// Decode-stage naming uses the observed format instead of dropping it.
for (const [source, path, expected] of [
  ['DATA.gz','module.elf','DATA.elf'],
  ['DATA.elf.gz','module.elf','DATA.elf'],
  ['DATA.prx.gz','module.elf','DATA.elf'],
  ['archive.gz','payload.bin','archive'],
  ['notes.txt.gz','payload.bin','notes.txt'],
  ['DATA.gz.gz','payload.gz','DATA.gz'],
]) {
  context.namingArgs = {source,path};
  assert.equal(vm.runInContext('extractedName(namingArgs.source,namingArgs.path,"decoded_suffix")',context),expected);
}
context.contextFixture.trees[payloadHash] = {size_bytes:7,extractor:{name:'gzip'},name_rule:'decoded_suffix',entries:[
  {path:'module.elf',type:'file',size_bytes:20,sha256:'6'.repeat(64)},
]};
vm.runInContext('build(contextFixture)',context);
assert.equal(vm.runInContext("[...nodes.values()].find(n=>n.hash==='6'.repeat(64)).name",context),'DATA.elf');
console.log('PASS: decoded ELF suffix survives contextual gzip naming without duplicate suffixes.');

const matchedChild = vm.runInContext(`(() => {
  const parent = {name: 'DATA.BIN', path: 'DATA.BIN', children: [], hash: 'parent'};
  addInventory(parent, [{path: 'disc.bin', type: 'file', size_bytes: 42,
    sha256: 'disc', redump: [{id: 38300, name: 'Saikyou Ginsei Chess'}]}]);
  return parent.children[0];
})()`, context);
assert.equal(matchedChild.redump[0].id, 38300);
console.log('PASS: nested reconstructed discs retain exact Redump annotations.');
