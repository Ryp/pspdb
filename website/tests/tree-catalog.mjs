// Exercise ISO identity and grouping without requiring a running browser/site.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {Worker as ThreadWorker} from 'node:worker_threads';
const workerSource = fs.readFileSync(new URL('../pspdb/web/search-worker.js', import.meta.url), 'utf8');
class CatalogWorker {
  constructor() {
    this.thread = new ThreadWorker(`
      const {parentPort} = require('node:worker_threads');
      global.self = {postMessage:(data, transfer)=>parentPort.postMessage(data, transfer)};
      parentPort.on('message', data=>self.onmessage({data}));
      ${workerSource}
    `, {eval:true});
    this.thread.on('message', data=>this.onmessage?.({data}));
    this.thread.on('error', error=>this.onerror?.({message:error.message,preventDefault(){}}));
  }
  postMessage(data, transfer) { this.thread.postMessage(data, transfer); }
  terminate() { this.thread.terminate(); }
}
const el = {addEventListener(){}, setAttribute(){}, removeAttribute(){}};
const context = vm.createContext({
  document: {documentElement:{dataset:{catalog:'api/catalog'}}, getElementById:()=>el, addEventListener(){}},
  window: {addEventListener(){}},
  ResizeObserver: class {observe(){}},
  getComputedStyle: ()=>({getPropertyValue:()=> '21px'}),
  fetch: ()=>new Promise(()=>{}),
  Worker: CatalogWorker, setTimeout, URLSearchParams, URL,
  location: {href:'http://localhost/', search:'', hash:''},
  history: {replaceState(){}},
});
const appSource = fs.readFileSync(new URL('../pspdb/web/app.js', import.meta.url), 'utf8');
vm.runInContext(appSource, context);
let queryVersion = 1000;
async function search(query, sort = null, direction = 1) {
  assert.equal(await vm.runInContext('searchReady', context), true);
  const worker = vm.runInContext('searchWorker', context);
  const model = vm.runInContext('nodes', context);
  const handler = worker.onmessage, version = ++queryVersion;
  const ids = await new Promise((resolve, reject) => {
    worker.onmessage = ({data}) => {
      if (data.type === 'error') reject(new Error(data.message));
      else if (data.type === 'results' && data.version === version) resolve(data.ids);
      else handler({data});
    };
    worker.postMessage({type:'search', version, terms:query.toLowerCase().split(/\s+/).filter(Boolean), sort, direction});
  }).finally(() => { worker.onmessage = handler; });
  return Array.from(ids, id => model[id]);
}
const metadata = {disc_id:'ULJS00009', identifier:'ULJS-00009', title:'AI Shogi', disc_version:'1.00', umd_uid:'4997E9C6184F3200', media_code:'G'};
const entries = [{path:'UMD_DATA.BIN',type:'file',size_bytes:48,sha256:'c'.repeat(64)}];
function catalog(isos) {
  const trees = {iso:{}};
  const records = {iso:isos.map(({entries, ...record}) => {
    trees.iso[record.sha256] = {size_bytes:record.size_bytes,extractor:{name:'iso'},entries};
    return record;
  })};
  return {records,trees};
}
context.fixture = catalog(['a','b'].map(char=>({sha256:char.repeat(64),metadata,entries,size_bytes:2048,redump:char==='a'?[{id:123,name:'Example'}]:[]})));
await vm.runInContext('build(fixture)', context);
const nodes = JSON.parse(vm.runInContext('JSON.stringify(nodeAtPath("umd/game").children.map(n=>({label:label(n),hash:n.hash,redump:n.redump,path:n.path,file:n.children[0].hash})))', context));
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
await vm.runInContext('build(videoFixture)', context);
assert.equal(vm.runInContext('label(nodeAtPath("umd/video").children[0])', context), 'Ice Age');
assert.equal(vm.runInContext('nodeAtPath("umd/video").children[0].hash', context), 'd'.repeat(64));
console.log('PASS: video label uses its SFO title and retains its hash.');

context.untitledVideoFixture = catalog([{size_bytes:2048,sha256:'d'.repeat(64),
  metadata:{identifier:'UMDV-00001',media_code:'V'},entries}]);
await vm.runInContext('build(untitledVideoFixture)', context);
const untitledVideo = JSON.parse(vm.runInContext(`JSON.stringify((()=> {
  const node = nodeAtPath("umd/video").children[0];
  return {label:label(node),path:node.path,child:node.children[0].name};
})())`, context));
assert.deepEqual(untitledVideo, {label:'UMDV-00001',path:'umd/video/'+'d'.repeat(64)+'.iso',child:'UMD_DATA.BIN'});
console.log('PASS: video without optional SFO title retains its identifier and navigable inventory.');

context.failedIsoFixture = catalog([
  {sha256:'1'.repeat(64),size_bytes:2048,entries:[]},
  {sha256:'2'.repeat(64),size_bytes:2048,metadata:{title:'Known title'},entries:[]},
  {sha256:'3'.repeat(64),size_bytes:2048,metadata,entries},
]);
context.failedIsoFixture.trees.iso['1'.repeat(64)].error = 'MissingUmdData';
await vm.runInContext('build(failedIsoFixture)', context);
const failedIsos = JSON.parse(vm.runInContext(`JSON.stringify([...nodes.values()]
  .filter(n=>n.type==='file'&&n.name.endsWith('.iso'))
  .map(n=>({label:label(n),hash:n.hash,path:n.path,error:n.error})))`, context));
assert.deepEqual(failedIsos.find(n=>n.hash==='1'.repeat(64)), {
  label:'1'.repeat(64)+'.iso', hash:'1'.repeat(64),
  path:'umd/other/'+'1'.repeat(64)+'.iso', error:'MissingUmdData',
});
assert.equal(failedIsos.find(n=>n.hash==='2'.repeat(64)).label, 'Known title');
assert.equal(failedIsos.find(n=>n.hash==='3'.repeat(64)).label, 'ULJS-00009/1.00 AI Shogi');
console.log('PASS: metadata-free failed ISO retains hash/error, optional identifiers work, healthy siblings remain browsable.');

// A single hash-keyed extraction attaches to both occurrences, without replacing
// the original file's identity or counting expanded bytes in its parent's size.
context.fixture.trees.prx = {
  ['c'.repeat(64)]: {size_bytes:48,extractor:{name:'pspdecrypt'},entries:[
    {path:'F0/module.prx',type:'file',size_bytes:1024,sha256:'e'.repeat(64)},
    {path:'again.bin',type:'file',size_bytes:48,sha256:'c'.repeat(64)},
  ]},
};
await vm.runInContext('build(fixture)', context);
const expanded = JSON.parse(vm.runInContext(`JSON.stringify(nodeAtPath("umd/game").children.map(iso=>({
  size:iso.size, source:iso.children[0].hash, type:iso.children[0].type,
  expandable:expandable(iso.children[0]), children:iso.children[0].children.length,
  leaf:iso.children[0].children[0].children[0].hash,
  cycleChildren:iso.children[0].children[1].children.length,
})))`, context));
for (const iso of expanded) {
  assert.equal(iso.size,2048);
  assert.equal(iso.source,'c'.repeat(64));
  assert.equal(iso.type,'file');
  assert.equal(iso.expandable,true);
  assert.equal(iso.children,2);
  assert.equal(iso.leaf,'e'.repeat(64));
  assert.equal(iso.cycleChildren,0);
}
assert.equal((await search('e'.repeat(64))).length, 2);
console.log('PASS: shared extraction subtrees, source sizes/hashes, searchable children, cycle termination.');

context.namingFixture = catalog([{sha256:'a'.repeat(64),metadata,size_bytes:2048,entries:[
  {path:'OPNSSMP.BIN',type:'file',size_bytes:48,sha256:'c'.repeat(64)},
  {path:'ALIAS.BIN',type:'file',size_bytes:48,sha256:'c'.repeat(64)},
]}]);
Object.assign(context.namingFixture.trees, {
  prx: {['c'.repeat(64)]: {size_bytes:48,extractor:{name:'pspdecrypt'},name_rule:'source_stem',entries:[
    {path:'module.prx.gz',type:'file',size_bytes:32,sha256:'e'.repeat(64)},
  ]}},
  gzip: {['e'.repeat(64)]: {size_bytes:32,extractor:{name:'gzip'},name_rule:'strip_suffix',entries:[
    {path:'module.prx',type:'file',size_bytes:64,sha256:'f'.repeat(64)},
  ]}},
});
await vm.runInContext('build(namingFixture)', context);
const named = JSON.parse(vm.runInContext(`JSON.stringify([...nodes.values()].filter(n=>n.hash==='e'.repeat(64)||n.hash==='f'.repeat(64)).map(n=>n.name))`,context));
assert.deepEqual(named,['OPNSSMP.prx.gz','OPNSSMP.prx','ALIAS.prx.gz','ALIAS.prx']);
console.log('PASS: shared executable trees inherit each occurrence name through decompression.');

// PSN packages are root siblings of UMD and retain their exact package hash.
context.pkgFixture = {records:{iso:[],pkg:[{sha256:'9'.repeat(64),size_bytes:123,psn_kind:'neogeo',
  metadata:{content_type:16,content_id:'UP9000-NPUG00001_00-FIXTURE',title:'Demo'}}]},trees:{pkg:{
    ['9'.repeat(64)]:{size_bytes:123,extractor:{name:'pspdb-ingest'},entries:[{path:'PARAM.SFO',type:'file',size_bytes:10,sha256:'8'.repeat(64)}]}}}};
await vm.runInContext('build(pkgFixture)',context);
const psn = JSON.parse(vm.runInContext(`JSON.stringify((()=>{const n=nodeAtPath('psn/neogeo/'+'9'.repeat(64)+'.pkg');
  return {path:n.path,hash:n.hash,size:n.size,label:label(n),child:n.children[0].name};})())`,context));
assert.equal(psn.path, 'psn/neogeo/'+'9'.repeat(64)+'.pkg');
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
assert.deepEqual((await search('up9000-npug00001_00-fixture')).map(node=>node.name), ['9'.repeat(64)+'.pkg', 'PARAM.SFO']);
console.log('PASS: compact package titles, unique collision suffixes, metadata fallback and full content-ID search.');

assert.equal(vm.runInContext("packageSerial({title_id:'npug80135'})", context), 'NPUG-80135');
assert.equal(vm.runInContext("packageSerial({title_id:'NPUG-80135'})", context), 'NPUG-80135');
console.log('PASS: serial-first package labels share UMD ID formatting.');

// Server-computed kinds own the grouping; package_flags and content_type stay ignored.
context.updateFixture = {records:{pkg:[
  {sha256:'1'.repeat(64),size_bytes:1,psn_kind:'patch',metadata:{content_type:7,package_flags:0x8000021c}},
  {sha256:'2'.repeat(64),size_bytes:1,psn_kind:'game',metadata:{content_type:7,package_flags:0x20c}},
  {sha256:'3'.repeat(64),size_bytes:1,psn_kind:'theme',metadata:{content_type:9,package_flags:0x21c}},
  {sha256:'4'.repeat(64),size_bytes:1,psn_kind:'dlc',metadata:{content_type:7}},
  {sha256:'5'.repeat(64),size_bytes:1,metadata:{content_type:7,package_flags:0x8000021c}},
]},trees:{}};
await vm.runInContext('build(updateFixture)',context);
const updatePaths = JSON.parse(vm.runInContext(
  "JSON.stringify([...nodes.values()].filter(n=>n.type==='file').map(n=>n.path).sort())",context));
assert.deepEqual(updatePaths,[
  'psn/dlc/'+'4'.repeat(64)+'.pkg',
  'psn/game/'+'2'.repeat(64)+'.pkg',
  'psn/patch/'+'1'.repeat(64)+'.pkg',
  'psn/theme/'+'3'.repeat(64)+'.pkg',
  'psn/unknown/'+'5'.repeat(64)+'.pkg',
]);
console.log('PASS: server kinds group every package, no package sits at the PSN root, missing kinds fall back to unknown.');

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
await vm.runInContext('build(contextFixture)',context);
const scoped = JSON.parse(vm.runInContext(`JSON.stringify(nodeAtPath("umd/game").children[0].children.map(n=>({name:n.name,hash:n.hash,children:n.children.map(c=>({name:c.name,hash:c.hash}))})))`,context));
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
context.contextFixture.trees.gzip = {[payloadHash]: {size_bytes:7,extractor:{name:'gzip'},name_rule:'decoded_suffix',entries:[
  {path:'module.elf',type:'file',size_bytes:20,sha256:'6'.repeat(64)},
]}};
await vm.runInContext('build(contextFixture)',context);
assert.equal(vm.runInContext("[...nodes.values()].find(n=>n.hash==='6'.repeat(64)).name",context),'DATA.elf');
console.log('PASS: decoded ELF suffix survives contextual gzip naming without duplicate suffixes.');

const matchedChild = vm.runInContext(`(() => {
  const parent = {name: 'DATA.BIN', path: 'DATA.BIN', children: [], hash: 'parent'};
  for (const _ of addInventory(parent, [{path: 'disc.bin', type: 'file', size_bytes: 42,
    sha256: 'disc', redump: [{id: 38300, name: 'Saikyou Ginsei Chess'}]}])) {}
  return parent.children[0];
})()`, context);
assert.equal(matchedChild.redump[0].id, 38300);
console.log('PASS: nested reconstructed discs retain exact Redump annotations.');

// The same bytes can be an original ISO, a package root, and a nested ISO9660 image.
// Inventories belong to those observations, not to the hash alone.
const roleHash = '7'.repeat(64), parentHash = '8'.repeat(64), rootOnlyHash = '0'.repeat(64);
const roleLeaf = name => ({path:name,type:'file',size_bytes:1,sha256:'9'.repeat(64)});
context.roleFixture = catalog([
  {sha256:roleHash,size_bytes:42,metadata,entries:[
    roleLeaf('root-only.bin'), {path:'self.iso',type:'file',size_bytes:42,sha256:roleHash},
  ]},
  {sha256:parentHash,size_bytes:100,metadata,entries:[
    {path:'nested.iso',type:'file',size_bytes:42,sha256:roleHash},
    {path:'root-observation-only.iso',type:'file',size_bytes:42,sha256:rootOnlyHash},
    {path:'inline.iso',type:'file',size_bytes:42,sha256:roleHash,extraction:{
      sha256:roleHash,size_bytes:42,extractor:{name:'contextual'},entries:[roleLeaf('inline-only.bin')],
    }},
  ]},
  {sha256:rootOnlyHash,size_bytes:42,metadata,entries:[roleLeaf('other-root-only.bin')]},
]);
context.roleFixture.records.pkg = [{sha256:roleHash,size_bytes:42,metadata:{title:'Package role',title_id:'NPUG00001'}}];
context.roleFixture.trees.pkg = {[roleHash]: {size_bytes:42,extractor:{name:'pkg'},entries:[roleLeaf('package-only.bin')]}};
context.roleFixture.trees.iso9660 = {[roleHash]: {size_bytes:42,extractor:{name:'iso9660'},entries:[
  roleLeaf('nested-only.bin'), {path:'again.iso',type:'file',size_bytes:42,sha256:roleHash},
]}};
await vm.runInContext('build(roleFixture)',context);
const roles = JSON.parse(vm.runInContext(`JSON.stringify((() => {
  const original = nodeAtPath('umd/game/'+'7'.repeat(64)+'.iso');
  const parent = nodeAtPath('umd/game/'+'8'.repeat(64)+'.iso');
  const nested = parent.children.find(n=>n.name==='nested.iso');
  return {
    root:original.children.map(n=>n.name),
    nested:nested.children.map(n=>n.name),
    self:original.children.find(n=>n.name==='self.iso').children.map(n=>n.name),
    cycle:nested.children.find(n=>n.name==='again.iso').children.map(n=>n.name),
    hash:nested.hash,size:nested.size,
    rootFallback:parent.children.find(n=>n.name==='root-observation-only.iso').children.map(n=>n.name),
    inline:parent.children.find(n=>n.name==='inline.iso').children.map(n=>n.name),
    pkg:nodeAtPath('psn/unknown/'+'7'.repeat(64)+'.pkg').children.map(n=>n.name),
  };
})())`,context));
assert.deepEqual(roles,{
  root:['root-only.bin','self.iso'],nested:['again.iso','nested-only.bin'],
  self:['again.iso','nested-only.bin'],cycle:[],hash:roleHash,size:42,
  rootFallback:[],inline:['inline-only.bin'],pkg:['package-only.bin'],
});
console.log('PASS: same-hash root, nested, package, and inline inventories retain their own names and byte identity.');

const ambiguousFixture = structuredClone(context.roleFixture);
ambiguousFixture.trees.prx = {[roleHash]: {size_bytes:42,extractor:{name:'prx'},entries:[roleLeaf('wrong-kind.bin')]}};
context.ambiguousFixture = ambiguousFixture;
await assert.rejects(vm.runInContext('build(ambiguousFixture)',context),/Ambiguous non-root extraction kinds/);
// Inline extraction remains authoritative even when no global kind can be selected.
context.inlineAmbiguousFixture = catalog([{sha256:parentHash,size_bytes:100,metadata,entries:[
  {path:'inline.iso',type:'file',size_bytes:42,sha256:roleHash,extraction:{
    sha256:roleHash,size_bytes:42,extractor:{name:'contextual'},entries:[roleLeaf('inline-only.bin')],
  }},
]}]);
context.inlineAmbiguousFixture.trees.iso9660 = {[roleHash]: {size_bytes:42,extractor:{name:'iso9660'},entries:[]}};
context.inlineAmbiguousFixture.trees.prx = ambiguousFixture.trees.prx;
await vm.runInContext('build(inlineAmbiguousFixture)',context);
assert.equal(vm.runInContext("[...nodes.values()].find(n=>n.name==='inline-only.bin').parent.name",context),'inline.iso');
const conflictingFixture = structuredClone(context.roleFixture);
conflictingFixture.trees.iso9660[roleHash].size_bytes++;
context.conflictingFixture = conflictingFixture;
await assert.rejects(vm.runInContext('build(conflictingFixture)',context),/Conflicting source sizes/);
console.log('PASS: ambiguous byte references and cross-role size conflicts fail explicitly; inline extraction overrides lookup.');

// Updater roots and generic PBP occurrences can observe the same bytes independently.
const updaterHash = 'a'.repeat(64), variantHash = 'b'.repeat(64), missingTreeHash = 'c'.repeat(64);
const updateRecord = (sha256, size_bytes, metadata = {}) => ({sha256, size_bytes, metadata});
const updateTree = (size_bytes, name) => ({
  size_bytes, extractor:{name:'pspdb-update', version:'1', options:[]}, entries:[roleLeaf(name)],
});
context.updaterFixture = {
  records:{
    update:[
      updateRecord(updaterHash, 42, {updater_version:'6.61', title:'System Software', disc_id:'UCJS10041'}),
      updateRecord(variantHash, 43, {updater_version:'6.61', title:'System Software Variant', disc_id:'UCJS10041'}),
      updateRecord(missingTreeHash, 44),
    ],
    pkg:[{sha256:parentHash, size_bytes:100, psn_kind:'patch', metadata:{content_type:7}}],
  },
  trees:{
    update:{[updaterHash]:updateTree(42, 'DATA.BIN'), [variantHash]:updateTree(43, 'DATA.BIN')},
    pbp:{
      [updaterHash]:{size_bytes:42, extractor:{name:'pbp'}, entries:[roleLeaf('generic-only.bin')]},
      [missingTreeHash]:{size_bytes:44, extractor:{name:'pbp'}, entries:[roleLeaf('generic-fallback.bin')]},
    },
    pkg:{[parentHash]:{size_bytes:100, extractor:{name:'pkg'}, entries:[
      {path:'EBOOT.PBP',type:'file',size_bytes:42,sha256:updaterHash},
    ]}},
  },
};
await vm.runInContext('build(updaterFixture)',context);
const updaterRoles = JSON.parse(vm.runInContext(`JSON.stringify((() => {
  const updates = nodeAtPath('firmware/update');
  return {
    roots:updates.children.map(node=>({
      hash:node.hash, size:node.size, path:node.path, url:url(node),
      children:node.children.map(child=>child.name),
    })).sort((a,b)=>a.hash.localeCompare(b.hash)),
    total:updates.size,
    nested:nodeAtPath('psn/patch/'+'8'.repeat(64)+'.pkg/EBOOT.PBP').children.map(node=>node.name),
  };
})())`,context));
assert.deepEqual(updaterRoles.roots, [
  {hash:updaterHash, size:42, path:`firmware/update/${updaterHash}.pbp`,
    url:`#firmware/update/${updaterHash}.pbp`, children:['DATA.BIN']},
  {hash:variantHash, size:43, path:`firmware/update/${variantHash}.pbp`,
    url:`#firmware/update/${variantHash}.pbp`, children:['DATA.BIN']},
  {hash:missingTreeHash, size:44, path:`firmware/update/${missingTreeHash}.pbp`,
    url:`#firmware/update/${missingTreeHash}.pbp`, children:[]},
]);
assert.equal(updaterRoles.total, 129);
assert.deepEqual(updaterRoles.nested, ['generic-only.bin']);
for (const term of ['6.61', 'system software', 'ucjs10041', updaterHash])
  assert.ok((await search(term)).some(node=>node.hash===updaterHash));
console.log('PASS: updater variants retain full raw identities, sizes, searchable metadata and root-specific inventories beside generic PBP and PSN update roles.');

// Refinements must not retain ancestor matches when a term becomes hash-only,
// and extraction failures belong only to their exact source occurrence.
const hashRoot = 'deadbeef' + '0'.repeat(56), duplicateHash = 'f'.repeat(64);
context.searchFixture = catalog([{sha256:hashRoot, size_bytes:100,
  metadata:{...metadata,title:'Ancestor title'}, entries:[
    {path:'one.bin',type:'file',size_bytes:10,sha256:duplicateHash},
    {path:'two.bin',type:'file',size_bytes:10,sha256:duplicateHash},
    {path:'broken.bin',type:'file',size_bytes:10,sha256:'e'.repeat(64),extraction:{
      sha256:'e'.repeat(64),size_bytes:10,extractor:{name:'partial'},error:'ChildFailure',
      entries:[{path:'decoded.bin',type:'file',size_bytes:5,sha256:'d'.repeat(64)}],
    }},
  ]}]);
context.searchFixture.trees.iso[hashRoot].error = 'ParentFailure';
await vm.runInContext('build(searchFixture)',context);
assert.equal((await search('deadbee')).length, 5);
assert.deepEqual((await search('DEADBEEF')).map(node=>node.hash), [hashRoot]);
assert.equal((await search(hashRoot+'.iso')).length, 5);
assert.deepEqual((await search(duplicateHash)).map(node=>node.name), ['one.bin','two.bin']);
assert.deepEqual((await search('ANCESTOR two.bin')).map(node=>node.name), ['two.bin']);
assert.deepEqual((await search('ParentFailure')).map(node=>node.hash), [hashRoot]);
assert.deepEqual((await search('ChildFailure')).map(node=>node.name), ['broken.bin']);
const defaultOrder = (await search('ancestor')).map(node=>node.path);
assert.deepEqual((await search('ancestor','size')).map(node=>node.size), [5,10,10,10,100]);
assert.deepEqual((await search('ancestor','size',-1)).map(node=>node.size), [100,10,10,10,5]);
assert.deepEqual((await search('ancestor')).map(node=>node.path), defaultOrder);

// Sparse results exercise candidate-only matching, including ancestor text,
// own errors, duplicate hashes and broadening back to the complete index.
context.refinementFixture = structuredClone(context.searchFixture);
const unrelatedHash = '9'.repeat(64);
context.refinementFixture.records.iso.push({sha256:unrelatedHash,size_bytes:128,metadata:{title:'Unrelated'}});
context.refinementFixture.trees.iso[unrelatedHash] = {size_bytes:128,extractor:{name:'iso'},
  entries:Array.from({length:128},(_,i)=>({path:`other-${i}.bin`,type:'file',size_bytes:1,
    sha256:'abcdef00'+i.toString(16).padStart(56,'0')}))};
await vm.runInContext('build(refinementFixture)',context);
assert.equal((await search('ancestor')).length, 5);
assert.deepEqual((await search('ancestor bin')).map(node=>node.name).sort(),
  ['broken.bin','decoded.bin','one.bin','two.bin']);
assert.deepEqual((await search('ancestor bin child')).map(node=>node.name), ['broken.bin']);
assert.deepEqual((await search('ancestor bin')).map(node=>node.name).sort(),
  ['broken.bin','decoded.bin','one.bin','two.bin']);
assert.deepEqual((await search('ffffffff')).map(node=>node.name).sort(), ['one.bin','two.bin']);
assert.deepEqual((await search(duplicateHash)).map(node=>node.name).sort(), ['one.bin','two.bin']);
assert.equal((await search('deadbee')).length, 5);
assert.deepEqual((await search('deadbeef')).map(node=>node.hash), [hashRoot]);
assert.deepEqual((await search('ancestor absent')).map(node=>node.name), []);
assert.deepEqual((await search('ancestor absent-longer')).map(node=>node.name), []);
assert.equal((await search('ancestor')).length, 5);
console.log('PASS: sparse refinements preserve ancestor context, own errors, duplicate hashes, hash transitions, empty results and broadening.');
vm.runInContext('searchWorker.terminate()',context);
console.log('PASS: asynchronous ancestor/own-hash transitions, duplicate occurrences, source-only errors and reversible sorting.');

// Browsers can advance scrollTop before delivering a passive wheel callback.
// The first movement must remain native pixels even on a compressed scroll rail.
for (const count of [28000, 3240000]) {
  const handlers = new Map();
  let position = 0, idle;
  const host = {
    clientHeight:600,
    get scrollTop() { return position; },
    set scrollTop(value) { position = Math.round(value); },
    addEventListener(type, handler) { handlers.set(type, handler); },
  };
  const tree = {...el, tHead:{offsetHeight:40}};
  const scrollContext = vm.createContext({
    document:{documentElement:{dataset:{catalog:'api/catalog'}}, addEventListener(){},
      getElementById:id=>id==='table-scroll' ? host : id==='tree' ? tree : el},
    window:{addEventListener(){}},
    ResizeObserver:class {observe(){}},
    getComputedStyle:()=>({getPropertyValue:()=> '45px'}),
    fetch:()=>new Promise(()=>{}),
    setTimeout:callback=>{ idle = callback; return 1; },
    clearTimeout:()=>{ idle = undefined; },
    requestAnimationFrame:()=>0,
    URLSearchParams, URL, location:{href:'http://localhost/', search:'', hash:''},
    history:{replaceState(){}},
    count,
  });
  vm.runInContext(appSource, scrollContext);
  vm.runInContext(`
    visible = {length:count};
    renderWindow = ()=>{};
    logicalOffset = 200000;
    scrollViewport = scrollMetrics().viewport;
    $("table-scroll").scrollTop = globalScrollPosition(logicalOffset, scrollMetrics());
    physicalOffset = $("table-scroll").scrollTop;
  `, scrollContext);
  host.scrollTop += 120;
  handlers.get('wheel')({deltaY:120});
  assert.equal(vm.runInContext('scrollMetrics().offset', scrollContext), 200120);
  assert.equal(typeof idle, 'function');
  idle();
  handlers.get('scroll')();
  assert.equal(vm.runInContext('scrollMetrics().offset', scrollContext), 200120);
}
console.log('PASS: compositor-first wheel movement and rounded idle remapping preserve native pixel distance at both list scales.');
