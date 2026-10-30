// Viewer behaviour without a browser: fixtures go through the real Python
// encoder, then catalog.js, app.js and the search worker run in a stubbed DOM.
//   node website/tests/tree-catalog.mjs
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {catalogModule, childNames, createViewer, encodeFixture, nodeAt, sources} from './viewer-support.mjs';
import {assertMatchesReference, digestTable} from './reference-tree.mjs';

const viewer = createViewer();
const {context} = viewer;
const H = (char, count = 64) => char.repeat(count);
const metadata = {disc_id:'ULJS00009', identifier:'ULJS-00009', title:'AI Shogi', disc_version:'1.00', umd_uid:'4997E9C6184F3200', media_code:'G'};
const entries = [{path:'UMD_DATA.BIN',type:'file',size_bytes:48,sha256:H('c')}];
function catalog(isos) {
  const trees = {iso:{}};
  const records = {iso:isos.map(({entries, ...record}) => {
    trees.iso[record.sha256] = {size_bytes:record.size_bytes,extractor:{name:'iso'},entries};
    return record;
  })};
  return {records,trees};
}
const cat = () => viewer.catalog;
// Full digests resolve lazily through the chunk endpoint, like the page does.
async function fullHash(node) { context.__node = node; return vm.runInContext('fullHash(__node)', context); }
const hashes = async nodes => Promise.all(nodes.map(fullHash));
const search = (...args) => viewer.search(...args);
const names = ids => ids.map(id => cat().nameOf(id));
const paths = ids => ids.map(id => cat().path(id));
// Every fixture also has to match the original object-per-row tree, row by row.
async function build(data, options) {
  const encoded = await viewer.build(data, options);
  assertMatchesReference(cat(), data, digestTable(encoded));
  return encoded;
}
const rebuild = source => catalogModule.buildCatalog(catalogModule.parseContainer(encodeFixture(source).bytes));

await build(catalog(['a','b'].map(char=>({sha256:H(char),metadata,entries,size_bytes:2048,redump:char==='a'?[{id:123,name:'Example'}]:[]}))));
{
  const games = cat().children(nodeAt(cat(), 'umd/game'));
  assert.equal(games.length, 2);
  assert.deepEqual(games.map(n => cat().label(n)), ['ULJS-00009/1.00 AI Shogi', 'ULJS-00009/1.00 AI Shogi']);
  assert.deepEqual(games.map(n => cat().knownHash(n)), [H('a'), H('b')]);
  assert.notEqual(cat().path(games[0]), cat().path(games[1]));
  const leaves = cat().children(games[0]).concat(cat().children(games[1]));
  assert.deepEqual(await hashes(leaves), [H('c'), H('c')]);
  assert.equal(cat().attrsOf(games[0]).gamePrefix, 'ULJS-00009/1.00');
  // UMD rows never link Redump directly; only inventory rows keep their own matches.
  assert.equal(cat().attrsOf(games[0]).redump, undefined);
  console.log('PASS: independent ISO roots, identical inventories, metadata labels, ISO and file hashes.');
}

await build(catalog([{size_bytes:2048,sha256:H('d'),metadata:{identifier:'ICE_AGE   ',title:'Ice Age',media_code:'V'},entries:[]}]));
assert.equal(cat().label(cat().children(nodeAt(cat(), 'umd/video'))[0]), 'Ice Age');
assert.equal(cat().knownHash(cat().children(nodeAt(cat(), 'umd/video'))[0]), H('d'));
console.log('PASS: video label uses its SFO title and retains its hash.');

await build(catalog([{size_bytes:2048,sha256:H('d'),metadata:{identifier:'UMDV-00001',media_code:'V'},entries}]));
{
  const node = cat().children(nodeAt(cat(), 'umd/video'))[0];
  assert.deepEqual({label:cat().label(node),path:cat().path(node),child:names(cat().children(node))[0]},
    {label:'UMDV-00001',path:'umd/video/'+H('d')+'.iso',child:'UMD_DATA.BIN'});
  console.log('PASS: video without optional SFO title retains its identifier and navigable inventory.');
}

{
  const data = catalog([
    {sha256:H('1'),size_bytes:2048,entries:[]},
    {sha256:H('2'),size_bytes:2048,metadata:{title:'Known title'},entries:[]},
    {sha256:H('3'),size_bytes:2048,metadata,entries},
  ]);
  data.trees.iso[H('1')].error = 'MissingUmdData';
  await build(data);
  const isos = cat().children(nodeAt(cat(), 'umd/other')).concat(cat().children(nodeAt(cat(), 'umd/game')));
  const byHash = hash => isos.find(n => cat().knownHash(n) === hash);
  const failed = byHash(H('1'));
  assert.equal(cat().label(failed), H('1')+'.iso');
  assert.equal(cat().path(failed), 'umd/other/'+H('1')+'.iso');
  assert.equal(cat().extraction(failed).error, 'MissingUmdData');
  assert.equal(cat().label(byHash(H('2'))), 'Known title');
  assert.equal(cat().label(byHash(H('3'))), 'ULJS-00009/1.00 AI Shogi');
  console.log('PASS: metadata-free failed ISO retains hash/error, optional identifiers work, healthy siblings remain browsable.');
}

// A single hash-keyed extraction attaches to both occurrences, without replacing
// the original file's identity or counting expanded bytes in its parent's size.
const baseFixture = () => catalog(['a','b'].map(char=>({sha256:H(char),metadata,entries,size_bytes:2048})));
{
  const data = baseFixture();
  data.trees.prx = {
    [H('c')]: {size_bytes:48,extractor:{name:'pspdecrypt'},entries:[
      {path:'F0/module.prx',type:'file',size_bytes:1024,sha256:H('e')},
      {path:'again.bin',type:'file',size_bytes:48,sha256:H('c')},
    ]},
  };
  await build(data);
  for (const iso of cat().children(nodeAt(cat(), 'umd/game'))) {
    const source = cat().children(iso)[0];
    assert.equal(cat().size[iso], 2048);
    assert.equal(await fullHash(source), H('c'));
    assert.ok(cat().isFile(source) && cat().expandable(source));
    assert.deepEqual(childNames(cat(), source), ['F0', 'again.bin']);
    const [folder, again] = cat().children(source);
    assert.equal(await fullHash(cat().children(folder)[0]), H('e'));
    assert.equal(cat().children(again).length, 0, 'an extraction never re-enters itself');
    assert.equal(cat().size[source], 48);
  }
  assert.equal((await search(H('e'))).length, 2);
  console.log('PASS: shared extraction subtrees, source sizes/hashes, searchable children, cycle termination.');
}

{
  const data = catalog([{sha256:H('a'),metadata,size_bytes:2048,entries:[
    {path:'OPNSSMP.BIN',type:'file',size_bytes:48,sha256:H('c')},
    {path:'ALIAS.BIN',type:'file',size_bytes:48,sha256:H('c')},
  ]}]);
  Object.assign(data.trees, {
    prx: {[H('c')]: {size_bytes:48,extractor:{name:'pspdecrypt'},name_rule:'source_stem',entries:[
      {path:'module.prx.gz',type:'file',size_bytes:32,sha256:H('e')},
    ]}},
    gzip: {[H('e')]: {size_bytes:32,extractor:{name:'gzip'},name_rule:'strip_suffix',entries:[
      {path:'module.prx',type:'file',size_bytes:64,sha256:H('f')},
    ]}},
  });
  await build(data);
  const found = [];
  for (let node = 0; node < cat().count; node++) {
    const hash = cat().isFile(node) && cat().slot[node] >= 0 ? await fullHash(node) : null;
    if (hash === H('e') || hash === H('f')) found.push(cat().nameOf(node));
  }
  // Children sort by name: ALIAS before OPNSSMP.
  assert.deepEqual(found, ['ALIAS.prx.gz','ALIAS.prx','OPNSSMP.prx.gz','OPNSSMP.prx']);
  console.log('PASS: shared executable trees inherit each occurrence name through decompression.');
}

// PSN packages are root siblings of UMD and retain their exact package hash.
await build({records:{iso:[],pkg:[{sha256:H('9'),size_bytes:123,psn_kind:'neogeo',
  metadata:{content_type:16,content_id:'UP9000-NPUG00001_00-FIXTURE',title:'Demo'}}]},trees:{pkg:{
    [H('9')]:{size_bytes:123,extractor:{name:'pspdb-ingest'},entries:[{path:'PARAM.SFO',type:'file',size_bytes:10,sha256:H('8')}]}}}});
{
  const node = nodeAt(cat(), 'psn/neogeo/'+H('9')+'.pkg');
  assert.equal(cat().knownHash(node), H('9'));
  assert.equal(cat().size[node], 123);
  assert.equal(cat().label(node), 'NPUG-00001 Demo');
  assert.deepEqual(childNames(cat(), node), ['PARAM.SFO']);
  assert.deepEqual(names(await search('up9000-npug00001_00-fixture')), [H('9')+'.pkg', 'PARAM.SFO']);
  console.log('PASS: PSN package grouping, identity, label, and attached inventory; full content-ID search.');
}

{
  const labels = [...catalogModule.packageLabels([
    {sha256:'aaaaaaaa0'+'0'.repeat(55),metadata:{title:' Demo  title ',title_id:'NPUG00001'}},
    {sha256:'aaaaaaaa1'+'0'.repeat(55),metadata:{title:'Demo title',content_id:'UP9000-NPUG00001_00-OTHER'}},
    {sha256:H('b'),metadata:{}},
  ]).values()];
  assert.deepEqual(labels,['NPUG-00001 Demo title · aaaaaaaa0','NPUG-00001 Demo title · aaaaaaaa1','Untitled package · bbbbbbbb']);
  console.log('PASS: compact package titles, unique collision suffixes and metadata fallback.');
  assert.equal(catalogModule.packageSerial({title_id:'npug80135'}), 'NPUG-80135');
  assert.equal(catalogModule.packageSerial({title_id:'NPUG-80135'}), 'NPUG-80135');
  console.log('PASS: serial-first package labels share UMD ID formatting.');
}

// Server-computed kinds own the grouping; package_flags and content_type stay ignored.
await build({records:{pkg:[
  {sha256:H('1'),size_bytes:1,psn_kind:'patch',metadata:{content_type:7,package_flags:0x8000021c}},
  {sha256:H('2'),size_bytes:1,psn_kind:'game',metadata:{content_type:7,package_flags:0x20c}},
  {sha256:H('3'),size_bytes:1,psn_kind:'theme',metadata:{content_type:9,package_flags:0x21c}},
  {sha256:H('4'),size_bytes:1,psn_kind:'dlc',metadata:{content_type:7}},
  {sha256:H('5'),size_bytes:1,metadata:{content_type:7,package_flags:0x8000021c}},
]},trees:{}});
{
  const files = [];
  for (let node = 0; node < cat().count; node++) if (cat().isFile(node)) files.push(cat().path(node));
  assert.deepEqual(files.sort(),[
    'psn/dlc/'+H('4')+'.pkg', 'psn/game/'+H('2')+'.pkg', 'psn/patch/'+H('1')+'.pkg',
    'psn/theme/'+H('3')+'.pkg', 'psn/unknown/'+H('5')+'.pkg',
  ]);
  console.log('PASS: server kinds group every package, no package sits at the PSN root, missing kinds fall back to unknown.');
}

// Contextual output is bound to one file occurrence, not globally to its hash.
const sourceHash = H('1'), payloadHash = H('2');
const inlineTree = {sha256:sourceHash,size_bytes:14,extractor:{name:'pops'},name_rule:'source_stem',entries:[
  {path:'payload.gz',type:'file',sha256:payloadHash,size_bytes:7},
]};
const contextFixture = catalog([{sha256:H('3'),size_bytes:100,metadata,entries:[
  {path:'DATA.BIN',type:'file',sha256:H('4'),size_bytes:50},
  {path:'DATA.PSP',type:'file',sha256:sourceHash,size_bytes:14,extraction:inlineTree},
  {path:'OTHER.PSP',type:'file',sha256:sourceHash,size_bytes:14},
  {path:'WRONG.PSP',type:'file',sha256:H('5'),size_bytes:14,extraction:inlineTree},
]}]);
await build(contextFixture);
{
  const iso = cat().children(nodeAt(cat(), 'umd/game'))[0];
  const kids = Object.fromEntries(cat().children(iso).map(n => [cat().nameOf(n), n]));
  assert.deepEqual(childNames(cat(), kids['DATA.PSP']), ['DATA.gz']);
  assert.equal(await fullHash(cat().children(kids['DATA.PSP'])[0]), payloadHash);
  for (const name of ['DATA.BIN','OTHER.PSP','WRONG.PSP']) assert.deepEqual(childNames(cat(), kids[name]), []);
  console.log('PASS: PBP-scoped output attaches only to its matching DATA.PSP occurrence.');
}

// Decode-stage naming uses the observed format instead of dropping it.
for (const [source, path, expected] of [
  ['DATA.gz','module.elf','DATA.elf'],
  ['DATA.elf.gz','module.elf','DATA.elf'],
  ['DATA.prx.gz','module.elf','DATA.elf'],
  ['archive.gz','payload.bin','archive'],
  ['notes.txt.gz','payload.bin','notes.txt'],
  ['DATA.gz.gz','payload.gz','DATA.gz'],
]) assert.equal(catalogModule.extractedName(source, path, 'decoded_suffix'), expected);
{
  const data = structuredClone(contextFixture);
  data.trees.gzip = {[payloadHash]: {size_bytes:7,extractor:{name:'gzip'},name_rule:'decoded_suffix',entries:[
    {path:'module.elf',type:'file',size_bytes:20,sha256:H('6')},
  ]}};
  await build(data);
  let decoded = null;
  for (let node = 0; node < cat().count; node++)
    if (cat().isFile(node) && cat().slot[node] >= 0 && await fullHash(node) === H('6')) decoded = cat().nameOf(node);
  assert.equal(decoded, 'DATA.elf');
  console.log('PASS: decoded ELF suffix survives contextual gzip naming without duplicate suffixes.');
}

{
  await build(catalog([{sha256:H('3'),size_bytes:100,metadata,entries:[
    {path:'DATA.BIN',type:'file',size_bytes:42,sha256:H('7'),redump:[{id:38300,name:'Saikyou Ginsei Chess'}]},
    {path:'PLAIN.BIN',type:'file',size_bytes:42,sha256:H('8'),redump:[]},
  ]}]));
  const [data, plain] = cat().children(nodeAt(cat(), 'umd/game/'+H('3')+'.iso'));
  assert.equal(cat().attrsOf(data).redump[0].id, 38300);
  assert.equal(cat().attrsOf(plain), undefined);
  console.log('PASS: nested reconstructed discs retain exact Redump annotations.');
}

// The same bytes can be an original ISO, a package root, and a nested ISO9660 image.
// Inventories belong to those observations, not to the hash alone.
const roleHash = H('7'), parentHash = H('8'), rootOnlyHash = H('0');
const roleLeaf = name => ({path:name,type:'file',size_bytes:1,sha256:H('9')});
const roleFixture = catalog([
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
roleFixture.records.pkg = [{sha256:roleHash,size_bytes:42,metadata:{title:'Package role',title_id:'NPUG00001'}}];
roleFixture.trees.pkg = {[roleHash]: {size_bytes:42,extractor:{name:'pkg'},entries:[roleLeaf('package-only.bin')]}};
roleFixture.trees.iso9660 = {[roleHash]: {size_bytes:42,extractor:{name:'iso9660'},entries:[
  roleLeaf('nested-only.bin'), {path:'again.iso',type:'file',size_bytes:42,sha256:roleHash},
]}};
await build(roleFixture);
{
  const original = nodeAt(cat(), 'umd/game/'+H('7')+'.iso'), parent = nodeAt(cat(), 'umd/game/'+H('8')+'.iso');
  const named = (node, name) => cat().children(node).find(n => cat().nameOf(n) === name);
  const nested = named(parent, 'nested.iso');
  assert.deepEqual({
    root:childNames(cat(), original), nested:childNames(cat(), nested),
    self:childNames(cat(), named(original, 'self.iso')),
    cycle:childNames(cat(), named(nested, 'again.iso')),
    hash:await fullHash(nested), size:cat().size[nested],
    rootFallback:childNames(cat(), named(parent, 'root-observation-only.iso')),
    inline:childNames(cat(), named(parent, 'inline.iso')),
    pkg:childNames(cat(), nodeAt(cat(), 'psn/unknown/'+H('7')+'.pkg')),
  }, {
    root:['root-only.bin','self.iso'],nested:['again.iso','nested-only.bin'],
    self:['again.iso','nested-only.bin'],cycle:[],hash:roleHash,size:42,
    rootFallback:[],inline:['inline-only.bin'],pkg:['package-only.bin'],
  });
  console.log('PASS: same-hash root, nested, package, and inline inventories retain their own names and byte identity.');
}

{
  const ambiguous = structuredClone(roleFixture);
  ambiguous.trees.prx = {[roleHash]: {size_bytes:42,extractor:{name:'prx'},entries:[roleLeaf('wrong-kind.bin')]}};
  assert.throws(() => rebuild(ambiguous), /Ambiguous non-root extraction kinds/);
  // Inline extraction remains authoritative even when no global kind can be selected.
  const inline = catalog([{sha256:parentHash,size_bytes:100,metadata,entries:[
    {path:'inline.iso',type:'file',size_bytes:42,sha256:roleHash,extraction:{
      sha256:roleHash,size_bytes:42,extractor:{name:'contextual'},entries:[roleLeaf('inline-only.bin')],
    }},
  ]}]);
  inline.trees.iso9660 = {[roleHash]: {size_bytes:42,extractor:{name:'iso9660'},entries:[]}};
  inline.trees.prx = ambiguous.trees.prx;
  await build(inline);
  const holder = cat().children(nodeAt(cat(), 'umd/game/'+H('8')+'.iso'))[0];
  assert.equal(cat().nameOf(holder), 'inline.iso');
  assert.deepEqual(childNames(cat(), holder), ['inline-only.bin']);
  const conflicting = structuredClone(roleFixture);
  conflicting.trees.iso9660[roleHash].size_bytes++;
  assert.throws(() => rebuild(conflicting), /Conflicting source sizes/);
  console.log('PASS: ambiguous byte references and cross-role size conflicts fail explicitly; inline extraction overrides lookup.');
}

// Updater roots and generic PBP occurrences can observe the same bytes independently.
const updaterHash = H('a'), variantHash = H('b'), missingTreeHash = H('c');
const updateRecord = (sha256, size_bytes, metadata = {}) => ({sha256, size_bytes, metadata});
const updateTree = (size_bytes, name) => ({
  size_bytes, extractor:{name:'pspdb-update', version:'1', options:[]}, entries:[roleLeaf(name)],
});
await build({
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
});
{
  const updates = nodeAt(cat(), 'firmware/update');
  const roots = cat().children(updates).map(node => ({
    hash:cat().knownHash(node), size:cat().size[node], path:cat().path(node),
    url:vm.runInContext(`url(${node})`, context), children:childNames(cat(), node),
  })).sort((a,b)=>a.hash.localeCompare(b.hash));
  assert.deepEqual(roots, [
    {hash:updaterHash, size:42, path:`firmware/update/${updaterHash}.pbp`,
      url:`#firmware/update/${updaterHash}.pbp`, children:['DATA.BIN']},
    {hash:variantHash, size:43, path:`firmware/update/${variantHash}.pbp`,
      url:`#firmware/update/${variantHash}.pbp`, children:['DATA.BIN']},
    {hash:missingTreeHash, size:44, path:`firmware/update/${missingTreeHash}.pbp`,
      url:`#firmware/update/${missingTreeHash}.pbp`, children:[]},
  ]);
  assert.equal(cat().size[updates], 129);
  assert.deepEqual(childNames(cat(), nodeAt(cat(), 'psn/patch/'+H('8')+'.pkg/EBOOT.PBP')), ['generic-only.bin']);
  for (const term of ['6.61', 'system software', 'ucjs10041', updaterHash])
    assert.ok((await search(term)).some(node => cat().knownHash(node) === updaterHash));
  console.log('PASS: updater variants retain full raw identities, sizes, searchable metadata and root-specific inventories beside generic PBP and PSN update roles.');
}

// Refinements must not retain ancestor matches when a term becomes hash-only,
// and extraction failures belong only to their exact source occurrence.
const hashRoot = 'deadbeef' + '0'.repeat(56), duplicateHash = H('f');
const searchFixture = catalog([{sha256:hashRoot, size_bytes:100,
  metadata:{...metadata,title:'Ancestor title'}, entries:[
    {path:'one.bin',type:'file',size_bytes:10,sha256:duplicateHash},
    {path:'two.bin',type:'file',size_bytes:10,sha256:duplicateHash},
    {path:'broken.bin',type:'file',size_bytes:10,sha256:H('e'),extraction:{
      sha256:H('e'),size_bytes:10,extractor:{name:'partial'},error:'ChildFailure',
      entries:[{path:'decoded.bin',type:'file',size_bytes:5,sha256:H('d')}],
    }},
  ]}]);
searchFixture.trees.iso[hashRoot].error = 'ParentFailure';
await build(searchFixture);
assert.equal((await search('deadbee')).length, 5);
assert.deepEqual(await hashes(await search('DEADBEEF')), [hashRoot]);
assert.equal((await search(hashRoot+'.iso')).length, 5);
assert.deepEqual(names(await search(duplicateHash)), ['one.bin','two.bin']);
assert.deepEqual(names(await search('ANCESTOR two.bin')), ['two.bin']);
assert.deepEqual(await hashes(await search('ParentFailure')), [hashRoot]);
assert.deepEqual(names(await search('ChildFailure')), ['broken.bin']);
const defaultOrder = paths(await search('ancestor'));
assert.deepEqual((await search('ancestor','size')).map(id => cat().size[id]), [5,10,10,10,100]);
assert.deepEqual((await search('ancestor','size',-1)).map(id => cat().size[id]), [100,10,10,10,5]);
assert.deepEqual(paths(await search('ancestor')), defaultOrder);
// Hash order is the digest's byte order; names sort by label, digit runs numerically.
assert.deepEqual(await hashes(await search('ancestor','hash')), [H('d'), hashRoot, H('e'), duplicateHash, duplicateHash]);
assert.deepEqual(names(await search('ancestor','name')).slice(0, 2), ['broken.bin','decoded.bin']);

// Sparse results exercise candidate-only matching, including ancestor text,
// own errors, duplicate hashes and broadening back to the complete index.
{
  const data = structuredClone(searchFixture);
  const unrelatedHash = H('9');
  data.records.iso.push({sha256:unrelatedHash,size_bytes:128,metadata:{title:'Unrelated'}});
  data.trees.iso[unrelatedHash] = {size_bytes:128,extractor:{name:'iso'},
    entries:Array.from({length:128},(_,i)=>({path:`other-${i}.bin`,type:'file',size_bytes:1,
      sha256:i.toString(16).padStart(8,'0')+'abcdef00'+'0'.repeat(48)}))};
  await build(data);
  assert.equal((await search('ancestor')).length, 5);
  assert.deepEqual(names(await search('ancestor bin')).sort(), ['broken.bin','decoded.bin','one.bin','two.bin']);
  assert.deepEqual(names(await search('ancestor bin child')), ['broken.bin']);
  assert.deepEqual(names(await search('ancestor bin')).sort(), ['broken.bin','decoded.bin','one.bin','two.bin']);
  assert.deepEqual(names(await search('ffffffff')).sort(), ['one.bin','two.bin']);
  assert.deepEqual(names(await search(duplicateHash)).sort(), ['one.bin','two.bin']);
  assert.equal((await search('deadbee')).length, 5);
  assert.deepEqual(await hashes(await search('deadbeef')), [hashRoot]);
  assert.deepEqual(names(await search('ancestor absent')), []);
  assert.deepEqual(names(await search('ancestor absent-longer')), []);
  assert.equal((await search('ancestor')).length, 5);
  // Refining a hash term by typing more digits keeps only the longer prefix's matches.
  assert.equal((await search('00000001')).length, 1);
  assert.equal((await search('00000001a')).length, 1);
  assert.equal((await search('00000001b')).length, 0);
  console.log('PASS: sparse refinements preserve ancestor context, own errors, duplicate hashes, hash transitions, empty results and broadening.');
}

// Hash terms are prefix-anchored: up to 16 digits match the 8-byte prefix locally,
// longer terms are verified against full digests fetched by chunk.
{
  const tail = 'abcdef0123456789' + H('0',47) + '1';
  await build(catalog([{sha256:H('1'), size_bytes:100, metadata, entries:[
    {path:'tail.bin',type:'file',size_bytes:1,sha256:tail},
    {path:'other.bin',type:'file',size_bytes:3,sha256:'abcdef0123450000'+H('2',48)},
  ]}]));
  assert.deepEqual(names(await search('abcdef01')).sort(), ['other.bin','tail.bin']);
  assert.deepEqual(names(await search('abcdef0123456789')), ['tail.bin']);
  assert.deepEqual(names(await search('bcdef012')), [], 'a hash term is anchored at the start of the digest');
  assert.deepEqual(names(await search('cdef0123 tail')), [], 'mid-hash text is not matched');
  assert.deepEqual(names(await search(tail)), ['tail.bin']);
  assert.deepEqual(names(await search(tail.slice(0, 40))), ['tail.bin']);
  // Same first 16 digits, wrong remainder: only the full digest can refuse it.
  assert.deepEqual(names(await search(tail.slice(0, 63) + '2')), []);
  assert.deepEqual(names(await search('abcdef0123456789 ancestor')), []);
  assert.deepEqual(names(await search('abcdef0123456789 shogi')), ['tail.bin']);
  // The encoder refuses two digests that share an 8-byte prefix instead of mis-merging them.
  assert.throws(() => encodeFixture(catalog([{sha256:H('1'), size_bytes:100, metadata, entries:[
    {path:'x.bin',type:'file',size_bytes:1,sha256:tail},
    {path:'y.bin',type:'file',size_bytes:1,sha256:tail.slice(0, 63) + '2'}]}])), /prefix collision/);
  console.log('PASS: hash search is prefix-anchored; terms past 16 digits verify full digests lazily; prefix collisions fail loudly.');
}

// Chunk addressing: slot i lives in chunk i div 4096 at offset (i mod 4096) * 32.
{
  const files = 4096 + 9;
  const digest = i => (i + 1).toString(16).padStart(8,'0') + 'cafe0000' + H('5',48);
  const bulk = Array.from({length:files}, (_, i) => ({path:`f${i}.bin`,type:'file',size_bytes:i,sha256:digest(i)}));
  await build(catalog([{sha256:H('1'), size_bytes:100, metadata, entries:bulk}]));
  const store = vm.runInContext('hashStore', context);
  // The ISO's own digest is slot 0; file i then takes slot i + 1.
  assert.equal(store.count, files + 1);
  // Slots follow first use, i.e. the (sorted) child order, so look files up by slot.
  const bySlot = new Map(cat().children(nodeAt(cat(), 'umd/game/'+H('1')+'.iso')).map(node => [cat().slot[node], node]));
  for (const slot of [4095, 4096, 4105, 1]) {
    const node = bySlot.get(slot), index = Number(/^f(\d+)\.bin$/.exec(cat().nameOf(node))[1]);
    assert.equal(await fullHash(node), digest(index), `slot ${slot}`);
  }
  const requests = viewer.state.server.requests;
  assert.equal(requests.length, 2, 'one request per chunk, cached afterwards');
  assert.ok(requests.every(url => /api\/hashes\/[0-9a-f]{16}\/[01]$/.test(url)));
  assert.equal(await fullHash(nodeAt(cat(), 'umd/game/'+H('1')+'.iso')), H('1'), 'records carry their own digest');
  assert.equal(await (async () => { try { await store.load(7); } catch (error) { return error.message; } })(), 'Hash chunk 7: HTTP 404');
  console.log('PASS: full hashes resolve by 4096-slot chunk, including the short last chunk, with one fetch per chunk.');
}

// A chunk from another export (or a tampered one) is rejected against the prefixes.
{
  const encoded = await build(catalog([{sha256:H('1'), size_bytes:100, metadata, entries}]));
  const leaf = cat().children(nodeAt(cat(), 'umd/game/'+H('1')+'.iso'))[0];
  const bad = Uint8Array.from(encoded.chunks[0]);
  bad[32 * cat().slot[leaf]] ^= 1;
  viewer.state.server = {requests:[], respond: async () => ({ok:true, status:200, arrayBuffer: async () => bad.buffer})};
  await assert.rejects(fullHash(leaf), /does not match the catalog/);
  // A server that has moved on answers 409; the page reloads instead of showing stale digests.
  const timers = [];
  context.setTimeout = callback => timers.push(callback);
  viewer.state.server = {requests:[], respond: async () => ({ok:false, status:409})};
  await assert.rejects(fullHash(leaf), error => error.name === 'StaleCatalogError');
  assert.equal(timers.length, 1, 'a stale generation schedules a catalog reload');
  context.setTimeout = setTimeout;
  console.log('PASS: chunks are checked against the catalog prefixes; a 409 generation schedules a reload.');
}

// Hash lookup failures in the worker are reported per query and do not break search.
{
  const data = catalog([{sha256:H('1'), size_bytes:100, metadata, entries:[
    {path:'tail-a.bin',type:'file',size_bytes:1,sha256:'abcdef0123456789'+H('0',48)}]}]);
  await build(data, {status:500});
  const failed = await viewer.query('abcdef0123456789'+H('0',48));
  assert.equal(failed.type, 'hash-error');
  assert.match(failed.message, /Could not verify a long SHA-256/);
  assert.deepEqual(names(await search('tail-a')), ['tail-a.bin']);
  await build(data, {status:409});
  assert.equal((await viewer.query('abcdef0123456789'+H('0',48))).type, 'stale');
  console.log('PASS: failed or stale long-hash verification is reported without disabling search.');
}
// Rows are ordered by the viewer too: directories first, then labels in UTF-16 order,
// whatever order a container happens to list them in.
{
  const jumbled = catalog([{sha256:H('1'), size_bytes:100, metadata, entries:[
    {path:'zeta.bin',type:'file',size_bytes:1,sha256:H('a')},
    {path:'Beta/inner.bin',type:'file',size_bytes:1,sha256:H('b')},
    {path:'alpha.bin',type:'file',size_bytes:1,sha256:H('c')},
    {path:'Alpha.bin',type:'file',size_bytes:1,sha256:H('d')},
    {path:'\u{1F600}.bin',type:'file',size_bytes:1,sha256:H('e')},
    {path:'\uFF21.bin',type:'file',size_bytes:1,sha256:H('f')},
    {path:'beta/inner.bin',type:'file',size_bytes:1,sha256:H('0')},
  ]}]);
  const encoded = await build(jumbled, {unsorted:true});
  const iso = nodeAt(cat(), 'umd/game/'+H('1')+'.iso');
  // Directories first; names compare by UTF-16 code unit (an astral character, a surrogate pair, precedes U+FF21).
  assert.deepEqual(childNames(cat(), iso), ['Beta','beta','Alpha.bin','alpha.bin','zeta.bin','\u{1F600}.bin','\uFF21.bin']);
  console.log('PASS: rows are ordered directories-first by label even when the container lists them otherwise.');
}

// A damaged or foreign container is refused with a clear error, never half-decoded.
{
  const good = encodeFixture(catalog([{sha256:H('1'), size_bytes:100, metadata, entries}])).bytes;
  assert.doesNotThrow(() => catalogModule.parseContainer(good));
  assert.throws(() => catalogModule.parseContainer(good.subarray(0, 5)), /Truncated/);
  assert.throws(() => catalogModule.parseContainer(good.subarray(0, Math.floor(good.length / 2))), /Truncated/);
  const foreign = Uint8Array.from(good); foreign[0] = 0x7b;
  assert.throws(() => catalogModule.parseContainer(foreign), /Not a PSPDB catalog container/);
  const future = Uint8Array.from(good); future[6] = 5;
  assert.throws(() => catalogModule.parseContainer(future), /Unsupported catalog container version 5/);
  console.log('PASS: truncated, foreign and future containers are refused explicitly.');
}

// The live API hands the browser an identity body (the browser undoes Content-Encoding);
// the static export is a gzip file the page inflates itself. Both decode to the same catalog.
{
  const {gzipSync} = await import('node:zlib');
  const encoded = encodeFixture(catalog([{sha256:H('1'), size_bytes:100, metadata, entries}]));
  for (const [url, body, headers] of [
    ['api/catalog', Buffer.from(encoded.bytes), {'Content-Length': String(encoded.bytes.length)}],
    ['api/catalog', Buffer.from(encoded.bytes), {'Content-Encoding': 'zstd'}],
    ['catalog.bin.gz', gzipSync(encoded.bytes, {level: 9}), {}],
  ]) {
    const loader = createViewer({catalogUrl: url});
    const status = {textContent: ''}, detail = {textContent: ''};
    loader.elements.set('loading-status', status);
    loader.elements.set('download-detail', detail);
    loader.state.server = {requests: [], respond: async () => new Response(body, {headers})};
    const built = await loader.run('loadCatalog()');
    assert.equal(built.count, 8, url);
    assert.deepEqual(Array.from(built.children(built.find('umd/game/'+H('1')+'.iso')), n => built.nameOf(n)), ['UMD_DATA.BIN']);
    assert.equal(status.textContent, 'Preparing catalog…');
    assert.match(detail.textContent, headers['Content-Encoding'] ? /received \(decoded\)/ : /received|100%/);
    loader.stop();
  }
  // A failed request is reported, not swallowed.
  const failing = createViewer();
  failing.state.server = {requests: [], respond: async () => ({ok: false, status: 503})};
  await assert.rejects(failing.run('loadCatalog()'), /HTTP 503/);
  console.log('PASS: identity, content-decoded and gzip catalog bodies load identically, with progress; HTTP failures surface.');
}
viewer.stop();

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
  const el = {addEventListener(){}, setAttribute(){}, removeAttribute(){}};
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
  vm.runInContext(sources.catalog, scrollContext);
  vm.runInContext(sources.app, scrollContext);
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
