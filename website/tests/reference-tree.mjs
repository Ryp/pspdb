// Test oracle: the object-per-row tree builder the viewer used before the
// typed-array occurrence tree, kept only to prove the new tree is equivalent.
// Input is a catalog data dict (what the server's `catalog_data` returns).
import assert from 'node:assert/strict';
import {catalogModule} from './viewer-support.mjs';

const {extractedName, packageLabels, packageSerial, referenceUUID} = catalogModule;
const emptyChildren = Object.freeze([]);

class RefNode {
  constructor(parent, name, data) {
    this.parent = parent; this.name = name; this.type = 'directory';
    this.children = emptyChildren; this.size = 0;
    Object.assign(this, data);
  }
}
const label = node => node.displayName || node.name;

export function referenceTree(data) {
  const nodes = [];
  const add = (parent, name, extra = {}) => {
    const node = new RefNode(parent, name, extra);
    nodes.push(node);
    if (parent) {
      if (parent.children === emptyChildren) parent.children = [];
      parent.children.push(node);
    }
    return node;
  };
  function addInventory(parent, entries, extractions, ancestors, nameRule) {
    const directories = new Map([['', parent]]);
    for (const entry of entries) {
      const parts = entry.path.split('/');
      const name = extractedName(parent.name, parts.pop(), nameRule);
      let path = '', directory = parent;
      for (const part of parts) {
        path = path ? `${path}/${part}` : part;
        if (!directories.has(path)) directories.set(path, add(directory, part));
        directory = directories.get(path);
      }
      if (entry.type === 'directory') {
        if (!directories.has(entry.path)) directories.set(entry.path, add(directory, name));
      } else {
        const node = add(directory, name, {type: 'file', size: entry.size_bytes, hash: entry.sha256, redump: entry.redump || emptyChildren});
        if (entry.extraction || extractions[node.hash] !== undefined)
          attachExtraction(node, extractions, ancestors, entry.extraction);
      }
    }
  }
  function attachExtraction(node, extractions, ancestors = new Set(), contextual = null, source = null) {
    const extraction = contextual || (source === null ? extractions[node.hash] : source[node.hash]);
    if (extraction === null) throw new Error(`Ambiguous non-root extraction kinds: ${node.hash}`);
    if (!extraction || (contextual && extraction.sha256 !== node.hash) || extraction.size_bytes !== node.size || ancestors.has(extraction)) return;
    node.extraction = extraction.extractor.name;
    node.extractionKind = extraction.extraction_kind;
    node.extractionVersion = extraction.extractor.version;
    if (extraction.error) {
      node.error = extraction.error;
      for (let ancestor = node.parent; ancestor; ancestor = ancestor.parent)
        ancestor.errorCount = (ancestor.errorCount || 0) + 1;
    }
    if (extraction.stale_extraction) node.stale_extraction = extraction.stale_extraction;
    addInventory(node, extraction.entries, extractions, new Set([...ancestors, extraction]), extraction.name_rule);
  }
  const group = (parent, name, extra = {}) => add(parent, name, {...extra, virtual: true});

  const root = group(null, '');
  root.name = 'psp';
  const population = data.coverage || {};
  const umdPopulation = population.umd || null, psnPopulation = population.psn || null;
  const umdSnapshot = [umdPopulation?.source?.name, umdPopulation?.source?.version].filter(Boolean).join(' ');
  const umd = group(root, 'umd', umdPopulation
    ? {coverage: {present: umdPopulation.present, total: umdPopulation.total, noun: 'UMD discs',
                  source: 'Redump', snapshot: umdSnapshot, href: 'http://redump.org/discs/system/psp/'}} : {});
  const categories = new Map();
  const mediaGroup = code => {
    const name = code === 'G' ? 'game' : code === 'V' ? 'video' : 'other';
    if (!categories.has(name)) categories.set(name, group(umd, name));
    return categories.get(name);
  };
  const extractions = Object.create(null), sizes = new Map();
  for (const [kind, sources] of Object.entries(data.trees)) {
    for (const [hash, tree] of Object.entries(sources)) {
      if (sizes.has(hash) && sizes.get(hash) !== tree.size_bytes) throw new Error(`Conflicting source sizes: ${hash}`);
      sizes.set(hash, tree.size_bytes);
      if (kind === 'iso' || kind === 'pkg' || kind === 'nand' || kind === 'update') continue;
      extractions[hash] = hash in extractions ? null : tree;
    }
  }
  const records = data.records || {};
  for (const iso of records.iso || []) {
    const metadata = iso.metadata || {};
    const category = mediaGroup(metadata.media_code);
    const id = (metadata.disc_id || metadata.identifier || '').trim().replace(/^([A-Z]{4})-?([0-9]{5})$/, '$1-$2');
    const identity = [id, metadata.disc_version].filter(Boolean).join('/');
    const displayName = metadata.media_code === 'V'
      ? metadata.title?.trim() || identity
      : [identity, metadata.title?.trim()].filter(Boolean).join(' ');
    const node = add(category, `${iso.sha256}.iso`, {
      type: 'file', umdatabase: iso.umdatabase || [], hash: iso.sha256, size: iso.size_bytes, displayName,
      serialstation_discs: (iso.serialstation_discs || []).filter(match => referenceUUID(match.id)),
      gamePrefix: metadata.media_code === 'G' ? identity : null,
    });
    attachExtraction(node, extractions, new Set(), null, data.trees.iso || {});
  }
  const packages = records.pkg || [];
  if (packages.length) {
    const psn = group(root, 'psn', psnPopulation
      ? {coverage: {present: psnPopulation.present, total: psnPopulation.total, noun: 'PSN packages',
                    source: 'NoPayStation', href: 'https://nopaystation.com/'}} : {});
    const labels = packageLabels(packages), groups = new Map();
    for (const pkg of packages) {
      const metadata = pkg.metadata || {};
      const category = pkg.psn_kind || 'unknown';
      if (!groups.has(category)) groups.set(category, group(psn, category));
      const node = add(groups.get(category), `${pkg.sha256}.pkg`, {
        type: 'file', hash: pkg.sha256, size: pkg.size_bytes, serialstation: pkg.serialstation || null,
        displayName: labels.get(pkg.sha256), gamePrefix: packageSerial(metadata) || null,
        searchMetadata: metadata.content_id || '',
      });
      attachExtraction(node, extractions, new Set(), null, data.trees.pkg || {});
    }
  }
  const firmware = group(root, 'firmware');
  const nandGroup = group(firmware, 'nand'), updateGroup = group(firmware, 'update');
  for (const nand of records.nand || []) {
    const metadata = nand.metadata || {};
    const valid = metadata.page_bytes === 512 && metadata.spare_bytes === 16
      && metadata.pages_per_block === 32 && (metadata.blocks === 2048 || metadata.blocks === 4096)
      && nand.size_bytes === metadata.blocks * 32 * 528;
    const node = add(nandGroup, `${nand.sha256}.nand`, {
      type: 'file', hash: nand.sha256, size: nand.size_bytes,
      displayName: valid ? `${metadata.blocks / 64} MiB NAND · ${nand.sha256.slice(0, 12)}` : null,
    });
    attachExtraction(node, extractions, new Set(), null, data.trees.nand || {});
  }
  for (const update of records.update || []) {
    const metadata = update.metadata || {};
    const version = metadata.updater_version?.trim();
    const node = add(updateGroup, `${update.sha256}.pbp`, {
      type: 'file', hash: update.sha256, size: update.size_bytes,
      displayName: version ? `Update ${version}${metadata.updater_target === 'psp-go' ? ' Go' : ''} · ${update.sha256.slice(0, 12)}` : null,
      searchMetadata: [metadata.title, metadata.disc_id].filter(Boolean).join(' '),
    });
    attachExtraction(node, extractions, new Set(), null, data.trees.update || {});
  }
  const rows = [], pending = [root];
  while (pending.length) {
    const node = pending.pop();
    if (node.children.length > 1) node.children.sort((a, b) => (a.type === b.type ? 0 : a.type === 'directory' ? -1 : 1)
      || (label(a) < label(b) ? -1 : label(a) > label(b) ? 1 : 0));
    rows.push(node);
    for (let i = node.children.length - 1; i >= 0; i--) pending.push(node.children[i]);
  }
  for (let i = nodes.length - 1; i > 0; i--) {
    const node = nodes[i], parent = node.parent;
    if (parent.type === 'directory') parent.size += node.size;
  }
  return rows;
}

const list = value => value == null ? [] : Array.isArray(value) ? value : [value];

// Compare the reference tree with a Catalog row by row: structure, names, sizes,
// full hashes, extraction state, error counters and per-row annotations.
export function assertMatchesReference(catalog, data, digests) {
  const reference = referenceTree(data);
  assert.equal(catalog.count, reference.length, 'occurrence count');
  const index = new Map(reference.map((node, i) => [node, i]));
  for (let i = 0; i < reference.length; i++) {
    const want = reference[i];
    const where = `row ${i} (${catalog.path(i)})`;
    assert.equal(catalog.parent[i], want.parent ? index.get(want.parent) : -1, `${where} parent`);
    assert.equal(catalog.nameOf(i), want.name, `${where} name`);
    assert.equal(catalog.label(i), label(want), `${where} label`);
    assert.equal(catalog.isFile(i), want.type === 'file', `${where} type`);
    assert.equal(catalog.isVirtual(i), Boolean(want.virtual), `${where} virtual`);
    assert.equal(catalog.size[i], want.size ?? 0, `${where} size`);
    const hash = catalog.slot[i] >= 0 ? (catalog.knownHash(i) ?? digests[catalog.slot[i]]) : undefined;
    assert.equal(hash, want.hash, `${where} hash`);
    const extraction = catalog.extraction(i);
    assert.equal(extraction !== null, Boolean(want.extraction), `${where} container`);
    if (extraction) {
      assert.deepEqual([extraction.name, extraction.kind, extraction.version, extraction.error, extraction.stale],
        [want.extraction, want.extractionKind, want.extractionVersion, want.error, want.stale_extraction], `${where} extraction`);
      assert.equal(catalog.errorCount(i), want.errorCount || 0, `${where} error count`);
    }
    const attrs = catalog.attrsOf(i) || {};
    for (const field of ['redump', 'umdatabase', 'serialstation', 'serialstation_discs'])
      assert.deepEqual(list(attrs[field]), list(want[field]), `${where} ${field}`);
    assert.deepEqual(attrs.coverage, want.coverage, `${where} coverage`);
    assert.equal(attrs.gamePrefix ?? null, want.gamePrefix ?? null, `${where} prefix`);
    assert.equal(attrs.searchMetadata ?? '', want.searchMetadata ?? '', `${where} metadata`);
  }
  const files = reference.filter(node => node.type === 'file').length;
  assert.equal(catalog.files, files, 'file count');
  return reference.length;
}

// Hex digest of every slot, from the chunks the server would deliver.
export function digestTable(encoded) {
  const table = [];
  for (const chunk of encoded.chunks)
    for (let offset = 0; offset < chunk.length; offset += 32) table.push(Buffer.from(chunk.subarray(offset, offset + 32)).toString('hex'));
  return table;
}
