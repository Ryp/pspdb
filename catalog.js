"use strict";

// Catalog container reader and occurrence tree. Mirrors the layout documented in
// pspdb/wire.py ("wire v4"). The container is decoded straight into typed arrays;
// the viewer never creates one JS object per tree row. Shared extraction trees
// and repeated directories are stored once on the wire ("unique" nodes) and are
// expanded here into *occurrences*: parallel typed arrays in preorder, so that
// `end[i]` bounds the subtree of occurrence `i` and parents precede children.
//
// Loaded by the page (classic script), by the search worker (importScripts) and by
// the Node tests (require).
(function (scope) {
  const MAGIC = "PSPDBW", FORMAT_VERSION = 4;
  const TYPE_FILE = 1, VIRTUAL = 2;
  const NONE = -1;
  const HEX = "0123456789abcdef";
  const SECTIONS = ["meta", "names_lens", "names_blob", "names_ids", "kids", "size", "href", "refs",
    "tsize", "tprof", "thash", "tkids", "tkey", "prefixes"];
  // Kinds whose trees belong to catalog records instead of being looked up by file hash.
  const ROOT_KINDS = new Set(["iso", "pkg", "nand", "update"]);

  class StaleCatalogError extends Error {
    constructor() { super("The catalog changed on the server; reload to continue"); this.name = "StaleCatalogError"; }
  }

  // ---- container -------------------------------------------------------------------

  function parseContainer(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    if (bytes.length < 12) throw new Error("Truncated catalog container");
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (let i = 0; i < MAGIC.length; i++)
      if (bytes[i] !== MAGIC.charCodeAt(i)) throw new Error("Not a PSPDB catalog container");
    const version = view.getUint16(6, true);
    if (version !== FORMAT_VERSION) throw new Error(`Unsupported catalog container version ${version}`);
    const count = view.getUint32(8, true);
    let position = 12;
    const table = [];
    for (let i = 0; i < count; i++) {
      const length = bytes[position++];
      let name = "";
      for (let j = 0; j < length; j++) name += String.fromCharCode(bytes[position++]);
      table.push([name, view.getUint32(position, true)]);
      position += 4;
    }
    position += -position & 7;
    const sections = {};
    for (const [name, length] of table) {
      if (position + length > bytes.length) throw new Error("Truncated catalog container");
      sections[name] = bytes.subarray(position, position + length);
      position += length + (-length & 7);
    }
    for (const name of SECTIONS) if (!sections[name]) throw new Error(`Catalog container lacks section ${name}`);
    return sections;
  }

  function varints(bytes, Type = Uint32Array) {
    let count = 0;
    for (let i = 0; i < bytes.length; i++) if (bytes[i] < 128) count++;
    const out = new Type(count);
    let k = 0, value = 0, scale = 1;
    for (let i = 0; i < bytes.length; i++) {
      const byte = bytes[i];
      if (byte < 128) { out[k++] = value + byte * scale; value = 0; scale = 1; }
      else { value += (byte & 127) * scale; scale *= 128; }
    }
    return out;
  }

  function decodeNames(lens, blob) {
    const decoder = new TextDecoder();
    const names = new Array(lens.length);
    let position = 0;
    for (let i = 0; i < lens.length; i++) {
      names[i] = decoder.decode(blob.subarray(position, position + lens[i]));
      position += lens[i];
    }
    return names;
  }

  // Unique-node tables. Unique nodes are the stream's child nodes plus one
  // pseudo-directory per root tree, in preorder; `end` skips a node's subtree.
  // kind: 0 file, 1 inline directory, 2 directory reference (`target`), 3 empty
  // directory that carries extras. A file may own a nested extraction tree `tree`.
  function readTables(sections) {
    const meta = JSON.parse(new TextDecoder().decode(sections.meta));
    const names = decodeNames(varints(sections.names_lens), sections.names_blob);
    const nameIds = varints(sections.names_ids), kids = varints(sections.kids);
    const sizeColumn = varints(sections.size, Float64Array), href = varints(sections.href);
    const refs = varints(sections.refs), tsize = varints(sections.tsize, Float64Array);
    const tprof = varints(sections.tprof), thash = varints(sections.thash);
    const tkids = varints(sections.tkids), tkey = varints(sections.tkey);
    const slotCount = meta.hash_count;
    const rootCount = meta.kinds.reduce((sum, [, n]) => sum + n, 0);
    const nU = kids.length + rootCount, nT = tsize.length;
    const uName = new Uint32Array(nU), uSize = new Float64Array(nU).fill(NONE), uSlot = new Int32Array(nU).fill(NONE);
    const uKind = new Uint8Array(nU), uEnd = new Uint32Array(nU), uTarget = new Int32Array(nU).fill(NONE);
    const uExtra = new Int32Array(nU).fill(NONE), uTree = new Int32Array(nU).fill(NONE);
    const dirOwner = new Uint32Array(refs.length + nT + kids.length);
    const tKind = new Uint8Array(nT), tKey = new Int32Array(nT).fill(NONE), tSize = new Float64Array(nT);
    const tSlot = new Int32Array(nT).fill(NONE), tProfile = new Uint32Array(nT), tBody = new Int32Array(nT);
    const sizeOfSlot = new Float64Array(slotCount).fill(-2);
    const extras = meta.extras;
    let nu = 0, ni = 0, ki = 0, si = 0, hi = 0, ri = 0, ti = 0, keyi = 0, ei = 0, fresh = 0, dirs = 0;
    const slotOf = code => code === 0 ? NONE : code === 1 ? fresh++ : code - 2;

    function readTree(root, nestedOwner, kind) {
      const t = ti++;
      tKind[t] = kind;
      if (root) tKey[t] = slotOf(tkey[keyi++]);
      tSize[t] = tsize[t] === 0 ? NONE : tsize[t] - 1;
      tProfile[t] = tprof[t];
      tSlot[t] = slotOf(thash[t]);
      const owner = root ? nu++ : nestedOwner;
      if (root) uKind[owner] = 1;
      if (tkids[t] === 0) tBody[t] = dirOwner[refs[ri++]];
      else {
        dirOwner[dirs++] = owner;
        tBody[t] = owner;
        readChildren(owner, tkids[t] - 1);
      }
      if (root) uEnd[owner] = nu;
      return t;
    }

    function readChildren(parent, n) {
      for (let i = 0; i < n; i++) {
        const u = nu++, k = kids[ki++];
        uName[u] = nameIds[ni++];
        if (k <= 1) {
          const code = href[hi++];
          if (code >= 2 && sizeOfSlot[code - 2] !== -2) {
            uSlot[u] = code - 2;
            uSize[u] = sizeOfSlot[code - 2];
          } else {
            const stored = sizeColumn[si++], size = stored === 0 ? NONE : stored - 1;
            const slot = slotOf(code);
            uSlot[u] = slot;
            uSize[u] = size;
            if (slot >= 0) sizeOfSlot[slot] = size;
          }
          if (k === 1) {
            const index = ei++, extra = extras[index];
            uExtra[u] = index;
            if (extra.type === "directory") uKind[u] = 3;
            if (extra.extraction === null) uTree[u] = readTree(false, u, 0xff);
          }
        } else if (k === 2) {
          uKind[u] = 2;
          uTarget[u] = dirOwner[refs[ri++]];
        } else {
          uKind[u] = 1;
          dirOwner[dirs++] = u;
          readChildren(u, k - 3);
        }
        uEnd[u] = nu;
      }
    }

    const kindNames = [], rootOf = [];
    for (let kindIndex = 0; kindIndex < meta.kinds.length; kindIndex++) {
      const [kind, count] = meta.kinds[kindIndex];
      kindNames.push(kind);
      for (let i = 0; i < count; i++) rootOf.push(readTree(true, 0, kindIndex));
    }
    if (nu > nU || ti !== nT || ki !== kids.length) throw new Error("Corrupt catalog container");
    return {
      meta, names, slotCount, kindNames, rootOf,
      // A copy: keeps the container's other 32 MB from living as long as the catalog does.
      prefixes: sections.prefixes.slice(),
      uName, uSize, uSlot, uKind, uEnd, uTarget, uExtra, uTree,
      tKind, tKey, tSize, tSlot, tProfile, tBody, nU: nu, nT,
    };
  }

  // ---- naming rules ----------------------------------------------------------------

  function extractedName(source, path, rule) {
    if (rule === "source_stem") return source.replace(/\.[^.]*$/, "") + path.slice(path.indexOf("."));
    if (rule === "strip_suffix") return source.replace(/\.[^.]*$/, "");
    if (rule === "decoded_suffix") {
      let stem = source.replace(/\.[^.]*$/, "");
      const dot = path.indexOf(".");
      const suffix = dot < 0 ? "" : path.slice(dot);
      if (!suffix || suffix === ".bin") return stem;
      if (suffix === ".elf") stem = stem.replace(/\.(?:elf|prx)$/i, "");
      return stem.endsWith(suffix) ? stem : stem + suffix;
    }
    return path;
  }

  // Validate reference identifiers before constructing same-source outbound links.
  const referenceUUID = id => typeof id === "string" && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(id);

  function packageSerial(metadata) {
    const id = metadata.title_id?.trim() || metadata.content_id?.match(/^[^-]+-([A-Z0-9]{9})_/i)?.[1] || "";
    return id.toUpperCase().replace(/^([A-Z0-9]{4})-?([0-9]{5})$/, "$1-$2");
  }

  function packageLabels(packages) {
    const groups = new Map();
    for (const pkg of packages) {
      const metadata = pkg.metadata || {};
      const title = metadata.title?.trim().replace(/\s+/g, " ") || "Untitled package";
      const id = packageSerial(metadata);
      const base = id ? `${id} ${title}` : title;
      if (!groups.has(base)) groups.set(base, []);
      groups.get(base).push({ pkg, id });
    }
    const labels = new Map();
    for (const [base, members] of groups) {
      const hashes = [...new Set(members.map(({ pkg }) => pkg.sha256))];
      for (const { pkg, id } of members) {
        let length = 8;
        while (length < 64 && hashes.some(hash => hash !== pkg.sha256 && hash.slice(0, length) === pkg.sha256.slice(0, length))) length++;
        labels.set(pkg.sha256, hashes.length > 1 || !id ? `${base} · ${pkg.sha256.slice(0, length)}` : base);
      }
    }
    return labels;
  }

  const compareLabels = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

  // ---- occurrence tree -------------------------------------------------------------

  // Expand the unique tables into occurrences plus the grouping above them
  // (psp / umd / psn / firmware, one file per record). Everything except the
  // arrays is small: group and record annotations live in sparse maps.
  function buildCatalog(sections, options = {}) {
    const tables = readTables(sections);
    const { meta, names, prefixes, slotCount } = tables;
    const { uName, uSize, uSlot, uKind, uEnd, uTarget, uExtra, uTree } = tables;
    const { tKey, tSize, tSlot, tProfile, tBody, rootOf, kindNames } = tables;
    const profiles = meta.profiles || [], extras = meta.extras || [];
    const data = meta, records = data.records || {};
    const rule = new Array(tables.nT);
    for (let t = 0; t < tables.nT; t++) rule[t] = profiles[tProfile[t]]?.name_rule || null;

    // Global (hash-keyed) extraction lookup and per-kind record trees.
    const globalTree = new Int32Array(slotCount).fill(NONE);
    const kindTrees = Object.create(null);
    const keySize = new Float64Array(slotCount).fill(-3);
    for (let i = 0; i < rootOf.length; i++) {
      const t = rootOf[i], kind = kindNames[tables.tKind[t]], slot = tKey[t];
      if (keySize[slot] !== -3 && keySize[slot] !== tSize[t])
        throw new Error(`Conflicting source sizes: ${prefixHex(prefixes, slot, 16)}`);
      keySize[slot] = tSize[t];
      (kindTrees[kind] ||= new Map()).set(slot, t);
      if (ROOT_KINDS.has(kind)) continue;
      globalTree[slot] = globalTree[slot] === NONE ? t : -2;
    }

    function attachTree(v) {
      const contextual = uTree[v];
      if (contextual >= 0) return tSlot[contextual] === uSlot[v] && tSize[contextual] === uSize[v] ? contextual : NONE;
      const slot = uSlot[v];
      if (slot < 0) return NONE;
      const t = globalTree[slot];
      if (t === NONE) return NONE;
      if (t === -2) throw new Error(`Ambiguous non-root extraction kinds: ${prefixHex(prefixes, slot, 16)}`);
      return tSize[t] === uSize[v] ? t : NONE;
    }

    // Upper bound on occurrences beneath a directory body, to size the arrays once.
    const memo = new Float64Array(tables.nU).fill(-1), visiting = new Uint8Array(tables.nU);
    function count(b) {
      if (memo[b] >= 0) return memo[b];
      if (visiting[b]) return 0;
      visiting[b] = 1;
      let n = 0;
      for (let v = b + 1; v < uEnd[b]; v = uEnd[v]) {
        n++;
        const kind = uKind[v];
        if (kind === 0) {
          const t = attachTree(v);
          if (t >= 0) n += count(tBody[t]);
        } else if (kind !== 3) n += count(kind === 2 ? uTarget[v] : v);
      }
      visiting[b] = 0;
      return memo[b] = n;
    }

    // ---- plan the grouping layer (a few thousand nodes) ----
    const plan = (name, props = {}) => ({ name, dir: true, children: [], ...props });
    const root = plan("psp", { virtual: true });
    const population = data.coverage || {};
    const umdPopulation = population.umd || null, psnPopulation = population.psn || null;
    const umdSnapshot = [umdPopulation?.source?.name, umdPopulation?.source?.version].filter(Boolean).join(" ");
    const group = (parent, name, attrs = null) => {
      const node = plan(name, { virtual: true, attrs });
      parent.children.push(node);
      return node;
    };
    const umd = group(root, "umd", umdPopulation
      ? { coverage: { present: umdPopulation.present, total: umdPopulation.total, noun: "UMD discs",
                      source: "Redump", snapshot: umdSnapshot, href: "http://redump.org/discs/system/psp/" } }
      : null);
    const categories = new Map();
    const mediaGroup = code => {
      const name = code === "G" ? "game" : code === "V" ? "video" : "other";
      if (!categories.has(name)) categories.set(name, group(umd, name));
      return categories.get(name);
    };
    const recordNode = (parent, kind, record, name, attrs) => {
      const node = { name, dir: false, record: { kind, sha256: record.sha256, size: record.size_bytes, slot: record.slot }, attrs, children: null };
      parent.children.push(node);
      return node;
    };
    for (const iso of records.iso || []) {
      const metadata = iso.metadata || {};
      const category = mediaGroup(metadata.media_code);
      const id = (metadata.disc_id || metadata.identifier || "").trim().replace(/^([A-Z]{4})-?([0-9]{5})$/, "$1-$2");
      const identity = [id, metadata.disc_version].filter(Boolean).join("/");
      const displayName = metadata.media_code === "V"
        ? metadata.title?.trim() || identity
        : [identity, metadata.title?.trim()].filter(Boolean).join(" ");
      recordNode(category, "iso", iso, `${iso.sha256}.iso`, {
        displayName,
        gamePrefix: metadata.media_code === "G" ? identity : null,
        umdatabase: iso.umdatabase || [],
        serialstation_discs: (iso.serialstation_discs || []).filter(match => referenceUUID(match.id)),
      });
    }
    const packages = records.pkg || [];
    if (packages.length) {
      const psn = group(root, "psn", psnPopulation
        ? { coverage: { present: psnPopulation.present, total: psnPopulation.total, noun: "PSN packages",
                        source: "NoPayStation", href: "https://nopaystation.com/" } }
        : null);
      const labels = packageLabels(packages);
      const groups = new Map();
      for (const pkg of packages) {
        const metadata = pkg.metadata || {};
        const category = pkg.psn_kind || "unknown";
        if (!groups.has(category)) groups.set(category, group(psn, category));
        recordNode(groups.get(category), "pkg", pkg, `${pkg.sha256}.pkg`, {
          displayName: labels.get(pkg.sha256),
          gamePrefix: packageSerial(metadata) || null,
          searchMetadata: metadata.content_id || "",
          serialstation: pkg.serialstation || null,
        });
      }
    }
    const firmware = group(root, "firmware");
    const nandGroup = group(firmware, "nand"), updateGroup = group(firmware, "update");
    for (const nand of records.nand || []) {
      const metadata = nand.metadata || {};
      const validGeometry = metadata.page_bytes === 512 && metadata.spare_bytes === 16
        && metadata.pages_per_block === 32 && (metadata.blocks === 2048 || metadata.blocks === 4096)
        && nand.size_bytes === metadata.blocks * 32 * 528;
      recordNode(nandGroup, "nand", nand, `${nand.sha256}.nand`, {
        displayName: validGeometry ? `${metadata.blocks / 64} MiB NAND · ${nand.sha256.slice(0, 12)}` : null,
      });
    }
    for (const update of records.update || []) {
      const metadata = update.metadata || {};
      const version = metadata.updater_version?.trim();
      recordNode(updateGroup, "update", update, `${update.sha256}.pbp`, {
        displayName: version ? `Update ${version}${metadata.updater_target === "psp-go" ? " Go" : ""} · ${update.sha256.slice(0, 12)}` : null,
        searchMetadata: [metadata.title, metadata.disc_id].filter(Boolean).join(" "),
      });
    }
    const planLabel = node => node.attrs?.displayName || node.name;
    const sortPlan = node => {
      if (!node.children) return;
      if (node.children.length > 1)
        node.children.sort((a, b) => (a.dir === b.dir ? 0 : a.dir ? -1 : 1) || compareLabels(planLabel(a), planLabel(b)));
      for (const child of node.children) sortPlan(child);
    };
    sortPlan(root);

    // Per-record expansion size, then the arrays.
    let capacity = 1;
    const recordTree = node => {
      const { kind, slot, size } = node.record;
      const t = kindTrees[kind]?.get(slot);
      return t !== undefined && tSize[t] === (size ?? NONE) ? t : NONE;
    };
    const planCount = node => {
      let n = 1;
      if (node.record) {
        const t = recordTree(node);
        if (t >= 0) n += count(tBody[t]);
      } else for (const child of node.children) n += planCount(child);
      return n;
    };
    capacity = planCount(root);

    let parent = new Int32Array(capacity), name = new Uint32Array(capacity), end = new Uint32Array(capacity);
    let size = new Float64Array(capacity), slot = new Int32Array(capacity).fill(NONE);
    let tree = new Int32Array(capacity).fill(NONE), flags = new Uint8Array(capacity);
    let on = 0, files = 0;
    function grow() {
      capacity = Math.ceil(capacity * 1.5) + 16;
      const widen = (array, Type, fill) => {
        const next = new Type(capacity);
        if (fill !== undefined) next.fill(fill);
        next.set(array);
        return next;
      };
      parent = widen(parent, Int32Array); name = widen(name, Uint32Array); end = widen(end, Uint32Array);
      size = widen(size, Float64Array); slot = widen(slot, Int32Array, NONE);
      tree = widen(tree, Int32Array, NONE); flags = widen(flags, Uint8Array);
    }

    const attrs = new Map();
    const derived = new Map();
    const internName = text => {
      let id = derived.get(text);
      if (id === undefined) { id = names.length; names.push(text); derived.set(text, id); }
      return id;
    };
    const active = new Uint8Array(tables.nT);
    // Child order is dirs first, then names; the encoder normally emits that
    // order already, so check once per unique directory and only sort when needed.
    const order = new Map(), ordered = new Uint8Array(tables.nU);
    const compareRows = (a, b) => {
      const left = uKind[a] === 0, right = uKind[b] === 0;
      if (left !== right) return left ? 1 : -1;
      const x = names[uName[a]], y = names[uName[b]];
      return x < y ? -1 : x > y ? 1 : 0;
    };
    function childOrder(b) {
      if (ordered[b] === 0) {
        let sorted = true;
        for (let v = b + 1, next; v < uEnd[b]; v = next) {
          next = uEnd[v];
          if (next < uEnd[b] && compareRows(v, next) > 0) { sorted = false; break; }
        }
        if (sorted) ordered[b] = 1;
        else {
          const rows = [];
          for (let v = b + 1; v < uEnd[b]; v = uEnd[v]) rows.push(v);
          order.set(b, Uint32Array.from(rows.sort(compareRows)));
          ordered[b] = 2;
        }
      }
      return ordered[b] === 2 ? order.get(b) : null;
    }

    function emitChildren(b, p, context) {
      if (uEnd[b] === b + 1) return;
      if (context) return emitDerived(b, p, context);
      const list = childOrder(b);
      if (list) for (let i = 0; i < list.length; i++) emitRow(list[i], p, uName[list[i]], null);
      else for (let v = b + 1; v < uEnd[b]; v = uEnd[v]) emitRow(v, p, uName[v], null);
    }

    function emitDerived(b, p, context) {
      const rows = [], nameIds = new Map();
      for (let v = b + 1; v < uEnd[b]; v = uEnd[v]) {
        rows.push(v);
        nameIds.set(v, internName(extractedName(context.source, names[uName[v]], context.rule)));
      }
      rows.sort((a, c) => {
        const left = uKind[a] === 0, right = uKind[c] === 0;
        if (left !== right) return left ? 1 : -1;
        return compareLabels(names[nameIds.get(a)], names[nameIds.get(c)]);
      });
      for (const v of rows) emitRow(v, p, nameIds.get(v), context);
    }

    function emitTree(id, t) {
      if (t < 0 || active[t]) return;
      tree[id] = t;
      active[t] = 1;
      emitChildren(tBody[t], id, rule[t] ? { rule: rule[t], source: names[name[id]] } : null);
      active[t] = 0;
    }

    function emitRow(v, p, nameId, context) {
      if (on === capacity) grow();
      const id = on++, kind = uKind[v];
      parent[id] = p;
      name[id] = nameId;
      if (kind === 0) {
        flags[id] = TYPE_FILE;
        size[id] = Math.max(uSize[v], 0);
        slot[id] = uSlot[v];
        files++;
        if (uExtra[v] >= 0 && extras[uExtra[v]].redump?.length) attrs.set(id, { redump: extras[uExtra[v]].redump });
        emitTree(id, attachTree(v));
      } else if (kind !== 3) emitChildren(kind === 2 ? uTarget[v] : v, id, context);
      end[id] = on;
    }

    function emitPlan(node, p) {
      if (on === capacity) grow();
      const id = on++;
      parent[id] = p;
      name[id] = internName(node.name);
      if (node.attrs) attrs.set(id, node.attrs);
      if (node.record) {
        flags[id] = TYPE_FILE;
        size[id] = node.record.size ?? 0;
        slot[id] = node.record.slot ?? NONE;
        files++;
        emitTree(id, recordTree(node));
      } else {
        flags[id] = node.virtual ? VIRTUAL : 0;
        for (const child of node.children) emitPlan(child, id);
      }
      end[id] = on;
    }
    emitPlan(root, NONE);

    // Directory sizes sum the files beneath them (not extracted contents); children
    // always follow their parents, so one reverse pass completes every aggregate.
    for (let i = on - 1; i > 0; i--) if (!(flags[parent[i]] & TYPE_FILE)) size[parent[i]] += size[i];

    if (on !== capacity) {
      parent = parent.slice(0, on); name = name.slice(0, on); end = end.slice(0, on);
      size = size.slice(0, on); slot = slot.slice(0, on); tree = tree.slice(0, on); flags = flags.slice(0, on);
    }

    const recordHashes = new Map();
    for (const list of Object.values(records))
      for (const record of list) if (record.sha256 && record.slot !== undefined) recordHashes.set(record.slot, record.sha256);

    return new Catalog({
      meta, names, prefixes, slotCount, parent, name, end, size, slot, tree, flags, attrs, files,
      profiles, recordHashes, treeProfile: tProfile,
    });
  }

  function prefixHex(prefixes, slot, chars) {
    let out = "";
    for (let i = 0, base = slot * 8; out.length < chars; i++) {
      const byte = prefixes[base + i];
      out += HEX[byte >> 4] + HEX[byte & 15];
    }
    return out.slice(0, chars);
  }

  class Catalog {
    constructor(parts) {
      Object.assign(this, parts);
      this.count = parts.parent.length;
      this.generation = parts.meta.generation || "";
      this.downloadsEnabled = parts.meta.downloads_enabled === true;
      this.errorCounts = null;
    }
    isFile(i) { return (this.flags[i] & TYPE_FILE) !== 0; }
    isVirtual(i) { return (this.flags[i] & VIRTUAL) !== 0; }
    isContainer(i) { return this.tree[i] >= 0; }
    expandable(i) { return !this.isFile(i) || this.tree[i] >= 0; }
    hasChildren(i) { return this.end[i] > i + 1; }
    nameOf(i) { return this.names[this.name[i]]; }
    attrsOf(i) { return this.attrs.get(i); }
    label(i) { return this.attrs.get(i)?.displayName || this.names[this.name[i]]; }
    depth(i) {
      let depth = 0;
      for (let p = this.parent[i]; p >= 0; p = this.parent[p]) depth++;
      return depth;
    }
    path(i) {
      const parts = [];
      for (let n = i; this.parent[n] >= 0; n = this.parent[n]) parts.push(this.names[this.name[n]]);
      return parts.reverse().join("/");
    }
    displayPath(i) {
      if (this.parent[i] < 0) return this.label(i);
      const parts = [];
      for (let n = i; this.parent[n] >= 0; n = this.parent[n]) parts.push(this.label(n));
      return parts.reverse().join("/");
    }
    children(i) {
      const out = [];
      for (let c = i + 1; c < this.end[i]; c = this.end[c]) out.push(c);
      return out;
    }
    find(path) {
      let node = 0;
      if (!path) return node;
      for (const part of path.split("/")) {
        let found = -1;
        for (let c = node + 1; c < this.end[node]; c = this.end[c])
          if (this.names[this.name[c]] === part) { found = c; break; }
        if (found < 0) return -1;
        node = found;
      }
      return node;
    }
    // Extraction attached to `i`: extractor, kind, version, error, stale marker.
    extraction(i) {
      const t = this.tree[i];
      if (t < 0) return null;
      const profile = this.profiles[this.treeProfile[t]] || {};
      return {
        name: profile.extractor?.name, kind: profile.extraction_kind, version: profile.extractor?.version,
        error: profile.error, stale: profile.stale_extraction,
      };
    }
    prefixHex(i, chars = 12) { return this.slot[i] >= 0 ? prefixHex(this.prefixes, this.slot[i], chars) : ""; }
    // Full hash already known without a fetch (catalog records carry theirs).
    knownHash(i) { return this.slot[i] >= 0 ? this.recordHashes.get(this.slot[i]) : undefined; }
    // Message for the search worker: copies of the occurrence arrays (this thread
    // keeps rendering from the originals) plus the sparse per-occurrence strings,
    // interned into the shared string table.
    searchIndex(hashUrl, catalogScript) {
      const added = new Map(), names = this.names;
      const intern = text => {
        let id = added.get(text);
        if (id === undefined) { id = names.length; names.push(text); added.set(text, id); }
        return id;
      };
      const labels = { ids: [], strs: [] }, texts = { ids: [], strs: [] }, errors = { ids: [], strs: [] };
      for (const [id, attrs] of this.attrs) {
        if (attrs.displayName) { labels.ids.push(id); labels.strs.push(intern(attrs.displayName)); }
        if (attrs.displayName || attrs.searchMetadata) {
          texts.ids.push(id);
          texts.strs.push(intern(`${attrs.displayName || ""} ${attrs.searchMetadata || ""}`));
        }
      }
      const errorString = new Int32Array(this.treeProfile.length).fill(NONE);
      this.treeProfile.forEach((profile, t) => {
        const error = this.profiles[profile]?.error;
        if (error) errorString[t] = intern(`error: ${error}`);
      });
      for (let i = 0; i < this.count; i++) {
        const t = this.tree[i];
        if (t >= 0 && errorString[t] >= 0) { errors.ids.push(i); errors.strs.push(errorString[t]); }
      }
      const typed = ({ ids, strs }) => ({ ids: Uint32Array.from(ids), strs: Uint32Array.from(strs) });
      const message = {
        type: "index", count: this.count, strings: names,
        parent: this.parent.slice(), name: this.name.slice(), size: this.size.slice(),
        slot: this.slot.slice(), flags: this.flags.slice(), prefixes: this.prefixes.slice(),
        labels: typed(labels), texts: typed(texts), errors: typed(errors),
        hashCount: this.slotCount, hashChunkSlots: CHUNK_SLOTS, hashUrl, catalogScript,
      };
      const transfer = [message.parent.buffer, message.name.buffer, message.size.buffer, message.slot.buffer,
        message.flags.buffer, message.prefixes.buffer];
      return { message, transfer };
    }
    errorCount(i) {
      if (!this.errorCounts) {
        const failed = new Uint8Array(this.treeProfile.length);
        for (let t = 0; t < failed.length; t++) failed[t] = this.profiles[this.treeProfile[t]]?.error ? 1 : 0;
        const counts = new Map();
        for (let n = 0; n < this.count; n++) {
          const t = this.tree[n];
          if (t < 0 || !failed[t]) continue;
          for (let p = this.parent[n]; p >= 0; p = this.parent[p])
            if (this.tree[p] >= 0) counts.set(p, (counts.get(p) || 0) + 1);
        }
        this.errorCounts = counts;
      }
      return this.errorCounts.get(i) || 0;
    }
  }

  // ---- full hashes (lazy, chunked) --------------------------------------------------

  const CHUNK_SLOTS = 4096;

  class HashStore {
    // chunkUrl(chunk) -> URL; fetchImpl is injectable for tests.
    constructor({ count, chunkSlots = CHUNK_SLOTS, chunkUrl, prefixes, fetchImpl = (...args) => fetch(...args) }) {
      Object.assign(this, { count, chunkSlots, chunkUrl, prefixes, fetchImpl });
      this.loaded = new Map();
      this.pending = new Map();
    }
    peek(slot) {
      const chunk = this.loaded.get(Math.floor(slot / this.chunkSlots));
      if (!chunk) return undefined;
      const base = (slot % this.chunkSlots) * 32;
      let out = "";
      for (let i = 0; i < 32; i++) { const byte = chunk[base + i]; out += HEX[byte >> 4] + HEX[byte & 15]; }
      return out;
    }
    load(index) {
      if (this.loaded.has(index)) return Promise.resolve(this.loaded.get(index));
      let pending = this.pending.get(index);
      if (!pending) {
        pending = this.fetchChunk(index).then(bytes => { this.loaded.set(index, bytes); return bytes; })
          .finally(() => this.pending.delete(index));
        this.pending.set(index, pending);
      }
      return pending;
    }
    async fetchChunk(index) {
      const response = await this.fetchImpl(this.chunkUrl(index));
      if (response.status === 409) throw new StaleCatalogError();
      if (!response.ok) throw new Error(`Hash chunk ${index}: HTTP ${response.status}`);
      const bytes = new Uint8Array(await response.arrayBuffer());
      const slots = Math.min(this.chunkSlots, this.count - index * this.chunkSlots);
      if (slots <= 0 || bytes.length !== slots * 32) throw new Error(`Hash chunk ${index} has the wrong size`);
      // A static host can serve a chunk from another export; check against the catalog's prefixes.
      for (let i = 0; i < slots; i++) {
        const slot = index * this.chunkSlots + i;
        for (let j = 0; j < 8; j++)
          if (bytes[i * 32 + j] !== this.prefixes[slot * 8 + j]) throw new Error(`Hash chunk ${index} does not match the catalog`);
      }
      return bytes;
    }
    // Full hex digests for slots, fetching the chunks they live in.
    async resolve(slots) {
      const wanted = [...new Set(slots)].filter(slot => slot >= 0 && slot < this.count);
      await Promise.all([...new Set(wanted.map(slot => Math.floor(slot / this.chunkSlots)))].map(index => this.load(index)));
      return new Map(wanted.map(slot => [slot, this.peek(slot)]));
    }
  }

  const api = {
    MAGIC, FORMAT_VERSION, TYPE_FILE, VIRTUAL, StaleCatalogError, HashStore, Catalog,
    parseContainer, readTables, buildCatalog, extractedName, packageLabels, packageSerial, referenceUUID, prefixHex,
  };
  if (typeof module === "object" && module.exports) module.exports = api;
  else scope.PspdbCatalog = api;
})(typeof self !== "undefined" ? self : globalThis);
