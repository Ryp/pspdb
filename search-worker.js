"use strict";

// The index is the occurrence tree itself: parent-before-child ids (preorder),
// each occurrence's name string id, size and hash slot. Rare per-occurrence text
// (labels, search metadata, extraction errors) is sparse. Inherited matches are
// propagated as bits rather than by concatenating ancestor text.
// catalog.js is loaded on the first message, from an absolute URL the page supplies:
// some hosts start workers from blob: URLs, where relative paths do not resolve.
const catalogModule = () => self.PspdbCatalog;
let strings = [], lower = [];
let index = null, store = null, revision = 0, queued = null, running = false, previous = null;
const nameOrder = new Intl.Collator("en", { numeric: true, sensitivity: "base" });
const pause = () => self.scheduler?.yield ? self.scheduler.yield() : new Promise(resolve => setTimeout(resolve, 0));
// Hash terms are 8-64 hex digits, matched as prefixes of an occurrence's own SHA-256.
const hashTerm = term => /^[0-9a-f]{8,64}$/.test(term);

class HashLookupError extends Error {}

self.onmessage = ({ data }) => {
  try {
    if (data.type === "index") {
      if (!self.PspdbCatalog) importScripts(data.catalogScript);
      strings = data.strings;
      lower = new Array(strings.length);
      for (let i = 0; i < strings.length; i++) lower[i] = strings[i].toLowerCase();
      const { count, prefixes } = data;
      const view = new DataView(prefixes.buffer, prefixes.byteOffset, prefixes.byteLength);
      const slots = prefixes.length / 8, hi = new Uint32Array(slots), lo = new Uint32Array(slots);
      for (let i = 0; i < slots; i++) { hi[i] = view.getUint32(i * 8, false); lo[i] = view.getUint32(i * 8 + 4, false); }
      const sparse = ({ ids, strs }) => new Map(Array.from(ids, (id, k) => [id, strs[k]]));
      index = {
        count, parent: data.parent, name: data.name, size: data.size, slot: data.slot, flags: data.flags,
        hi, lo, slots, labels: sparse(data.labels), texts: sparse(data.texts), errors: sparse(data.errors),
        accepted: new Uint8Array(count), inherited: new Uint8Array(count), extra: new Uint8Array(count),
      };
      store = new (catalogModule().HashStore)({ count: data.hashCount, chunkSlots: data.hashChunkSlots, prefixes,
        chunkUrl: chunk => data.hashUrl.replace("__chunk__", String(chunk)) });
      previous = null;
      self.postMessage({ type: "ready" });
    } else if (data.type === "cancel") {
      revision = data.version;
      queued = null;
    } else if (data.type === "search") {
      revision = data.version;
      queued = data;
      drain();
    }
  } catch (error) {
    self.postMessage({ type: "error", message: error.message });
  }
};

async function drain() {
  if (running) return;
  running = true;
  try {
    while (queued) {
      const request = queued;
      queued = null;
      try {
        const ids = await search(request);
        if (ids && request.version === revision)
          self.postMessage({ type: "results", version: request.version, ids }, [ids.buffer]);
      } catch (error) {
        if (error instanceof catalogModule().StaleCatalogError) self.postMessage({ type: "stale", version: request.version });
        else if (error instanceof HashLookupError) {
          previous = null;
          self.postMessage({ type: "hash-error", version: request.version, message: error.message });
        } else throw error;
      }
    }
  } catch (error) {
    self.postMessage({ type: "error", message: error.message });
  } finally {
    running = false;
  }
}

// 1 where a slot's digest starts with the term. Terms past the 8-byte prefix
// match their first 16 digits here, then verify the rest against the full
// digests of the (few) candidate slots, fetched chunk by chunk.
async function hashSlots(term) {
  const { hi, lo, slots } = index;
  const digits = Math.min(term.length, 16), padded = term.slice(0, 16).padEnd(16, "0");
  const wantHi = parseInt(padded.slice(0, 8), 16), wantLo = parseInt(padded.slice(8), 16);
  const mask = count => count <= 0 ? 0 : count >= 8 ? 0xffffffff : (0xffffffff << (32 - 4 * count)) >>> 0;
  const maskHi = mask(digits), maskLo = mask(digits - 8);
  const matches = new Uint8Array(slots), candidates = [];
  for (let slot = 0; slot < slots; slot++) {
    if (((hi[slot] ^ wantHi) & maskHi) === 0 && ((lo[slot] ^ wantLo) & maskLo) === 0) {
      matches[slot] = 1;
      if (term.length > 16) candidates.push(slot);
    }
  }
  if (candidates.length) {
    let full;
    try { full = await store.resolve(candidates); }
    catch (error) {
      if (error instanceof catalogModule().StaleCatalogError) throw error;
      throw new HashLookupError(`Could not verify a long SHA-256 (${error.message})`);
    }
    for (const slot of candidates) if (!full.get(slot).startsWith(term)) matches[slot] = 0;
  }
  return matches;
}

function clearExtra() {
  for (const id of index.texts.keys()) index.extra[id] = 0;
  for (const id of index.errors.keys()) index.extra[id] = 0;
}

async function search(request) {
  const { version, terms, sort, direction } = request;
  const { count, parent, name, slot, flags, texts, errors, accepted, inherited, extra } = index;
  const sameTerms = previous && terms.length === previous.terms.length
    && terms.every((term, i) => term === previous.terms[i]);
  let ids;
  if (sameTerms) ids = previous.ids.slice();
  else {
    // A text-to-hash (or hash-to-text) transition is not a refinement: hashes
    // match only this file, while ordinary terms may match any ancestor.
    const refines = (term, old) => hashTerm(old) ? hashTerm(term) && term.startsWith(old) : !hashTerm(term) && term.includes(old);
    const narrowed = previous && previous.ids.length < count / 8
      && previous.terms.every(old => terms.some(term => refines(term, old)));
    const candidates = narrowed ? previous.ids : null;
    const size = narrowed ? candidates.length : count;
    const live = narrowed ? new Uint8Array(size).fill(1) : accepted.fill(1);
    for (const term of terms) {
      if (narrowed && previous.terms.includes(term)) continue;
      if (hashTerm(term)) {
        const slotHit = await hashSlots(term);
        if (version !== revision) return null;
        for (let start = 0; start < size; start += 65536) {
          for (let i = start; i < Math.min(start + 65536, size); i++) {
            const node = narrowed ? candidates[i] : i;
            if (!live[i]) continue;
            live[i] = slot[node] >= 0 ? slotHit[slot[node]] : 0;
          }
          await pause();
          if (version !== revision) return null;
        }
        continue;
      }
      const matches = new Uint8Array(strings.length);
      // Refinements touch only surviving candidates, memoizing strings on demand:
      // 0 = unknown, 1 = miss, 2 = match, rather than scanning the dictionary.
      const match = narrowed ? id => {
        if (!matches[id]) matches[id] = lower[id].includes(term) ? 2 : 1;
        return matches[id] === 2;
      } : null;
      if (!narrowed) {
        for (let start = 0; start < strings.length; start += 16384) {
          for (let i = start; i < Math.min(start + 16384, strings.length); i++) matches[i] = lower[i].includes(term);
          await pause();
          if (version !== revision) return null;
        }
        clearExtra();
        for (const [id, text] of texts) if (matches[text]) extra[id] |= 1;
        for (const [id, text] of errors) if (matches[text]) extra[id] |= 2;
      }
      for (let start = 0; start < size; start += 32768) {
        for (let i = start; i < Math.min(start + 32768, size); i++) {
          if (narrowed) {
            if (!live[i]) continue;
            const node = candidates[i], own = errors.get(node);
            let found = own !== undefined && match(own);
            for (let ancestor = node; !found && ancestor >= 0; ancestor = parent[ancestor]) {
              const text = texts.get(ancestor);
              found = match(name[ancestor]) || (text !== undefined && match(text));
            }
            live[i] = found;
          } else {
            const up = parent[i];
            inherited[i] = (up >= 0 && inherited[up]) || matches[name[i]] || (extra[i] & 1);
            live[i] &= inherited[i] | (extra[i] >> 1);
          }
        }
        await pause();
        if (version !== revision) return null;
      }
      if (!narrowed) clearExtra();
    }
    const total = narrowed ? candidates.length : count;
    const result = new Uint32Array(total);
    let length = 0;
    for (let start = 0; start < total; start += 32768) {
      for (let i = start; i < Math.min(start + 32768, total); i++) {
        const node = narrowed ? candidates[i] : i;
        if (live[i] && (flags[node] & 1)) result[length++] = node;
      }
      await pause();
      if (version !== revision) return null;
    }
    ids = result.slice(0, length);
    previous = { terms, ids };
    // Keep the unsorted order for refinements and the third sort-header click.
    ids = ids.slice();
  }
  if (sort && ids.length > 1) return sortResults(ids, request);
  return ids;
}

async function sortResults(ids, { version, sort, direction }) {
  const { parent, name, labels, size, slot, hi, lo } = index;
  const paths = new Map();
  function path(id) {
    let value = paths.get(id);
    if (value !== undefined) return value;
    const parts = [];
    for (let node = id; parent[node] >= 0; node = parent[node]) parts.push(strings[name[node]]);
    value = parts.reverse().join("/");
    if (paths.size >= 8192) paths.clear();
    paths.set(id, value);
    return value;
  }
  const label = id => strings[labels.get(id) ?? name[id]];
  function byHash(a, b) {
    // No hash sorts first, as the empty string did; digests compare bytewise.
    const x = slot[a], y = slot[b];
    if (x < 0 || y < 0) return (x >= 0) - (y >= 0);
    return hi[x] === hi[y] ? (lo[x] === lo[y] ? 0 : lo[x] < lo[y] ? -1 : 1) : hi[x] < hi[y] ? -1 : 1;
  }
  function compare(a, b) {
    const order = sort === "size" ? size[a] - size[b]
      : sort === "hash" ? byHash(a, b)
      : nameOrder.compare(label(a), label(b));
    if (order) return order * direction;
    const left = path(a), right = path(b);
    return nameOrder.compare(left, right) || left.localeCompare(right);
  }
  // Yield inside the merge, not just between passes, so a broad sorted query
  // can be superseded immediately even when it matches the complete catalog.
  let source = ids, target = new Uint32Array(ids.length), work = 0;
  for (let width = 1; width < ids.length; width *= 2) {
    for (let start = 0; start < ids.length; start += width * 2) {
      const middle = Math.min(start + width, ids.length), end = Math.min(start + width * 2, ids.length);
      let left = start, right = middle;
      for (let out = start; out < end; out++) {
        target[out] = left < middle && (right >= end || compare(source[left], source[right]) <= 0)
          ? source[left++] : source[right++];
        if (++work % 8192 === 0) {
          await pause();
          if (version !== revision) return null;
        }
      }
    }
    [source, target] = [target, source];
  }
  return source;
}
