"use strict";

// Nodes are parent-before-child IDs. Strings are interned across all occurrences;
// inherited matches are propagated as bits rather than concatenated ancestor text.
const strings = [], lower = [];
let index, revision = 0, queued = null, running = false, previous = null;
const nameOrder = new Intl.Collator("en", { numeric: true, sensitivity: "base" });
const pause = () => self.scheduler?.yield ? self.scheduler.yield() : new Promise(resolve => setTimeout(resolve, 0));
const hashTerm = term => /^[0-9a-f]{8,64}$/.test(term);

self.onmessage = ({ data }) => {
  try {
    if (data.type === "strings") {
      for (const text of data.strings) { strings.push(text); lower.push(text.toLowerCase()); }
    } else if (data.type === "index") {
      index = data;
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
      const ids = await search(request);
      if (ids && request.version === revision)
        self.postMessage({ type: "results", version: request.version, ids }, [ids.buffer]);
    }
  } catch (error) {
    self.postMessage({ type: "error", message: error.message });
  } finally {
    running = false;
  }
}

async function search(request) {
  const { version, terms, sort, direction } = request;
  const { parents, names, texts, hashes, errors, order } = index;
  const sameTerms = previous && terms.length === previous.terms.length
    && terms.every((term, i) => term === previous.terms[i]);
  let ids;
  if (sameTerms) ids = previous.ids.slice();
  else {
    // A text-to-hash (or hash-to-text) transition is not a refinement: hashes
    // match only this file, while ordinary terms may match any ancestor.
    const narrowed = previous && previous.ids.length < parents.length / 8
      && previous.terms.every(old => terms.some(term => term.includes(old) && hashTerm(term) === hashTerm(old)));
    const candidates = narrowed ? previous.ids : order;
    const accepted = new Uint8Array(narrowed ? candidates.length : parents.length).fill(1);
    const inherited = narrowed ? null : new Uint8Array(parents.length);
    for (const term of terms) {
      if (narrowed && previous.terms.includes(term)) continue;
      const matches = new Uint8Array(strings.length);
      // Refinements touch only surviving candidates. Memoize their strings on
      // demand: 0 = unknown, 1 = miss, 2 = match, rather than scanning the dictionary.
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
      }
      const ownHash = hashTerm(term);
      const count = narrowed ? candidates.length : parents.length;
      for (let start = 0; start < count; start += 32768) {
        for (let i = start; i < Math.min(start + 32768, count); i++) {
          const node = narrowed ? candidates[i] : i;
          if (narrowed) {
            if (!accepted[i]) continue;
            let found = ownHash ? match(hashes[node]) : match(errors[node]);
            if (!ownHash) {
              for (let ancestor = node; !found && ancestor >= 0; ancestor = parents[ancestor])
                found = match(names[ancestor]) || match(texts[ancestor]) || match(hashes[ancestor]);
            }
            accepted[i] = found;
          } else if (ownHash) accepted[i] &= matches[hashes[node]];
          else {
            inherited[node] = (parents[node] >= 0 && inherited[parents[node]])
              || matches[names[node]] || matches[texts[node]] || matches[hashes[node]];
            accepted[node] &= inherited[node] || matches[errors[node]];
          }
        }
        await pause();
        if (version !== revision) return null;
      }
    }
    const result = new Uint32Array(candidates.length);
    let length = 0;
    for (let start = 0; start < candidates.length; start += 32768) {
      for (let i = start; i < Math.min(start + 32768, candidates.length); i++)
        if (accepted[narrowed ? i : candidates[i]]) result[length++] = candidates[i];
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
  const { parents, names, labels, sizes, hashes } = index;
  const paths = new Map();
  function path(id) {
    let value = paths.get(id);
    if (value !== undefined) return value;
    const parts = [];
    for (let node = id; parents[node] >= 0; node = parents[node]) parts.push(strings[names[node]]);
    value = parts.reverse().join("/");
    if (paths.size >= 8192) paths.clear();
    paths.set(id, value);
    return value;
  }
  function compare(a, b) {
    const order = sort === "size" ? sizes[a] - sizes[b]
      : sort === "hash" ? strings[hashes[a]].localeCompare(strings[hashes[b]])
      : nameOrder.compare(strings[labels[a]], strings[labels[b]]);
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
