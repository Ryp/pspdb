"use strict";

const $ = id => document.getElementById(id);
const number = new Intl.NumberFormat("en-US");
const sizeNumber = new Intl.NumberFormat("en-US", { maximumSignificantDigits: 3 });
function formatSize(bytes) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let unit = 0, value = bytes;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${sizeNumber.format(value)} ${units[unit]}`;
}

async function copyHash(hash) {
  try {
    await navigator.clipboard.writeText(hash);
    return true;
  } catch {
    // LAN HTTP pages may lack the Clipboard API. Copy from a temporary field
    // without changing the visible hash or the tree's selection.
    const previousFocus = document.activeElement;
    const field = document.createElement("textarea");
    field.value = hash;
    field.readOnly = true;
    field.style.cssText = "position:fixed;left:-9999px;top:0;opacity:0";
    document.body.append(field);
    try {
      field.focus({ preventScroll: true });
      field.select();
      return document.execCommand("copy");
    } catch {
      return false;
    } finally {
      field.remove();
      previousFocus?.focus({ preventScroll: true });
    }
  }
}
const nodes = [], collapsed = new Set(), rowElements = new Map();
const disclosures = new Map();
let root, selected, visible = [];
let catalogReady = false;
let filterNodes = null, searchTerms = [], savedTree = null;
let searchWorker = null, searchReady = Promise.resolve(false), searchVersion = 0;
let searchSettled = Promise.resolve(), settleSearch = null;
const emptyChildren = Object.freeze([]);
let searchSort = null, sortDirection = 1;
const highlightCache = new WeakMap();
let rowHeight = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--row-height"));
const overscan = 20;
let windowKey = "", windowVersion = 0, scrollFrame = 0;
let logicalOffset = 0, physicalOffset = 0, scrollViewport = 0;
let nativeScrolling = false, touchCount = 0, scrollEndTimer = 0;
let downloadsEnabled = false, checkingDownloads = false;
const availability = new Map();

async function refreshDownloads() {
  if (!downloadsEnabled) return;
  const mounted = [...$("entries").querySelectorAll("tr.node")]
    .map(row => nodes[Number(row.dataset.node)]).filter(node => node?.type === "file" && node.hash);
  for (const node of mounted) {
    const cell = node.downloadCell, state = availability.get(node.hash);
    if (cell.dataset.state === String(state)) continue;
    cell.dataset.state = String(state);
    cell.classList.toggle("missing", state === false);
    cell.replaceChildren();
    if (state === true) {
      const link = element("a", "download-link", "Download");
      link.href = `download/${node.hash}/${encodeURIComponent(node.name)}`;
      link.download = node.name;
      link.title = `Download ${node.name}`;
      link.onclick = event => event.stopPropagation();
      cell.append(link);
    } else cell.textContent = state === undefined ? "Checking…" : state === false ? "Missing" : "Check failed";
  }
  if (checkingDownloads) return;
  const hashes = [...new Set(mounted.filter(node => !availability.has(node.hash)).map(node => node.hash))].slice(0, 128);
  if (!hashes.length) return;
  checkingDownloads = true;
  try {
    const query = new URLSearchParams(hashes.map(hash => ["hash", hash]));
    const response = await fetch(`api/availability?${query}`, { signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const result = await response.json();
    for (const hash of hashes) availability.set(hash, result[hash] === true);
  } catch {
    for (const hash of hashes) availability.set(hash, null);
  } finally {
    checkingDownloads = false;
    refreshDownloads();
  }
}

function scrollMetrics() {
  const host = $("table-scroll");
  const viewport = Math.max(0, host.clientHeight - $("tree").tHead.offsetHeight);
  const logicalHeight = visible.length * rowHeight;
  // Stay below browser layout limits; rendered rows retain their normal height.
  const height = Math.min(logicalHeight, 8_000_000);
  const maximum = Math.max(0, height - viewport);
  const logicalMaximum = Math.max(0, logicalHeight - viewport);
  // Leave room for overscan at both physical ends. The rest of the scrollbar
  // maps proportionally over the entire remaining logical range.
  const edge = logicalMaximum > maximum
    ? Math.min(maximum / 4, (overscan + 2) * rowHeight + $("tree").tHead.offsetHeight) : 0;
  const scale = maximum ? (logicalMaximum - 2 * edge) / (maximum - 2 * edge) : 1;
  return { height, maximum, logicalMaximum, viewport, edge, scale, offset: logicalOffset };
}

function globalScrollOffset(position, metrics) {
  if (position <= metrics.edge) return position;
  if (position >= metrics.maximum - metrics.edge)
    return metrics.logicalMaximum - (metrics.maximum - position);
  return metrics.edge + (position - metrics.edge) * metrics.scale;
}

function globalScrollPosition(offset, metrics) {
  if (offset <= metrics.edge) return offset;
  if (offset >= metrics.logicalMaximum - metrics.edge)
    return metrics.maximum - (metrics.logicalMaximum - offset);
  return metrics.edge + (offset - metrics.edge) / metrics.scale;
}

function nativeScrollPosition(metrics) {
  // A large, bounded native-input window, aligned to a real logical endpoint
  // when it is nearby. Most gestures never need a rebase while in motion.
  return Math.min(logicalOffset,
    Math.max(metrics.maximum / 2, metrics.maximum - (metrics.logicalMaximum - logicalOffset)));
}

function writeScrollPosition(position) {
  physicalOffset = position;
  // Install the new spacer geometry before scrolling: the old DOM may describe
  // a shorter tree/search result and otherwise clamp the requested position.
  renderWindow();
  $("table-scroll").scrollTop = position;
  const actual = $("table-scroll").scrollTop;
  if (actual !== physicalOffset) {
    physicalOffset = actual;
    renderWindow();
  }
  // Record the browser-rounded position immediately. Its asynchronous scroll
  // event is then a zero delta, without dropping any intervening native motion.
}

function setScrollOffset(offset, keepNative = false) {
  clearTimeout(scrollEndTimer);
  nativeScrolling = keepNative || touchCount > 0;
  const metrics = scrollMetrics();
  logicalOffset = Math.max(0, Math.min(metrics.logicalMaximum, offset));
  writeScrollPosition(nativeScrolling ? nativeScrollPosition(metrics) : globalScrollPosition(logicalOffset, metrics));
  scheduleScrollEnd();
}

function readScrollOffset() {
  const metrics = scrollMetrics();
  // A viewport change can clamp scrollTop before ResizeObserver runs. That is
  // a layout adjustment, not input; retain the logical row and remap instead.
  if (metrics.viewport !== scrollViewport) {
    resizeScroll();
    return logicalOffset;
  }
  const position = Math.max(0, Math.min(metrics.maximum, $("table-scroll").scrollTop));
  if (position !== physicalOffset) {
    const delta = nativeScrolling ? position - physicalOffset
      : globalScrollOffset(position, metrics) - globalScrollOffset(physicalOffset, metrics);
    logicalOffset = Math.max(0, Math.min(metrics.logicalMaximum, logicalOffset + delta));
    if (!nativeScrolling && (position === 0 || position === metrics.maximum))
      logicalOffset = position === 0 ? 0 : metrics.logicalMaximum;
    physicalOffset = position;
  }
  return logicalOffset;
}

function rebaseNativeScroll() {
  const metrics = scrollMetrics();
  const guard = Math.min(metrics.maximum / 4, Math.max(65_536, metrics.viewport * 4));
  if ((physicalOffset < guard && logicalOffset > physicalOffset)
    || (metrics.maximum - physicalOffset < guard
      && metrics.logicalMaximum - logicalOffset > metrics.maximum - physicalOffset))
    writeScrollPosition(nativeScrollPosition(metrics));
}

function beginNativeScroll() {
  // Compositor scrolling may precede a passive wheel callback. Consume that
  // first pending movement as native pixels, not as a scrollbar-track jump.
  const starting = !nativeScrolling;
  nativeScrolling = true;
  readScrollOffset();
  if (starting) rebaseNativeScroll();
  scheduleScrollEnd();
}

function finishNativeScroll() {
  if (!nativeScrolling || touchCount) return;
  setScrollOffset(readScrollOffset());
}

function scheduleScrollEnd() {
  clearTimeout(scrollEndTimer);
  // Debounce scrollend as well: internal rebases can emit it, and wheel packets
  // may be separate native animations. Never remap under a stationary finger.
  if (nativeScrolling && !touchCount)
    scrollEndTimer = setTimeout(finishNativeScroll, 180);
}

function resizeScroll() {
  const nextHeight = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--row-height"));
  const position = logicalOffset / rowHeight;
  if (nextHeight !== rowHeight) {
    rowHeight = nextHeight;
    windowVersion++;
  }
  if (root) setScrollOffset(position * rowHeight, nativeScrolling);
}

function renderWindow() {
  const host = $("table-scroll");
  const metrics = scrollMetrics();
  const start = Math.min(visible.length, Math.max(0, Math.floor(metrics.offset / rowHeight) - overscan));
  const end = Math.min(visible.length, start + Math.ceil(host.clientHeight / rowHeight) + overscan * 2);
  const compact = getComputedStyle($("heading-hash")).display === "none";
  scrollViewport = metrics.viewport;
  const key = `${windowVersion}:${start}:${end}:${metrics.viewport}:${compact}:${physicalOffset - metrics.offset}`;
  if (key === windowKey) return;
  windowKey = key;
  const columns = (downloadsEnabled ? 4 : 3) - Number(compact);
  $("tree").setAttribute("aria-colcount", String(columns));
  const fragment = document.createDocumentFragment();
  function spacer(height) {
    if (!height) return;
    const row = element("tr", "tree-spacer");
    row.setAttribute("aria-hidden", "true");
    const cell = element("td"); cell.colSpan = columns;
    cell.style.height = `${height}px`;
    row.append(cell); fragment.append(row);
  }
  const before = Math.max(0, physicalOffset + start * rowHeight - metrics.offset);
  spacer(before);
  for (let index = start; index < end; index++) {
    const node = visible[index], row = rowElements.get(node.index) || createRow(node);
    row.classList.toggle("selected", node === selected);
    row.setAttribute("aria-selected", String(node === selected));
    const button = disclosures.get(node);
    if (button) {
      const expanded = !collapsed.has(node.index);
      row.setAttribute("aria-expanded", String(expanded));
      button.textContent = expanded ? "▾" : "▸";
      button.setAttribute("aria-label", `${expanded ? "Collapse" : "Expand"} ${node.name}`);
    }
    if (node.gamePrefix) {
      highlight(node.pathElement, filterNodes && !compact ? node.displayPath.slice(0, -label(node).length) : "");
      highlight(node.prefixElement, node.gamePrefix);
      highlight(node.titleElement, label(node).slice(node.gamePrefix.length));
    } else highlight(node.nameElement, filterNodes && !compact ? node.displayPath : label(node));
    row.setAttribute("aria-level", filterNodes ? 1 : node.depth + 1);
    if (node.note) highlight(node.noteElement, node.note);
    if (node.hashElement) highlight(node.hashElement, node.hash.slice(0, 12));
    if (node.error) highlight(node.errorElement, `error: ${node.error}`);
    row.setAttribute("aria-rowindex", index + 2);
    fragment.append(row);
  }
  spacer(Math.max(0, metrics.height - before - (end - start) * rowHeight));
  const mounted = new Set(visible.slice(start, end));
  for (const [index] of rowElements) {
    const node = nodes[index];
    if (mounted.has(node)) continue;
    rowElements.delete(index);
    disclosures.delete(node);
    for (const key of ["nameElement", "pathElement", "prefixElement", "titleElement",
      "noteElement", "hashElement", "errorElement", "downloadCell"]) delete node[key];
  }
  $("entries").replaceChildren(fragment);
  refreshDownloads();
}

$("table-scroll").addEventListener("scroll", () => {
  readScrollOffset();
  if (nativeScrolling) {
    rebaseNativeScroll();
    scheduleScrollEnd();
  }
  if (!scrollFrame) scrollFrame = requestAnimationFrame(() => { scrollFrame = 0; renderWindow(); });
}, { passive: true });
$("table-scroll").addEventListener("wheel", event => {
  if (!event.ctrlKey && !event.shiftKey && event.deltaY) beginNativeScroll();
}, { passive: true });
$("table-scroll").addEventListener("touchstart", event => {
  touchCount = event.touches.length;
  beginNativeScroll();
}, { passive: true });
for (const type of ["touchend", "touchcancel"]) {
  $("table-scroll").addEventListener(type, event => {
    touchCount = event.touches.length;
    scheduleScrollEnd();
  }, { passive: true });
}
$("table-scroll").addEventListener("scrollend", scheduleScrollEnd, { passive: true });
$("table-scroll").addEventListener("pointerdown", event => {
  if (event.pointerType !== "touch") finishNativeScroll();
}, { passive: true });
new ResizeObserver(resizeScroll).observe($("table-scroll"));

function highlight(el, text) {
  const lower = text.toLowerCase();
  const terms = searchTerms.filter(term => lower.includes(term));
  const signature = JSON.stringify([text, terms]);
  if (highlightCache.get(el) === signature) return;
  highlightCache.set(el, signature);
  if (!terms.length && el.childNodes.length === 1 && el.firstChild.nodeType === Node.TEXT_NODE && el.textContent === text) return;
  el.replaceChildren();
  let offset = 0;
  while (offset < text.length) {
    let start = text.length, length = 0;
    for (const term of terms) {
      const index = lower.indexOf(term, offset);
      if (index !== -1 && (index < start || (index === start && term.length > length))) {
        start = index; length = term.length;
      }
    }
    el.append(document.createTextNode(text.slice(offset, start)));
    if (!length) break;
    el.append(element("mark", "", text.slice(start, start + length)));
    offset = start + length;
  }
}


function updateSortHeaders() {
  for (const key of ["name", "size", "hash"]) {
    const button = $("sort-" + key), heading = $("heading-" + key);
    button.disabled = !filterNodes;
    const active = filterNodes && key === searchSort;
    heading.setAttribute("aria-sort", active ? (sortDirection === 1 ? "ascending" : "descending") : "none");
    button.querySelector("span").textContent = active ? (sortDirection === 1 ? " ↑" : " ↓") : "";
  }
}

function sortSearch(key) {
  if (!filterNodes) return;
  if (key !== searchSort) {
    searchSort = key;
    sortDirection = 1;
  } else if (sortDirection === 1) {
    sortDirection = -1;
  } else {
    searchSort = null;
  }
  return requestSearch();
}

function yieldPage() {
  return globalThis.scheduler?.yield ? scheduler.yield() : new Promise(resolve => setTimeout(resolve, 0));
}

function cancelSearch() {
  searchVersion++;
  settleSearch?.();
  settleSearch = null;
  searchWorker?.postMessage({ type: "cancel", version: searchVersion });
}

function searchFailure(error) {
  cancelSearch();
  searchWorker?.terminate();
  searchWorker = null;
  $("tree-search").disabled = true;
  $("tree").removeAttribute("aria-busy");
  $("search-count").textContent = `Search unavailable (${error.message}). Reload to try again.`;
}

async function initializeSearch() {
  searchWorker?.terminate();
  cancelSearch();
  const worker = new Worker("search-worker.js");
  searchWorker = worker;
  let readyResolve, readyReject;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  // Handle early startup errors even while the index is still being assembled.
  ready.catch(() => {});
  let failure = null;
  worker.onerror = event => {
    event.preventDefault();
    failure = new Error(event.message || "Search worker failed");
    readyReject(failure);
    if (searchWorker === worker) searchFailure(failure);
  };
  worker.onmessage = async ({ data }) => {
    if (searchWorker !== worker) return;
    if (data.type === "ready") { readyResolve(true); return; }
    if (data.type === "error") {
      failure = new Error(data.message);
      readyReject(failure);
      searchFailure(failure);
      return;
    }
    if (data.type !== "results" || data.version !== searchVersion) return;
    const matches = new Array(data.ids.length);
    for (let start = 0; start < matches.length; start += 8192) {
      const end = Math.min(start + 8192, matches.length);
      for (let i = start; i < end; i++) matches[i] = nodes[data.ids[i]];
      if (end < matches.length) await yieldPage();
      if (data.version !== searchVersion) return;
    }
    filterNodes = matches;
    $("search-count").textContent = `${number.format(matches.length)} matching files`;
    $("tree").removeAttribute("aria-busy");
    const query = $("tree-search").value.trim();
    $("search-empty").hidden = matches.length !== 0;
    if (!matches.length) {
      $("search-empty").textContent = `No matches for “${query}”`;
      const clear = element("button", "", "Clear filter");
      clear.onclick = clearSearch;
      $("search-empty").append(clear);
    }
    updateSortHeaders();
    render(0);
    if (visible.length) select(visible.includes(selected) ? selected : visible[0], false, false);
    else {
      $("tree").removeAttribute("aria-activedescendant");
      $("selected-error").hidden = true;
      $("selected-path").textContent = "";
      $("selected-detail").textContent = "";
      $("open-selected").hidden = true;
      $("copy-selected").hidden = true;
    }
    settleSearch?.();
    settleSearch = null;
  };
  const count = nodes.length;
  const parents = new Int32Array(count), names = new Uint32Array(count), labels = new Uint32Array(count);
  const texts = new Uint32Array(count), hashes = new Uint32Array(count), errors = new Uint32Array(count);
  const sizes = new Float64Array(count), order = new Uint32Array(root.files);
  const strings = [""], interned = new Map([["", 0]]);
  function intern(text) {
    if (!text) return 0;
    let id = interned.get(text);
    if (id === undefined) { id = strings.length; strings.push(text); interned.set(text, id); }
    return id;
  }
  let sent = 0;
  for (let start = 0; start < count; start += 8192) {
    for (let i = start; i < Math.min(start + 8192, count); i++) {
      const node = nodes[i];
      texts[i] = node.displayName || node.note || node.searchMetadata
        ? intern(`${node.displayName || ""} ${node.note || ""} ${node.searchMetadata || ""}`) : 0;
      names[i] = intern(node.name);
      labels[i] = intern(label(node));
      parents[i] = node.parent ? node.parent.index : -1;
      hashes[i] = intern(node.hash);
      errors[i] = intern(node.error ? `error: ${node.error}` : "");
      sizes[i] = node.size;
      if (node.type === "file") order[node.fileOrder] = i;
    }
    if (failure) throw failure;
    if (searchWorker !== worker) return false;
    if (sent < strings.length) worker.postMessage({ type: "strings", strings: strings.slice(sent) });
    sent = strings.length;
    await yieldPage();
  }
  worker.postMessage({ type: "index", parents, names, labels, texts, hashes, errors, sizes, order },
    [parents.buffer, names.buffer, labels.buffer, texts.buffer, hashes.buffer, errors.buffer, sizes.buffer, order.buffer]);
  await ready;
  if (searchWorker !== worker) return false;
  return true;
}

function requestSearch() {
  cancelSearch();
  const version = searchVersion;
  searchSettled = new Promise(resolve => { settleSearch = resolve; });
  $("search-count").textContent = "Searching…";
  $("search-empty").hidden = true;
  $("tree").setAttribute("aria-busy", "true");
  searchReady.then(ready => {
    if (version !== searchVersion) return;
    if (!ready) { settleSearch?.(); settleSearch = null; return; }
    searchWorker.postMessage({ type: "search", version, terms: searchTerms, sort: searchSort, direction: sortDirection });
  });
  return searchSettled;
}

function applySearch() {
  const query = $("tree-search").value.trim();
  $("clear-search").hidden = !$("tree-search").value;
  const address = new URL(location.href);
  if ($("tree-search").value) address.searchParams.set("q", $("tree-search").value);
  else address.searchParams.delete("q");
  if (address.href !== location.href) history.replaceState(null, "", address);
  if (!catalogReady || $("tree-search").disabled) return;
  searchTerms = query.toLowerCase().split(/\s+/).filter(Boolean);
  $("tree").classList.toggle("search-results", Boolean(query));
  if (query) {
    if (!savedTree) savedTree = {
      collapsed: new Set(collapsed), selected, scroll: readScrollOffset() / rowHeight,
    };
    filterNodes ||= [];
    updateSortHeaders();
    return requestSearch();
  }
  cancelSearch();
  searchSettled = Promise.resolve();
  filterNodes = null;
  $("search-count").textContent = "";
  $("search-empty").hidden = true;
  $("tree").removeAttribute("aria-busy");
  if (savedTree) {
    collapsed.clear();
    for (const index of savedTree.collapsed) collapsed.add(index);
  }
  updateSortHeaders();
  render();
  if (savedTree) {
    select(savedTree.selected, false);
    setScrollOffset(savedTree.scroll * rowHeight);
    savedTree = null;
  }
  return searchSettled;
}

function clearSearch() {
  $("tree-search").value = "";
  applySearch();
  (catalogReady ? $("tree") : $("tree-search")).focus({ preventScroll: true });
}

function element(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}

class CatalogNode {
  constructor(parent, name, data) {
    this.index = nodes.length;
    this.parent = parent;
    this.name = name;
    this.type = "directory";
    this.children = emptyChildren;
    this.depth = parent ? parent.depth + 1 : 0;
    this.size = 0;
    this.files = 0;
    Object.assign(this, data);
  }
  get id() { return `node-${this.index}`; }
  get path() {
    const parts = [];
    for (let node = this; node?.parent; node = node.parent) parts.push(node.name);
    return parts.reverse().join("/");
  }
  get displayPath() {
    if (!this.parent) return label(this);
    const parts = [];
    for (let node = this; node.parent; node = node.parent) parts.push(label(node));
    return parts.reverse().join("/");
  }
}

function nodeAtPath(path) {
  let node = root;
  if (!path) return node;
  for (const part of path.split("/")) {
    node = node.children.find(child => child.name === part);
    if (!node) return undefined;
  }
  return node;
}

function add(parent, name, data = {}) {
  const node = new CatalogNode(parent, name, data);
  nodes.push(node);
  if (parent) {
    if (parent.children === emptyChildren) parent.children = [];
    parent.children.push(node);
  }
  return node;
}

function expandable(node) { return node.type === "directory" || Boolean(node.extraction); }

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

let buildWork = 0;
function* addInventory(parent, entries, extractions = {}, ancestors = new Set(), nameRule = null) {
  const directories = new Map([["", parent]]);
  for (const entry of entries) {
    if (++buildWork % 4096 === 0) yield;
    const parts = entry.path.split("/");
    const name = extractedName(parent.name, parts.pop(), nameRule);
    let path = "", directory = parent;
    for (const part of parts) {
      path = path ? `${path}/${part}` : part;
      if (!directories.has(path)) directories.set(path, add(directory, part));
      directory = directories.get(path);
    }
    if (entry.type === "directory") {
      if (!directories.has(entry.path)) directories.set(entry.path, add(directory, name));
    } else {
      const node = add(directory, name, { type: "file", size: entry.size_bytes, hash: entry.sha256, redump: entry.redump || emptyChildren });
      if (entry.extraction || extractions[node.hash] !== undefined)
        yield* attachExtraction(node, extractions, ancestors, entry.extraction);
    }
  }
}

function* attachExtraction(node, extractions, ancestors = new Set(), contextual = null, source = null) {
  const extraction = contextual || (source === null ? extractions[node.hash] : source[node.hash]);
  if (extraction === null) throw new Error(`Ambiguous non-root extraction kinds: ${node.hash}`);
  if (!extraction || (contextual && extraction.sha256 !== node.hash) || extraction.size_bytes !== node.size || ancestors.has(extraction)) return;
  node.extraction = extraction.extractor.name;
  node.extractionKind = extraction.extraction_kind;
  node.extractionVersion = extraction.extractor.version;
  if (extraction.error) {
    node.error = extraction.error;
  }
  if (extraction.stale_extraction) node.stale_extraction = extraction.stale_extraction;
  yield* addInventory(node, extraction.entries, extractions, new Set([...ancestors, extraction]), extraction.name_rule);
}

function addGroup(parent, name, data = {}) {
  return add(parent, name, { ...data, virtual: true });
}

function packageSerial(metadata) {
  const id = metadata.title_id?.trim() || metadata.content_id?.match(/^[^-]+-([A-Z0-9]{9})_/i)?.[1] || "";
  return id.toUpperCase().replace(/^([A-Z0-9]{4})-?([0-9]{5})$/, "$1-$2");
}

function packageGroup(contentType, packageFlags) {
  switch (contentType) {
    case 6: return "psone_classic";
    case 7:
      // PSP update heuristic: package metadata entry 3, bit 4.
      return Number.isInteger(packageFlags) && (packageFlags & 0x10) !== 0 ? "update" : null;
    case 14: return null;
    case 15: return "minis";
    case 9: return "theme";
    case 16: return "neogeo";
    default: return "unknown";
  }
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

async function build(data) {
  cancelSearch();
  searchWorker?.terminate();
  searchWorker = null;
  for (const _ of buildCatalog(data)) await yieldPage();
  searchReady = initializeSearch().catch(error => { searchFailure(error); return false; });
}

function* buildCatalog(data) {
  nodes.length = 0;
  buildWork = 0;
  downloadsEnabled = data.downloads_enabled === true;
  availability.clear();
  $("download-col").hidden = !downloadsEnabled;
  $("download-heading").hidden = !downloadsEnabled;
  $("tree").setAttribute("aria-colcount", downloadsEnabled ? "4" : "3");
  root = addGroup(null, "");
  // Show the aggregate root without changing existing UMD/PSN URL paths.
  root.name = "psp";
  const umd = addGroup(root, "umd");
  const categories = new Map();
  function mediaGroup(code) {
    const name = code === "G" ? "game" : code === "V" ? "video" : "other";
    if (!categories.has(name)) categories.set(name, addGroup(umd, name));
    return categories.get(name);
  }
  const isos = data.records.iso || [];
  const extractions = Object.create(null), sizes = new Map();
  for (const [kind, sources] of Object.entries(data.trees)) {
    for (const [hash, tree] of Object.entries(sources)) {
      if (sizes.has(hash) && sizes.get(hash) !== tree.size_bytes) throw new Error(`Conflicting source sizes: ${hash}`);
      sizes.set(hash, tree.size_bytes);
      if (kind === "iso" || kind === "pkg" || kind === "nand" || kind === "update") continue;
      extractions[hash] = hash in extractions ? null : tree;
    }
  }
  for (const iso of isos) {
    const metadata = iso.metadata || {};
    const category = mediaGroup(metadata.media_code);
    const id = (metadata.disc_id || metadata.identifier || "").trim().replace(/^([A-Z]{4})-?([0-9]{5})$/, "$1-$2");
    const identity = [id, metadata.disc_version].filter(Boolean).join("/");
    const displayName = metadata.media_code === "V"
      ? metadata.title?.trim() || identity
      : [identity, metadata.title?.trim()].filter(Boolean).join(" ");
    const node = add(category, `${iso.sha256}.iso`, {
      type: "file",
      redump: iso.redump || [], umdatabase: iso.umdatabase || [], hash: iso.sha256, size: iso.size_bytes,
      displayName,
      gamePrefix: metadata.media_code === "G" ? identity : null,
    });
    yield* attachExtraction(node, extractions, new Set(), null, data.trees.iso || {});
  }
  const packages = data.records.pkg || [];
  if (packages.length) {
    const psn = addGroup(root, "psn");
    const labels = packageLabels(packages);
    const groups = new Map([[null, psn]]);
    for (const pkg of packages) {
      const metadata = pkg.metadata || {};
      const category = packageGroup(metadata.content_type, metadata.package_flags);
      if (!groups.has(category)) groups.set(category, addGroup(psn, category));
      const node = add(groups.get(category), `${pkg.sha256}.pkg`, {
        type: "file", hash: pkg.sha256, size: pkg.size_bytes,
        displayName: labels.get(pkg.sha256),
        gamePrefix: packageSerial(metadata) || null,
        searchMetadata: metadata.content_id || "",
      });
      yield* attachExtraction(node, extractions, new Set(), null, data.trees.pkg || {});
    }
  }
  const firmware = addGroup(root, "firmware");
  const nandGroup = addGroup(firmware, "nand");
  const updateGroup = addGroup(firmware, "update");
  const nands = data.records.nand || [];
  for (const nand of nands) {
    const metadata = nand.metadata || {};
    const validGeometry = metadata.page_bytes === 512 && metadata.spare_bytes === 16
      && metadata.pages_per_block === 32 && (metadata.blocks === 2048 || metadata.blocks === 4096)
      && nand.size_bytes === metadata.blocks * 32 * 528;
    const node = add(nandGroup, `${nand.sha256}.nand`, {
      type: "file", hash: nand.sha256, size: nand.size_bytes,
      displayName: validGeometry ? `${metadata.blocks / 64} MiB NAND · ${nand.sha256.slice(0, 12)}` : null,
    });
    yield* attachExtraction(node, extractions, new Set(), null, data.trees.nand || {});
  }
  const updates = data.records.update || [];
  for (const update of updates) {
    const metadata = update.metadata || {};
    const version = metadata.updater_version?.trim();
    const node = add(updateGroup, `${update.sha256}.pbp`, {
      type: "file", hash: update.sha256, size: update.size_bytes,
      displayName: version ? `Update ${version}${metadata.updater_target === "psp-go" ? " Go" : ""} · ${update.sha256.slice(0, 12)}` : null,
      searchMetadata: [metadata.title, metadata.disc_id].filter(Boolean).join(" "),
    });
    yield* attachExtraction(node, extractions, new Set(), null, data.trees.update || {});
  }
  let fileOrder = 0;
  const pending = [root];
  while (pending.length) {
    const node = pending.pop();
    if (++buildWork % 8192 === 0) yield;
    if (node.children.length > 1) node.children.sort((a, b) => (a.type === b.type ? 0 : a.type === "directory" ? -1 : 1)
      || (label(a) < label(b) ? -1 : label(a) > label(b) ? 1 : 0));
    if (node.type === "file") node.fileOrder = fileOrder++;
    node.files = node.type === "file" ? 1 : 0;
    for (let i = node.children.length - 1; i >= 0; i--) pending.push(node.children[i]);
  }
  for (let i = nodes.length - 1; i > 0; i--) {
    const node = nodes[i], parent = node.parent;
    parent.files += node.files;
    if (parent.type === "directory") parent.size += node.size;
    if (i % 8192 === 0) yield;
  }
  $("catalog-count").textContent = `${isos.length} UMD images · ${packages.length} PSN packages · ${nands.length} NAND dumps · ${updates.length} updater PBPs · ${number.format(root.files)} files`;
}

function url(node) { return "#" + node.path.split("/").map(encodeURIComponent).join("/"); }
function label(node) { return node.displayName || node.name; }

function select(node, scroll = true, updateURL = true) {
  if (!node || !visible.includes(node)) return;
  const previous = selected && rowElements.get(selected.index);
  previous?.classList.remove("selected");
  previous?.setAttribute("aria-selected", "false");
  selected = node;
  const row = rowElements.get(node.index);
  row?.classList.add("selected");
  row?.setAttribute("aria-selected", "true");
  $("tree").setAttribute("aria-activedescendant", node.id);
  $("selected-path").textContent = node.path || label(node);
  $("selected-detail").textContent = `${number.format(node.size)} bytes${node.extraction ? ` · ${node.extraction}` : ""}`;
  $("open-selected").hidden = !filterNodes;
  $("copy-selected").hidden = !node.hash;
  $("selected-error").hidden = !node.error;
  $("selected-error-message").textContent = node.error ? `error: ${node.error}` : "";
  $("notice").textContent = "";
  if (scroll || node.error) {
    // Scroll only vertically, preserving the user's horizontal column position.
    const top = visible.indexOf(node) * rowHeight;
    readScrollOffset();
    const metrics = scrollMetrics();
    const offset = top < metrics.offset ? top
      : top + rowHeight > metrics.offset + metrics.viewport ? top + rowHeight - metrics.viewport : metrics.offset;
    setScrollOffset(offset);
  }
  if (updateURL) history.replaceState(null, "", url(node));
}

function jump(node, focus = true) {
  if (savedTree) clearSearch();
  for (let parent = node.parent; parent; parent = parent.parent) collapsed.delete(parent.index);
  render();
  select(node);
  setScrollOffset(Math.max(0, (visible.indexOf(node) - 2) * rowHeight));
  if (focus) $("tree").focus({ preventScroll: true });
}

function toggle(node) {
  if (filterNodes || !expandable(node)) return;
  if (collapsed.has(node.index)) {
    collapsed.delete(node.index);
  } else collapsed.add(node.index);
  render();
  select(node);
  $("tree").focus({ preventScroll: true });
}

function render(offset = readScrollOffset()) {
  visible = [];
  function walk(node) {
    visible.push(node);
    if (!collapsed.has(node.index)) for (const child of node.children) walk(child);
  }
  if (filterNodes) visible = filterNodes;
  else walk(root);
  windowVersion++;
  $("tree").setAttribute("aria-rowcount", visible.length + 1);
  setScrollOffset(offset);
}

function createRow(node) {
    const folder = expandable(node);
    const container = Boolean(node.extraction);
    const row = element("tr", `node ${container ? "file container" : folder ? "folder" : "file"}${node.virtual && !container ? " virtual" : ""}`);
    if (node.error) row.classList.add("extraction-failed");
    row.id = node.id;
    row.dataset.path = node.path;
    row.dataset.node = node.index;
    row.setAttribute("aria-level", node.depth + 1);
    row.setAttribute("aria-selected", "false");
    if (folder) row.setAttribute("aria-expanded", String(!collapsed.has(node.index)));
    const nameCell = element("td", "name-cell");
    nameCell.style.setProperty("--depth", node.depth);
    const content = element("div", "name-content");
    if (folder) {
      const disclosure = element("button", "toggle", collapsed.has(node.index) ? "▸" : "▾");
      disclosure.tabIndex = -1;
      disclosure.setAttribute("aria-label", `${collapsed.has(node.index) ? "Expand" : "Collapse"} ${node.name}`);
      disclosure.onclick = event => { event.stopPropagation(); toggle(node); };
      disclosures.set(node, disclosure);
      content.append(disclosure);
    } else content.append(element("span", "file-mark", "·"));
    const name = element("span", "name", label(node));
    node.nameElement = name;
    if (node.gamePrefix) {
      node.pathElement = element("span", "");
      node.prefixElement = element("span", "game-identity", node.gamePrefix);
      node.titleElement = element("span", "", label(node).slice(node.gamePrefix.length));
      name.replaceChildren(node.pathElement, node.prefixElement, node.titleElement);
    }
    name.title = node.error ? `error: ${node.error}` : node.extraction ? `${node.path} — extracted with ${node.extraction}` : node.virtual ? `${node.path || label(node)} — catalog grouping, not a filesystem directory` : node.path;
    content.append(name);
    for (const [source, matches] of [["Redump", node.redump || []], ["UMDatabase", node.umdatabase || []]]) {
      for (const match of matches) {
        const redump = source === "Redump";
        if (redump ? !Number.isSafeInteger(match.id) || match.id <= 0 : !/^[0-9A-F]{8}$/.test(match.id)) continue;
        const label = matches.length === 1 ? source : `${source} #${match.id}`;
        const link = element("a", redump ? "redump-link" : "umdatabase-link");
        link.append(element("span", "reference-label", `${label} `));
        const icon = element("span", "reference-icon", "↗");
        icon.setAttribute("aria-hidden", "true");
        link.append(icon);
        link.href = redump ? `http://redump.org/disc/${match.id}/` : `https://umdatabase.net/view.php?id=${match.id}`;
        link.title = `${label}: ${match.name}`;
        link.setAttribute("aria-label", link.title);
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.onclick = event => event.stopPropagation();
        content.append(link);
      }
    }
    if (node.note) { node.noteElement = element("span", "note", node.note); content.append(node.noteElement); }
    if (node.error) {
      const error = element("span", "extraction-error");
      const icon = element("span", "error-icon", "!");
      icon.setAttribute("aria-hidden", "true");
      node.errorElement = element("span", "error-message", `error: ${node.error}`);
      node.errorElement.id = `${node.id}-error`;
      row.setAttribute("aria-describedby", node.errorElement.id);
      error.append(icon, node.errorElement);
      content.append(error);
    }
    if (container && node.extractionKind) {
      const tags = element("span", "extraction-tags");
      const kind = node.extractionKind.toUpperCase();
      tags.append(element("span", "extraction-tag", kind));
      if (node.extractionVersion) {
        const version = element("span", "extraction-tag", `v${node.extractionVersion}`);
        if (node.stale_extraction) {
          const { version: recorded, latest_version } = node.stale_extraction;
          const message = `Outdated ${kind} subtree v${recorded} (latest is v${latest_version})`;
          version.classList.add("outdated");
          version.title = message;
          version.setAttribute("aria-label", message);
        }
        tags.append(version);
      }
      content.append(tags);
    }
    nameCell.append(content);
    const displayedSize = node.size;
    const summed = node.type === "directory";
    const bytes = element("td", "size", `${summed ? "Σ " : ""}${formatSize(displayedSize)}`);
    bytes.title = `${number.format(displayedSize)} bytes${summed ? " — sum of contained file sizes, excluding their extracted contents; includes filtered files" : ""}`;
    const hashCell = element("td", "hash");
    const hash = node.hash;
    if (hash) {
      const copy = element("button", "", hash.slice(0, 12));
      node.hashElement = copy;
      copy.tabIndex = -1;
      copy.title = `${hash}\nClick to copy full file SHA-256`;
      copy.onclick = async event => {
        event.stopPropagation(); select(node, false);
        $("notice").textContent = await copyHash(hash) ? "SHA-256 copied" : "Copy unavailable in this browser";
      };
      hashCell.append(copy);
    } else hashCell.textContent = "—";
    row.append(nameCell, bytes, hashCell);
    if (downloadsEnabled) {
      node.downloadCell = element("td", "download-cell", folder ? "" : "Checking…");
      row.append(node.downloadCell);
    }
    row.onclick = () => { select(node, false); $("tree").focus({ preventScroll: true }); };
    row.ondblclick = event => {
      if (event.target.closest("button, a")) return;
      if (filterNodes) jump(node);
      else if (folder) toggle(node);
    };
    rowElements.set(node.index, row);
    return row;
}

function restore(focus = true) {
  let path;
  try { path = location.hash.slice(1).split("/").map(decodeURIComponent).join("/"); } catch { path = ""; }
  jump(nodeAtPath(path) || root, focus);
}

$("tree-search").value = new URLSearchParams(location.search).get("q") || "";
$("clear-search").hidden = !$("tree-search").value;
$("tree-search").addEventListener("input", applySearch);
$("clear-search").onclick = clearSearch;
$("open-selected").onclick = () => { if (selected && filterNodes) jump(selected); };
$("copy-selected").onclick = async () => {
  if (selected?.hash) $("notice").textContent = await copyHash(selected.hash) ? "SHA-256 copied" : "Copy unavailable in this browser";
};
for (const key of ["name", "size", "hash"]) $("sort-" + key).onclick = () => sortSearch(key);

document.addEventListener("keydown", event => {
  if (catalogReady && !event.ctrlKey && !event.metaKey && !event.altKey) {
    if (event.key === "Escape" && (savedTree || event.target === $("tree-search"))) {
      event.preventDefault(); clearSearch(); return;
    }
    if (event.key === "Enter" && event.target === $("tree-search")) {
      event.preventDefault(); $("tree").focus({ preventScroll: true });
      select(selected, true, false); return;
    }
    if (event.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName)) {
      event.preventDefault(); $("tree-search").focus(); return;
    }
  }
  if (!catalogReady || event.ctrlKey || event.metaKey || event.altKey || /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName) || event.target === $("selected-error")) return;
  if (!visible.length) return;
  if (event.key === "Enter" && /^(BUTTON|A)$/.test(event.target.tagName)) return;
  const key = event.key;
  if (["PageUp", "PageDown", " "].includes(key) && $("table-scroll").contains(event.target)
    && !event.target.closest("button, a")) {
    beginNativeScroll();
    return;
  }
  if (!["h", "j", "k", "l", "ArrowLeft", "ArrowDown", "ArrowUp", "ArrowRight", "Enter", "Home", "End"].includes(key)) return;
  event.preventDefault();
  const node = selected;
  if (filterNodes && ["h", "l", "ArrowLeft", "ArrowRight", "Enter"].includes(key)) return;
  if (key === "h" || key === "ArrowLeft") {
    if (expandable(node) && !collapsed.has(node.index) && node.children.length) toggle(node);
    else select(node.parent || node);
  } else if (["l", "ArrowRight", "Enter"].includes(key)) {
    if (expandable(node)) {
      if (collapsed.has(node.index)) toggle(node);
      else select(node.children.find(child => visible.includes(child)) || node);
    }
  } else {
    const index = visible.indexOf(node);
    const next = key === "Home" ? 0 : key === "End" ? visible.length - 1 : index + (["j", "ArrowDown"].includes(key) ? 1 : -1);
    select(visible[Math.max(0, Math.min(visible.length - 1, next))]);
  }
  $("tree").focus({ preventScroll: true });
});
window.addEventListener("hashchange", () => { if (catalogReady) restore(); });

async function loadCatalog() {
  const response = await fetch(document.documentElement.dataset.catalog);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const progress = $("catalog-progress"), detail = $("download-detail");
  const encoding = response.headers.get("Content-Encoding");
  const decoded = !!encoding && encoding !== "identity";
  // Fetch decodes HTTP content encodings before exposing chunks. In that case
  // Content-Length counts different bytes, so do not invent a percentage.
  const length = decoded ? 0 : Number(response.headers.get("Content-Length"));
  const total = Number.isSafeInteger(length) && length > 0 ? length : 0;
  let received = 0, lastUpdate = 0;
  function update() {
    if (total) {
      progress.max = total;
      progress.value = Math.min(received, total);
      detail.textContent = `${formatSize(received)} / ${formatSize(total)} · ${Math.min(100, Math.floor(received / total * 100))}%`;
    } else {
      detail.textContent = `${formatSize(received)} received${decoded ? " (decoded)" : ""}`;
    }
  }
  $("loading-status").textContent = "Downloading catalog…";
  update();
  let body = response.body.pipeThrough(new TransformStream({
    transform(chunk, controller) {
      received += chunk.byteLength;
      const now = performance.now();
      if (now - lastUpdate >= 100) {
        lastUpdate = now;
        update();
      }
      controller.enqueue(chunk);
    },
    flush() {
      progress.max = 1;
      progress.value = 1;
      detail.textContent = `${formatSize(received)} received${decoded ? " (decoded)" : ""}`;
      $("loading-status").textContent = "Preparing catalog…";
    },
  }));
  if (document.documentElement.dataset.catalog.endsWith(".gz"))
    body = body.pipeThrough(new DecompressionStream("gzip"));
  return new Response(body).json();
}

loadCatalog().then(async data => {
  await build(data);
  for (const node of nodes) if (node.extraction) collapsed.add(node.index);
  $("message").hidden = true;
  $("browser").hidden = false;
  restore(document.activeElement !== $("tree-search") && document.activeElement !== $("clear-search"));
  catalogReady = true;
  if ($("tree-search").value) applySearch();
}).catch(error => {
  root = null;
  catalogReady = false;
  $("browser").hidden = true;
  $("message").hidden = false;
  $("catalog-progress").hidden = true;
  $("download-detail").hidden = true;
  $("loading-status").textContent = `Could not load the catalog (${error.message}). Reload to try again.`;
});
