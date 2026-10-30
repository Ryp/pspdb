"use strict";

const $ = id => document.getElementById(id);
const number = new Intl.NumberFormat("en-US");
const sizeNumber = new Intl.NumberFormat("en-US", { maximumSignificantDigits: 3 });
const { referenceUUID, buildCatalog, parseContainer, HashStore, StaleCatalogError } = PspdbCatalog;
const REFERENCE_SOURCES = [
  { source: "Redump", field: "redump", className: "redump-link",
    valid: id => Number.isSafeInteger(id) && id > 0,
    href: id => `http://redump.org/disc/${id}/` },
  { source: "UMDatabase", field: "umdatabase", className: "umdatabase-link",
    valid: id => /^[0-9A-F]{8}$/.test(id),
    href: id => `https://umdatabase.net/view.php?id=${id}` },
  { source: "SerialStation", field: "serialstation", className: "serialstation-link",
    valid: referenceUUID,
    href: id => `https://serialstation.com/pkgs/${id}/` },
  { source: "SerialStation", field: "serialstation_discs", className: "serialstation-link",
    valid: referenceUUID,
    href: id => `https://serialstation.com/discs/${id}` },
];
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
// The catalog is a typed-array occurrence tree (catalog.js): a tree row is an
// integer `node`, an index into its parallel arrays, never an object.
let catalog = null, hashStore = null;
let collapsed = new Uint8Array(0);
const rows = new Map();
let selected = -1, visible = new Uint32Array(0);
let catalogReady = false;
let filterNodes = null, searchTerms = [], savedTree = null;
let searchWorker = null, searchReady = Promise.resolve(false), searchVersion = 0;
let searchSettled = Promise.resolve(), settleSearch = null;
let searchSort = null, sortDirection = 1;
const highlightCache = new WeakMap();
let rowHeight = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--row-height"));
const overscan = 20;
let windowKey = "", windowVersion = 0, scrollFrame = 0;
let logicalOffset = 0, physicalOffset = 0, scrollViewport = 0;
let nativeScrolling = false, touchCount = 0, scrollEndTimer = 0;
let downloadsEnabled = false, checkingDownloads = false, resolvingHashes = false;
const availability = new Map();
// Slots whose full digest could not be fetched: their rows report "Check failed".
const hashFailures = new Set();

const label = node => catalog.label(node);
const url = node => "#" + catalog.path(node).split("/").map(encodeURIComponent).join("/");
const expandable = node => catalog.expandable(node);

// Full digests are fetched lazily, a chunk of 4096 at a time. Catalog records
// carry theirs; every other row resolves its own on demand.
const hashOf = node => catalog.knownHash(node)
  ?? (catalog.slot[node] >= 0 ? hashStore.peek(catalog.slot[node]) : undefined);

function hashUrl(chunk) {
  const template = document.documentElement.dataset.hashes;
  return new URL(template.replace("{generation}", catalog.generation).replace("{chunk}", chunk), location.href).href;
}

function catalogChanged() {
  // The server replaced its catalog, so lazily fetched digests no longer match it.
  $("notice").textContent = "The catalog changed on the server — reloading…";
  setTimeout(() => location.reload(), 1000);
}

async function fullHash(node) {
  const known = hashOf(node);
  if (known || catalog.slot[node] < 0) return known;
  try {
    const hash = (await hashStore.resolve([catalog.slot[node]])).get(catalog.slot[node]);
    rows.get(node)?.describe?.(hash);
    return hash;
  } catch (error) {
    if (error instanceof StaleCatalogError) catalogChanged();
    throw error;
  }
}

async function copyNodeHash(node) {
  let hash;
  try { hash = await fullHash(node); }
  catch (error) { $("notice").textContent = `SHA-256 unavailable (${error.message})`; return; }
  $("notice").textContent = await copyHash(hash) ? "SHA-256 copied" : "Copy unavailable in this browser";
}

async function refreshDownloads() {
  if (!downloadsEnabled) return;
  const mounted = [], unresolved = [];
  for (const [node, parts] of rows) {
    if (!catalog.isFile(node) || catalog.slot[node] < 0) continue;
    const hash = hashOf(node);
    mounted.push({ node, parts, hash });
    if (!hash && !hashFailures.has(catalog.slot[node])) unresolved.push(catalog.slot[node]);
  }
  for (const { node, parts, hash } of mounted) {
    const cell = parts.download;
    const state = hash ? availability.get(hash) : hashFailures.has(catalog.slot[node]) ? null : undefined;
    if (cell.dataset.state === String(state)) continue;
    cell.dataset.state = String(state);
    cell.classList.toggle("missing", state === false);
    cell.replaceChildren();
    if (state === true) {
      const name = catalog.nameOf(node);
      const link = element("a", "download-link", "Download");
      link.href = `download/${hash}/${encodeURIComponent(name)}`;
      link.download = name;
      link.title = `Download ${name}`;
      link.onclick = event => event.stopPropagation();
      cell.append(link);
    } else cell.textContent = state === undefined ? "Checking…" : state === false ? "Missing" : "Check failed";
  }
  if (unresolved.length && !resolvingHashes) {
    resolvingHashes = true;
    hashStore.resolve(unresolved).catch(error => {
      if (error instanceof StaleCatalogError) catalogChanged();
      else for (const slot of unresolved) hashFailures.add(slot);
    }).finally(() => { resolvingHashes = false; refreshDownloads(); });
  }
  if (checkingDownloads) return;
  const hashes = [...new Set(mounted.filter(({ hash }) => hash && !availability.has(hash)).map(({ hash }) => hash))].slice(0, 128);
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
  if (catalog) setScrollOffset(position * rowHeight, nativeScrolling);
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
    const node = visible[index], parts = rows.get(node) || createRow(node);
    const { row } = parts;
    row.classList.toggle("selected", node === selected);
    row.setAttribute("aria-selected", String(node === selected));
    if (parts.disclosure) {
      const expanded = !collapsed[node];
      row.setAttribute("aria-expanded", String(expanded));
      parts.disclosure.textContent = expanded ? "▾" : "▸";
      parts.disclosure.setAttribute("aria-label", `${expanded ? "Collapse" : "Expand"} ${catalog.nameOf(node)}`);
    }
    if (parts.gamePrefix) {
      highlight(parts.path, filterNodes && !compact ? catalog.displayPath(node).slice(0, -label(node).length) : "");
      highlight(parts.prefix, parts.gamePrefix);
      highlight(parts.title, label(node).slice(parts.gamePrefix.length));
    } else highlight(parts.name, filterNodes && !compact ? catalog.displayPath(node) : label(node));
    row.setAttribute("aria-level", filterNodes ? 1 : parts.depth + 1);
    if (parts.hash) highlight(parts.hash, catalog.prefixHex(node, 12));
    if (parts.error) highlight(parts.error, `error: ${parts.errorText}`);
    row.setAttribute("aria-rowindex", index + 2);
    fragment.append(row);
  }
  spacer(Math.max(0, metrics.height - before - (end - start) * rowHeight));
  const mounted = new Set(visible.subarray(start, end));
  for (const node of rows.keys()) if (!mounted.has(node)) rows.delete(node);
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
  worker.onerror = event => {
    event.preventDefault();
    const failure = new Error(event.message || "Search worker failed");
    readyReject(failure);
    if (searchWorker === worker) searchFailure(failure);
  };
  worker.onmessage = ({ data }) => {
    if (searchWorker !== worker) return;
    if (data.type === "ready") { readyResolve(true); return; }
    if (data.type === "error") {
      const failure = new Error(data.message);
      readyReject(failure);
      searchFailure(failure);
      return;
    }
    if (data.version !== searchVersion) return;
    if (data.type === "stale") { catalogChanged(); return; }
    if (data.type === "hash-error") {
      // A long hash term could not be verified: report it, keep the page usable.
      $("tree").removeAttribute("aria-busy");
      $("search-count").textContent = data.message;
      settleSearch?.();
      settleSearch = null;
      return;
    }
    if (data.type !== "results") return;
    filterNodes = data.ids;
    $("search-count").textContent = `${number.format(filterNodes.length)} matching files`;
    $("tree").removeAttribute("aria-busy");
    const query = $("tree-search").value.trim();
    $("search-empty").hidden = filterNodes.length !== 0;
    if (!filterNodes.length) {
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
  // The worker searches copies of the occurrence arrays; ours keep rendering.
  const { message, transfer } = catalog.searchIndex(hashUrl("__chunk__"), new URL("catalog.js", location.href).href);
  worker.postMessage(message, transfer);
  await ready;
  return searchWorker === worker;
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
      collapsed: collapsed.slice(), selected, scroll: readScrollOffset() / rowHeight,
    };
    filterNodes ||= new Uint32Array(0);
    updateSortHeaders();
    return requestSearch();
  }
  cancelSearch();
  searchSettled = Promise.resolve();
  filterNodes = null;
  $("search-count").textContent = "";
  $("search-empty").hidden = true;
  $("tree").removeAttribute("aria-busy");
  if (savedTree) collapsed.set(savedTree.collapsed);
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

// Directories and extraction containers start closed unless they only group
// further virtual groups: the first screen shows psp / umd / psn / firmware.
function defaultCollapsed() {
  const flags = new Uint8Array(catalog.count);
  const { tree, parent, end } = catalog;
  for (let i = 0; i < catalog.count; i++) {
    if (tree[i] >= 0) flags[i] = 1;
    else if (catalog.isVirtual(i) && parent[i] >= 0) {
      let groups = false;
      for (let child = i + 1; child < end[i] && !groups; child = end[child]) groups = catalog.isVirtual(child);
      if (!groups) flags[i] = 1;
    }
  }
  return flags;
}

async function build(built) {
  cancelSearch();
  searchWorker?.terminate();
  searchWorker = null;
  catalog = built;
  hashStore = new HashStore({ count: catalog.slotCount, prefixes: catalog.prefixes, chunkUrl: hashUrl });
  downloadsEnabled = catalog.downloadsEnabled;
  availability.clear();
  hashFailures.clear();
  rows.clear();
  selected = -1;
  savedTree = null;
  filterNodes = null;
  visible = new Uint32Array(0);
  collapsed = defaultCollapsed();
  $("download-col").hidden = !downloadsEnabled;
  $("download-heading").hidden = !downloadsEnabled;
  $("tree").setAttribute("aria-colcount", downloadsEnabled ? "4" : "3");
  $("catalog-count").textContent = `${number.format(catalog.files)} files`;
  searchReady = initializeSearch().catch(error => { searchFailure(error); return false; });
}

function select(node, scroll = true, updateURL = true) {
  if (node < 0 || !visible.includes(node)) return;
  const previous = selected >= 0 ? rows.get(selected)?.row : undefined;
  previous?.classList.remove("selected");
  previous?.setAttribute("aria-selected", "false");
  selected = node;
  const row = rows.get(node)?.row;
  row?.classList.add("selected");
  row?.setAttribute("aria-selected", "true");
  const extraction = catalog.extraction(node);
  $("tree").setAttribute("aria-activedescendant", `node-${node}`);
  $("selected-path").textContent = catalog.path(node) || label(node);
  $("selected-detail").textContent = `${number.format(catalog.size[node])} bytes${extraction?.name ? ` · ${extraction.name}` : ""}`;
  $("open-selected").hidden = !filterNodes;
  $("copy-selected").hidden = catalog.slot[node] < 0;
  $("selected-error").hidden = !extraction?.error;
  $("selected-error-message").textContent = extraction?.error ? `error: ${extraction.error}` : "";
  $("notice").textContent = "";
  if (scroll || extraction?.error) {
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
  for (let parent = catalog.parent[node]; parent >= 0; parent = catalog.parent[parent]) collapsed[parent] = 0;
  render();
  select(node);
  setScrollOffset(Math.max(0, (visible.indexOf(node) - 2) * rowHeight));
  if (focus) $("tree").focus({ preventScroll: true });
}

function toggle(node) {
  if (filterNodes || !expandable(node)) return;
  collapsed[node] ^= 1;
  render();
  select(node);
  $("tree").focus({ preventScroll: true });
}

// Visible rows in preorder: a collapsed row skips its whole subtree.
function walkVisible() {
  const { end } = catalog;
  let list = new Uint32Array(1 << 12), length = 0;
  for (let node = 0; node < catalog.count;) {
    if (length === list.length) { const next = new Uint32Array(list.length * 2); next.set(list); list = next; }
    list[length++] = node;
    node = collapsed[node] ? end[node] : node + 1;
  }
  return list.subarray(0, length);
}

function render(offset = readScrollOffset()) {
  visible = filterNodes || walkVisible();
  windowVersion++;
  $("tree").setAttribute("aria-rowcount", visible.length + 1);
  setScrollOffset(offset);
}

function createRow(node) {
    const folder = expandable(node);
    const extraction = catalog.extraction(node);
    const container = extraction !== null;
    const attrs = catalog.attrsOf(node) || {};
    const virtual = catalog.isVirtual(node);
    const path = catalog.path(node), nodeName = catalog.nameOf(node);
    const depth = catalog.depth(node);
    const parts = { depth, gamePrefix: attrs.gamePrefix || null };
    const row = element("tr", `node ${container ? "file container" : folder ? "folder" : "file"}${virtual && !container ? " virtual" : ""}`);
    parts.row = row;
    if (extraction?.error) row.classList.add("extraction-failed");
    row.id = `node-${node}`;
    row.dataset.path = path;
    row.dataset.node = node;
    row.setAttribute("aria-level", depth + 1);
    row.setAttribute("aria-selected", "false");
    if (folder) row.setAttribute("aria-expanded", String(!collapsed[node]));
    const nameCell = element("td", "name-cell");
    nameCell.style.setProperty("--depth", depth);
    const content = element("div", "name-content");
    if (folder) {
      const disclosure = element("button", "toggle", collapsed[node] ? "▸" : "▾");
      disclosure.tabIndex = -1;
      disclosure.setAttribute("aria-label", `${collapsed[node] ? "Expand" : "Collapse"} ${nodeName}`);
      disclosure.onclick = event => { event.stopPropagation(); toggle(node); };
      parts.disclosure = disclosure;
      content.append(disclosure);
    } else content.append(element("span", "file-mark", "·"));
    const name = element("span", "name", label(node));
    parts.name = name;
    if (parts.gamePrefix) {
      parts.path = element("span", "");
      parts.prefix = element("span", "game-identity", parts.gamePrefix);
      parts.title = element("span", "", label(node).slice(parts.gamePrefix.length));
      name.replaceChildren(parts.path, parts.prefix, parts.title);
    }
    name.title = extraction?.error ? `error: ${extraction.error}` : container ? `${path} — extracted with ${extraction.name}` : virtual ? `${path || label(node)} — catalog grouping, not a filesystem directory` : path;
    content.append(name);
    if (attrs.coverage) content.append(coverageChip(attrs.coverage));
    for (const { source, field, className, valid, href } of REFERENCE_SOURCES) {
      const value = attrs[field];
      const matches = value == null ? [] : Array.isArray(value) ? value : [value];
      for (const [index, match] of matches.entries()) {
        if (!valid(match.id)) continue;
        const label = matches.length === 1 ? source : `${source} #${source === "SerialStation" ? index + 1 : match.id}`;
        const link = element("a", className);
        link.append(element("span", "reference-label", `${label} `));
        const icon = element("span", "reference-icon", "↗");
        icon.setAttribute("aria-hidden", "true");
        link.append(icon);
        link.href = href(match.id);
        link.title = `${label}: ${match.name}`;
        link.setAttribute("aria-label", link.title);
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.onclick = event => event.stopPropagation();
        content.append(link);
      }
    }
    if (extraction?.error) {
      const error = element("span", "extraction-error");
      const icon = element("span", "error-icon", "!");
      icon.setAttribute("aria-hidden", "true");
      parts.error = element("span", "error-message", `error: ${extraction.error}`);
      parts.errorText = extraction.error;
      parts.error.id = `node-${node}-error`;
      row.setAttribute("aria-describedby", parts.error.id);
      error.append(icon, parts.error);
      content.append(error);
    } else if (container && catalog.errorCount(node)) {
      const errors = catalog.errorCount(node);
      const contained = element("span", "extraction-error contained");
      const icon = element("span", "error-icon", "!");
      icon.setAttribute("aria-hidden", "true");
      contained.append(icon);
      contained.title = `Contains ${errors} extraction error${errors === 1 ? "" : "s"}`;
      contained.setAttribute("aria-label", contained.title);
      contained.setAttribute("role", "img");
      content.append(contained);
    }
    if (container && extraction.kind) {
      const tags = element("span", "extraction-tags");
      const kind = extraction.kind.toUpperCase();
      tags.append(element("span", "extraction-tag", kind));
      if (extraction.version) {
        const version = element("span", "extraction-tag", `v${extraction.version}`);
        if (extraction.stale) {
          const { version: recorded, latest_version } = extraction.stale;
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
    const displayedSize = catalog.size[node];
    const summed = !catalog.isFile(node);
    const bytes = element("td", "size", `${summed ? "Σ " : ""}${formatSize(displayedSize)}`);
    bytes.title = `${number.format(displayedSize)} bytes${summed ? " — sum of contained file sizes, excluding their extracted contents; includes filtered files" : ""}`;
    const hashCell = element("td", "hash");
    if (catalog.slot[node] >= 0) {
      const copy = element("button", "", catalog.prefixHex(node, 12));
      parts.hash = copy;
      copy.tabIndex = -1;
      const describe = parts.describe = hash => { copy.title = `${hash}\nClick to copy full file SHA-256`; };
      describe(hashOf(node) || `${catalog.prefixHex(node, 16)}…`);
      // Resolve the full digest as soon as the pointer gets near, so a click copies instantly.
      const prefetch = () => { const known = hashOf(node); if (known) describe(known); else fullHash(node).catch(() => {}); };
      copy.addEventListener("pointerenter", prefetch);
      copy.addEventListener("focus", prefetch);
      copy.onclick = event => {
        event.stopPropagation(); select(node, false);
        return copyNodeHash(node);
      };
      hashCell.append(copy);
    } else hashCell.textContent = "—";
    row.append(nameCell, bytes, hashCell);
    if (downloadsEnabled) {
      parts.download = element("td", "download-cell", folder ? "" : "Checking…");
      row.append(parts.download);
    }
    row.onclick = () => { select(node, false); $("tree").focus({ preventScroll: true }); };
    row.ondblclick = event => {
      if (event.target.closest("button, a")) return;
      if (filterNodes) jump(node);
      else if (folder) toggle(node);
    };
    rows.set(node, parts);
    return parts;
}

function restore(focus = true) {
  let path;
  try { path = location.hash.slice(1).split("/").map(decodeURIComponent).join("/"); } catch { path = ""; }
  const node = catalog.find(path);
  jump(node >= 0 ? node : 0, focus);
}

function coveragePercent(present, total) {
  return total ? `${Math.round(present / total * 1000) / 10}%` : "—";
}

// One right-aligned chip per reference population, on the `umd`/`psn` group that
// population maps onto: source, share and a filled bar, linking to that source's
// own population listing. Subgroups carry nothing.
function coverageChip({ present, total, noun, source, snapshot, href }) {
  const chip = element(href ? "a" : "span", "coverage-chip");
  const bar = element("span", "coverage-bar");
  bar.style.setProperty("--filled", total ? `${Math.min(100, present / total * 100)}%` : "0%");
  bar.setAttribute("aria-hidden", "true");
  chip.append(element("span", "coverage-source", source), bar,
    element("span", "coverage-figure", coveragePercent(present, total)),
    element("span", "coverage-count", `· ${number.format(present)}/${number.format(total)}`));
  chip.title = `${number.format(present)} of ${number.format(total)} ${noun} listed by ${source}${snapshot ? ` (${snapshot})` : ""} are held`;
  if (href) {
    chip.href = href;
    chip.title += ` — open ${source}`;
    chip.target = "_blank";
    chip.rel = "noopener noreferrer";
    chip.onclick = event => event.stopPropagation();
  }
  chip.setAttribute("aria-label", chip.title);
  return chip;
}

$("tree-search").value = new URLSearchParams(location.search).get("q") || "";
$("clear-search").hidden = !$("tree-search").value;
$("tree-search").addEventListener("input", applySearch);
$("clear-search").onclick = clearSearch;
$("open-selected").onclick = () => { if (selected >= 0 && filterNodes) jump(selected); };
$("copy-selected").onclick = () => { if (selected >= 0 && catalog.slot[selected] >= 0) return copyNodeHash(selected); };
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
  if (node < 0) { select(visible[0]); return; }
  if (filterNodes && ["h", "l", "ArrowLeft", "ArrowRight", "Enter"].includes(key)) return;
  if (key === "h" || key === "ArrowLeft") {
    if (expandable(node) && !collapsed[node] && catalog.hasChildren(node)) toggle(node);
    else select(catalog.parent[node] >= 0 ? catalog.parent[node] : node);
  } else if (["l", "ArrowRight", "Enter"].includes(key)) {
    if (expandable(node)) {
      if (collapsed[node]) toggle(node);
      else select(catalog.children(node).find(child => visible.includes(child)) ?? node);
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
  const reader = body.getReader(), parts = [];
  let byteCount = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
    byteCount += value.length;
  }
  const bytes = new Uint8Array(byteCount);
  for (let offset = 0, i = 0; i < parts.length; offset += parts[i++].length) bytes.set(parts[i], offset);
  parts.length = 0;
  // Let the "Preparing catalog…" status paint before the (synchronous) decode.
  await new Promise(resolve => globalThis.requestAnimationFrame ? requestAnimationFrame(() => setTimeout(resolve)) : setTimeout(resolve));
  return buildCatalog(parseContainer(bytes));
}

loadCatalog().then(async built => {
  await build(built);
  $("message").hidden = true;
  $("browser").hidden = false;
  restore(document.activeElement !== $("tree-search") && document.activeElement !== $("clear-search"));
  catalogReady = true;
  if ($("tree-search").value) applySearch();
}).catch(error => {
  catalog = null;
  catalogReady = false;
  $("browser").hidden = true;
  $("message").hidden = false;
  $("catalog-progress").hidden = true;
  $("download-detail").hidden = true;
  $("loading-status").textContent = `Could not load the catalog (${error.message}). Reload to try again.`;
});
