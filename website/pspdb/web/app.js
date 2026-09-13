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
const nodes = new Map(), collapsed = new Set(), rowElements = new Map();
const disclosures = new Map();
let root, selected, visible = [];
let filterNodes = null, searchTerms = [], savedTree = null;
let searchSort = null, sortDirection = 1;
const nameOrder = new Intl.Collator("en", { numeric: true, sensitivity: "base" });
const highlightCache = new WeakMap();
const rowHeight = 21, overscan = 20;
let windowKey = "", windowVersion = 0, scrollFrame = 0;
let downloadsEnabled = false, checkingDownloads = false;
const availability = new Map();

async function refreshDownloads() {
  if (!downloadsEnabled) return;
  const mounted = [...$("entries").querySelectorAll("tr.node")]
    .map(row => nodes.get(row.dataset.path)).filter(node => node?.type === "file" && node.hash);
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
    const response = await fetch(`api/availability?${query}`);
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

function renderWindow() {
  const host = $("table-scroll");
  const start = Math.min(visible.length, Math.max(0, Math.floor(host.scrollTop / rowHeight) - overscan));
  const end = Math.min(visible.length, start + Math.ceil(host.clientHeight / rowHeight) + overscan * 2);
  const key = `${windowVersion}:${start}:${end}`;
  if (key === windowKey) return;
  windowKey = key;
  const fragment = document.createDocumentFragment();
  function spacer(height) {
    if (!height) return;
    const row = element("tr", "tree-spacer");
    row.setAttribute("aria-hidden", "true");
    const cell = element("td"); cell.colSpan = downloadsEnabled ? 4 : 3;
    cell.style.height = `${height}px`;
    row.append(cell); fragment.append(row);
  }
  spacer(start * rowHeight);
  for (let index = start; index < end; index++) {
    const node = visible[index], row = rowElements.get(node.path);
    if (node.gamePrefix) {
      highlight(node.pathElement, filterNodes ? node.displayPath.slice(0, -label(node).length) : "");
      highlight(node.prefixElement, node.gamePrefix);
      highlight(node.titleElement, label(node).slice(node.gamePrefix.length));
    } else highlight(node.nameElement, filterNodes ? node.displayPath : label(node));
    row.setAttribute("aria-level", filterNodes ? 1 : node.depth + 1);
    if (node.note) highlight(node.noteElement, node.note);
    if (node.hashElement) highlight(node.hashElement, node.hash.slice(0, 12));
    row.setAttribute("aria-rowindex", index + 2);
    fragment.append(row);
  }
  spacer((visible.length - end) * rowHeight);
  $("entries").replaceChildren(fragment);
  refreshDownloads();
}

$("table-scroll").addEventListener("scroll", () => {
  if (!scrollFrame) scrollFrame = requestAnimationFrame(() => { scrollFrame = 0; renderWindow(); });
});
new ResizeObserver(() => { if (root && rowElements.size) renderWindow(); }).observe($("table-scroll"));

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

function compareSearchResults(a, b) {
  const order = searchSort === "size" ? a.size - b.size
    : searchSort === "hash" ? (a.hash || "").localeCompare(b.hash || "")
    : nameOrder.compare(label(a), label(b));
  return order * sortDirection || nameOrder.compare(a.path, b.path) || a.path.localeCompare(b.path);
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
  $("table-scroll").scrollTop = 0;
  updateSortHeaders();
  render();
  select(selected, false, false);
}

function applySearch() {
  const query = $("tree-search").value.trim();
  searchTerms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (query && !savedTree) savedTree = {
    collapsed: new Set(collapsed), selected, scroll: $("table-scroll").scrollTop,
  };
  if (query) {
    filterNodes = new Set();
    let files = 0;
    for (const node of nodes.values()) {
      if (node.type !== "file") continue;
      if (!searchTerms.every(term => node.searchText.includes(term))) continue;
      files++;
      filterNodes.add(node);
    }
    $("search-count").textContent = `${number.format(files)} matching files`;
  } else {
    filterNodes = null;
    $("search-count").textContent = "";
    if (savedTree) {
      collapsed.clear();
      for (const path of savedTree.collapsed) collapsed.add(path);
    }
  }
  updateSortHeaders();
  $("tree").classList.toggle("search-results", Boolean(query));
  $("clear-search").hidden = !$("tree-search").value;
  const empty = query && !filterNodes.size;
  $("search-empty").hidden = !empty;
  if (empty) {
    $("search-empty").textContent = `No matches for “${query}”`;
    const clear = element("button", "", "Clear filter");
    clear.onclick = clearSearch;
    $("search-empty").append(clear);
  }
  $("table-scroll").scrollTop = 0;
  render();
  if (!query && savedTree) {
    select(savedTree.selected, false);
    $("table-scroll").scrollTop = savedTree.scroll;
    renderWindow();
    savedTree = null;
  } else if (visible.length) {
    select(visible.includes(selected) ? selected : visible[0], false, false);
  } else {
    rowElements.get(selected?.path)?.classList.remove("selected");
    rowElements.get(selected?.path)?.setAttribute("aria-selected", "false");
    $("tree").removeAttribute("aria-activedescendant");
    $("position").textContent = "0 rows";
  }
}

function clearSearch() {
  $("tree-search").value = "";
  applySearch();
  $("tree").focus({ preventScroll: true });
}

function element(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}

function add(parent, name, data = {}) {
  const node = { name, type: "directory", children: [], parent, depth: parent ? parent.depth + 1 : 0, ...data };
  node.path = parent?.path ? `${parent.path}/${name}` : name;
  node.id = `node-${nodes.size}`;
  nodes.set(node.path, node);
  if (parent) parent.children.push(node);
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

function addInventory(parent, entries, extractions = {}, ancestors = new Set(), nameRule = null) {
  const directories = new Map([["", parent]]);
  for (const entry of entries) {
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
      const node = add(directory, name, { type: "file", size: entry.size_bytes, hash: entry.sha256, redump: entry.redump || [] });
      attachExtraction(node, extractions, ancestors, entry.extraction);
    }
  }
}

function attachExtraction(node, extractions, ancestors = new Set(), contextual = null, source = null) {
  const extraction = contextual || (source === null ? extractions[node.hash] : source[node.hash]);
  if (extraction === null) throw new Error(`Ambiguous non-root extraction kinds: ${node.hash}`);
  if (!extraction || (contextual && extraction.sha256 !== node.hash) || extraction.size_bytes !== node.size || ancestors.has(extraction)) return;
  node.extraction = extraction.extractor.name;
  addInventory(node, extraction.entries, extractions, new Set([...ancestors, extraction]), extraction.name_rule);
}

function addGroup(parent, name, data = {}) {
  return add(parent, name, { ...data, virtual: true });
}

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

function build(data) {
  nodes.clear();
  downloadsEnabled = data.downloads_enabled === true;
  availability.clear();
  $("download-col").hidden = !downloadsEnabled;
  $("download-heading").hidden = !downloadsEnabled;
  $("tree").setAttribute("aria-colcount", downloadsEnabled ? "4" : "3");
  root = { name: "", path: "", depth: -1, children: [] };
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
      if (kind === "iso" || kind === "pkg") continue;
      extractions[hash] = hash in extractions ? null : tree;
    }
  }
  for (const iso of isos) {
    const category = mediaGroup(iso.metadata.media_code);
    const id = (iso.metadata.disc_id || iso.metadata.identifier).trim().replace(/^([A-Z]{4})-?([0-9]{5})$/, "$1-$2");
    const identity = [id, iso.metadata.disc_version].filter(Boolean).join("/");
    const displayName = iso.metadata.media_code === "V"
      ? iso.metadata.title?.trim() || identity
      : [identity, iso.metadata.title?.trim()].filter(Boolean).join(" ");
    const node = add(category, `${iso.sha256}.iso`, {
      type: "file",
      redump: iso.redump || [], umdatabase: iso.umdatabase || [], hash: iso.sha256, size: iso.size_bytes,
      displayName,
      gamePrefix: iso.metadata.media_code === "G" ? identity : null,
    });
    attachExtraction(node, extractions, new Set(), null, data.trees.iso || {});
  }
  const packages = data.records.pkg || [];
  if (packages.length) {
    const psn = addGroup(root, "psn");
    const labels = packageLabels(packages);
    for (const pkg of packages) {
      const metadata = pkg.metadata || {};
      const node = add(psn, `${pkg.sha256}.pkg`, {
        type: "file", hash: pkg.sha256, size: pkg.size_bytes,
        displayName: labels.get(pkg.sha256),
        gamePrefix: packageSerial(metadata) || null,
        searchMetadata: metadata.content_id || "",
      });
      attachExtraction(node, extractions, new Set(), null, data.trees.pkg || {});
    }
  }
  function summarize(node) {
    node.children.sort((a, b) => (a.type === b.type ? 0 : a.type === "directory" ? -1 : 1)
      || (label(a) < label(b) ? -1 : label(a) > label(b) ? 1 : 0));
    for (const child of node.children) summarize(child);
    node.files = (node.type === "file" ? 1 : 0) + node.children.reduce((sum, child) => sum + child.files, 0);
    if (node.type === "directory" || node === root)
      node.size = node.children.reduce((sum, child) => sum + child.size, 0);
  }
  summarize(root);
  for (const node of nodes.values()) {
    node.displayPath = node.parent && node.parent !== root ? `${node.parent.displayPath}/${label(node)}` : label(node);
    node.searchText = `${node.parent?.searchText || ""} ${node.name} ${node.displayName || ""} ${node.note || ""} ${node.searchMetadata || ""} ${node.hash || ""}`.toLowerCase();
  }
  $("catalog-count").textContent = `${isos.length} UMD images · ${packages.length} PSN packages · ${number.format(root.files)} files`;
}

function url(node) { return "#" + node.path.split("/").map(encodeURIComponent).join("/"); }
function label(node) { return node.displayName || node.name; }

function select(node, scroll = true, updateURL = true) {
  if (!node || !visible.includes(node)) return;
  const previous = selected && rowElements.get(selected.path);
  previous?.classList.remove("selected");
  previous?.setAttribute("aria-selected", "false");
  selected = node;
  const row = rowElements.get(node.path);
  row.classList.add("selected");
  row.setAttribute("aria-selected", "true");
  $("tree").setAttribute("aria-activedescendant", node.id);
  $("selected-path").textContent = node.path;
  $("position").textContent = `${visible.indexOf(node) + 1} / ${number.format(visible.length)} rows`;
  $("notice").textContent = "";
  if (scroll) {
    // Scroll only vertically, preserving the user's horizontal column position.
    const host = $("table-scroll"), top = visible.indexOf(node) * rowHeight;
    const height = host.clientHeight - $("tree").tHead.offsetHeight;
    if (top < host.scrollTop) host.scrollTop = top;
    else if (top + rowHeight > host.scrollTop + height) host.scrollTop = top + rowHeight - height;
    renderWindow();
  }
  if (updateURL) history.replaceState(null, "", url(node));
}

function jump(node) {
  if (savedTree) clearSearch();
  for (let parent = node.parent; parent; parent = parent.parent) collapsed.delete(parent.path);
  render();
  select(node);
  const host = $("table-scroll");
  host.scrollTop = Math.max(0, (visible.indexOf(node) - 2) * rowHeight);
  renderWindow();
  $("tree").focus({ preventScroll: true });
}

function toggle(node) {
  if (filterNodes || !expandable(node)) return;
  if (collapsed.has(node.path)) {
    collapsed.delete(node.path);
  } else collapsed.add(node.path);
  render();
  select(node);
  $("tree").focus({ preventScroll: true });
}

function render() {
  const previous = visible;
  visible = [];
  function walk(node) {
    if (!filterNodes || filterNodes.has(node)) visible.push(node);
    if (filterNodes || !collapsed.has(node.path)) for (const child of node.children) walk(child);
  }
  for (const child of root.children) walk(child);
  if (filterNodes && searchSort) visible.sort(compareSearchResults);
  windowVersion++;
  if (rowElements.size) {
    // Keep row identity and handlers intact, mounting only the viewport window.
    const showing = new Set(visible);
    for (const node of previous) {
      if (!showing.has(node)) rowElements.get(node.path).hidden = true;
    }
    for (const node of visible) {
      const row = rowElements.get(node.path);
      if (row.hidden) row.hidden = false;
    }
    for (const [node, button] of disclosures) {
      const expanded = !collapsed.has(node.path);
      const row = rowElements.get(node.path);
      if (row.getAttribute("aria-expanded") !== String(expanded)) {
        row.setAttribute("aria-expanded", String(expanded));
        button.textContent = expanded ? "▾" : "▸";
        button.setAttribute("aria-label", `${expanded ? "Collapse" : "Expand"} ${node.name}`);
      }
    }
    $("tree").setAttribute("aria-rowcount", visible.length + 1);
    const host = $("table-scroll");
    host.scrollTop = Math.min(host.scrollTop, Math.max(0, visible.length * rowHeight - host.clientHeight + $("tree").tHead.offsetHeight));
    renderWindow();
    return;
  }
  const showing = new Set(visible);
  for (const node of nodes.values()) {
    const folder = expandable(node);
    const container = Boolean(node.extraction);
    const row = element("tr", `node ${container ? "file container" : folder ? "folder" : "file"}${node.virtual && !container ? " virtual" : ""}`);
    row.hidden = !showing.has(node);
    row.id = node.id;
    row.dataset.path = node.path;
    row.setAttribute("aria-level", node.depth + 1);
    row.setAttribute("aria-selected", "false");
    if (folder) row.setAttribute("aria-expanded", String(!collapsed.has(node.path)));
    const nameCell = element("td", "name-cell");
    nameCell.style.setProperty("--depth", node.depth);
    const content = element("div", "name-content");
    if (folder) {
      const disclosure = element("button", "toggle", collapsed.has(node.path) ? "▸" : "▾");
      disclosure.tabIndex = -1;
      disclosure.setAttribute("aria-label", `${collapsed.has(node.path) ? "Expand" : "Collapse"} ${node.name}`);
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
    name.title = node.extraction ? `${node.path} — extracted with ${node.extraction}`  : node.virtual ? `${node.path} — catalog grouping, not a filesystem directory` : node.path;
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
    nameCell.append(content);
    const displayedSize = node.size;
    const summed = node.type === "directory";
    const bytes = element("td", "size", `${summed ? "Σ " : ""}${formatSize(displayedSize)}`);
    bytes.title = `${number.format(displayedSize)} bytes${summed ? " — sum of all descendant files, including filtered files" : ""}`;
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
    rowElements.set(node.path, row);
  }
  $("tree").setAttribute("aria-rowcount", visible.length + 1);
  renderWindow();
}

function restore() {
  let path;
  try { path = location.hash.slice(1).split("/").map(decodeURIComponent).join("/"); } catch { path = ""; }
  jump(nodes.get(path) || root.children[0]);
}

$("tree-search").addEventListener("input", applySearch);
$("clear-search").onclick = clearSearch;
for (const key of ["name", "size", "hash"]) $("sort-" + key).onclick = () => sortSearch(key);

document.addEventListener("keydown", event => {
  if (root && !event.ctrlKey && !event.metaKey && !event.altKey) {
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
  if (!root || event.ctrlKey || event.metaKey || event.altKey || /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName)) return;
  if (!visible.length) return;
  if (event.key === "Enter" && /^(BUTTON|A)$/.test(event.target.tagName)) return;
  const key = event.key;
  if (!["h", "j", "k", "l", "ArrowLeft", "ArrowDown", "ArrowUp", "ArrowRight", "Enter", "Home", "End"].includes(key)) return;
  event.preventDefault();
  const node = selected;
  if (filterNodes && ["h", "l", "ArrowLeft", "ArrowRight", "Enter"].includes(key)) return;
  if (key === "h" || key === "ArrowLeft") {
    if (expandable(node) && !collapsed.has(node.path) && node.children.length) toggle(node);
    else select(node.parent === root ? node : node.parent || node);
  } else if (["l", "ArrowRight", "Enter"].includes(key)) {
    if (expandable(node)) {
      if (collapsed.has(node.path)) toggle(node);
      else select(node.children.find(child => visible.includes(child)) || node);
    }
  } else {
    const index = visible.indexOf(node);
    const next = key === "Home" ? 0 : key === "End" ? visible.length - 1 : index + (["j", "ArrowDown"].includes(key) ? 1 : -1);
    select(visible[Math.max(0, Math.min(visible.length - 1, next))]);
  }
  $("tree").focus({ preventScroll: true });
});
window.addEventListener("hashchange", () => { if (root) restore(); });

fetch(document.documentElement.dataset.catalog).then(response => {
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}).then(data => {
  build(data);
  for (const node of nodes.values()) if (node.extraction) collapsed.add(node.path);
  $("message").hidden = true;
  $("browser").hidden = false;
  $("tree-search").disabled = false;
  restore();
}).catch(error => {
  root = null;
  $("browser").hidden = true;
  $("message").hidden = false;
  $("message").textContent = `Could not load the catalog (${error.message}). Reload to try again.`;
});
