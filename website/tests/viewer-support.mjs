// Shared harness for the viewer tests that run without a browser: fixtures are
// encoded by the real Python encoder (pspdb.wire), then decoded by catalog.js and
// driven through app.js and the search worker inside a stubbed DOM.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {createRequire} from 'node:module';
import {Worker as ThreadWorker} from 'node:worker_threads';

const web = new URL('../pspdb/web/', import.meta.url);
const websiteRoot = new URL('..', import.meta.url).pathname;
const require = createRequire(import.meta.url);
export const catalogModule = require(new URL('catalog.js', web).pathname);
export const sources = {
  app: fs.readFileSync(new URL('app.js', web), 'utf8'),
  catalog: fs.readFileSync(new URL('catalog.js', web), 'utf8'),
  worker: fs.readFileSync(new URL('search-worker.js', web), 'utf8'),
};

// Encode a catalog data dict into `{bytes, chunks, generation}` with the Python encoder.
// `unsorted` keeps the inventory's own child order (the encoder normally sorts), to prove the viewer orders rows itself.
export function encodeFixture(data, {unsorted = false} = {}) {
  const directory = fs.mkdtempSync(path.join(process.env.PSPDB_TEST_TMP || os.tmpdir(), 'pspdb-wire-'));
  try {
    fs.writeFileSync(path.join(directory, 'data.json'), JSON.stringify(data));
    const python = process.env.PSPDB_PYTHON || 'python3';
    const command = unsorted
      ? ['-c', 'import sys, pspdb.wire as w; w.ordered = lambda node: node; w.main(sys.argv[1:])']
      : ['-m', 'pspdb.wire'];
    const run = spawnSync(python, [...command, path.join(directory, 'data.json'), directory], {
      cwd: websiteRoot, env: {...process.env, PYTHONPATH: websiteRoot}, encoding: 'utf8',
    });
    if (run.status !== 0) throw new Error(`pspdb.wire failed: ${run.stderr}`);
    const chunks = [];
    for (let index = 0; fs.existsSync(path.join(directory, 'hashes', `${index}.bin`)); index++)
      chunks.push(new Uint8Array(fs.readFileSync(path.join(directory, 'hashes', `${index}.bin`))));
    return {bytes: new Uint8Array(fs.readFileSync(path.join(directory, 'catalog.bin'))), chunks, generation: run.stdout.trim()};
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
}

export const decodeFixture = encoded => catalogModule.buildCatalog(catalogModule.parseContainer(encoded.bytes));

// A chunk server shaped like the live API (`api/hashes/<generation>/<n>`): 409 for
// another generation, 404 past the last chunk; `fail` forces one status. Counts requests.
export function chunkServer(encoded, {fail = 0} = {}) {
  const requests = [];
  const respond = async url => {
    requests.push(String(url));
    const match = /\/hashes\/([0-9a-f]+)\/(\d+)$/.exec(String(url));
    if (fail) return {ok: false, status: fail};
    if (!match) return {ok: false, status: 404};
    if (match[1] !== encoded.generation) return {ok: false, status: 409};
    const chunk = encoded.chunks[Number(match[2])];
    if (!chunk) return {ok: false, status: 404};
    return {ok: true, status: 200, arrayBuffer: async () => chunk.buffer.slice(chunk.byteOffset, chunk.byteOffset + chunk.byteLength)};
  };
  return {requests, respond};
}

const workerPrelude = (chunks, status) => `
  const {parentPort, workerData} = require('node:worker_threads');
  global.self = global;
  global.postMessage = (data, transfer) => parentPort.postMessage(data, transfer);
  global.importScripts = () => { self.PspdbCatalog = require(workerData.catalogPath); };
  global.fetch = async url => {
    const found = /\\/(\\d+)$/.exec(String(url));
    const chunk = found && workerData.chunks[Number(found[1])];
    if (workerData.status) return {ok: false, status: workerData.status};
    if (!chunk) return {ok: false, status: 404};
    return {ok: true, status: 200, arrayBuffer: async () => chunk.buffer.slice(chunk.byteOffset, chunk.byteOffset + chunk.byteLength)};
  };
  parentPort.on('message', data => self.onmessage({data}));
`;

// A browser-less viewer: app.js running in a vm with a stub DOM. `state` is
// mutable so each build can supply its own digest chunks.
export function createViewer({host = null, tree = null, computed = '21px', catalogUrl = 'api/catalog'} = {}) {
  const state = {chunks: [], status: 0, server: null};
  class CatalogWorker {
    constructor() {
      this.thread = new ThreadWorker(workerPrelude() + sources.worker, {eval: true,
        workerData: {chunks: state.chunks, status: state.status, catalogPath: new URL('catalog.js', web).pathname}});
      this.thread.on('message', data => this.onmessage?.({data}));
      this.thread.on('error', error => this.onerror?.({message: error.message, preventDefault() {}}));
    }
    postMessage(data, transfer) { this.thread.postMessage(data, transfer); }
    terminate() { this.thread.terminate(); }
  }
  const el = {addEventListener() {}, setAttribute() {}, removeAttribute() {}};
  const elements = new Map();
  const context = vm.createContext({
    document: {documentElement: {dataset: {catalog: catalogUrl, hashes: 'api/hashes/{generation}/{chunk}'}},
      getElementById: id => id === 'table-scroll' && host ? host : id === 'tree' && tree ? tree : (elements.get(id) ?? el),
      addEventListener() {}},
    window: {addEventListener() {}},
    ResizeObserver: class { observe() {} },
    getComputedStyle: () => ({getPropertyValue: () => computed}),
    fetch: url => state.server ? state.server.respond(url) : new Promise(() => {}),
    Worker: CatalogWorker, setTimeout, clearTimeout, URLSearchParams, URL,
    TextDecoder, TransformStream, DecompressionStream, Response, performance, AbortSignal,
    requestAnimationFrame: callback => setTimeout(callback, 0),
    location: {href: 'http://localhost/', search: '', hash: ''},
    history: {replaceState() {}},
  });
  vm.runInContext(sources.catalog, context);
  vm.runInContext(sources.app, context);
  let queryVersion = 1000;
  const viewer = {
    context, state, elements,
    run: code => vm.runInContext(code, context),
    // Build a fixture into the viewer; returns the encoded container.
    async build(data, options = {}) {
      const encoded = options.encoded ?? encodeFixture(data, options);
      state.chunks = encoded.chunks;
      state.status = options.status ?? 0;
      state.server = chunkServer(encoded);
      context.catalogBuilt = catalogModule.buildCatalog(catalogModule.parseContainer(encoded.bytes));
      await vm.runInContext('build(catalogBuilt)', context);
      return encoded;
    },
    get catalog() { return vm.runInContext('catalog', context); },
    // Run a worker query; resolves with the raw message so failures are observable.
    async query(text, sort = null, direction = 1) {
      assert.equal(await vm.runInContext('searchReady', context), true);
      const worker = vm.runInContext('searchWorker', context);
      const handler = worker.onmessage, version = ++queryVersion;
      return new Promise((resolve, reject) => {
        worker.onmessage = ({data}) => {
          if (data.type === 'error') reject(new Error(data.message));
          else if (data.version === version && data.type !== 'ready') resolve(data);
          else handler({data});
        };
        worker.postMessage({type: 'search', version, terms: text.toLowerCase().split(/\s+/).filter(Boolean), sort, direction});
      }).finally(() => { worker.onmessage = handler; });
    },
    async search(text, sort = null, direction = 1) {
      const message = await viewer.query(text, sort, direction);
      assert.equal(message.type, 'results', `search ${text}: ${message.type} ${message.message ?? ''}`);
      return Array.from(message.ids);
    },
    stop() { vm.runInContext('searchWorker?.terminate()', context); },
  };
  return viewer;
}

// Occurrence helpers for assertions.
export const nodeAt = (catalog, pathText) => {
  const node = catalog.find(pathText);
  assert.ok(node >= 0, `no node at ${pathText}`);
  return node;
};
export const childNames = (catalog, node) => catalog.children(node).map(child => catalog.nameOf(child));
