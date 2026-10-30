// The typed-array occurrence tree must equal the object tree the viewer used to
// build, row by row. Always runs on the checked-in fixture; set
//   PSPDB_ORACLE_DATA=data.json PSPDB_ORACLE_CONTAINER=dir   (dir: catalog.bin + hashes/<n>.bin)
// to compare a full catalog (needs `node --max-old-space-size=8192`).
import fs from 'node:fs';
import {catalogModule, decodeFixture, encodeFixture} from './viewer-support.mjs';
import {assertMatchesReference, digestTable} from './reference-tree.mjs';

const small = JSON.parse(fs.readFileSync(new URL('./fixtures/catalog-small.json', import.meta.url), 'utf8'));
const encoded = encodeFixture(small);
const rows = assertMatchesReference(decodeFixture(encoded), small, digestTable(encoded));
console.log(`PASS: fixture catalog matches the reference tree (${rows} rows).`);

if (process.env.PSPDB_ORACLE_DATA) {
  const directory = process.env.PSPDB_ORACLE_CONTAINER;
  const chunks = [];
  for (let n = 0; fs.existsSync(`${directory}/hashes/${n}.bin`); n++) chunks.push(new Uint8Array(fs.readFileSync(`${directory}/hashes/${n}.bin`)));
  const full = {bytes: new Uint8Array(fs.readFileSync(`${directory}/catalog.bin`)), chunks};
  const data = JSON.parse(fs.readFileSync(process.env.PSPDB_ORACLE_DATA, 'utf8'));
  const started = performance.now();
  const count = assertMatchesReference(catalogModule.buildCatalog(catalogModule.parseContainer(full.bytes)), data, digestTable(full));
  console.log(`PASS: full catalog matches the reference tree (${count.toLocaleString('en-US')} rows, ${((performance.now() - started) / 1000).toFixed(1)} s).`);
}
