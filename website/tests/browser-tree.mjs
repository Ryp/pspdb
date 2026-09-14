// With PSPDB served on :8000 and Chromium --remote-debugging-port=9333:
// node website/tests/browser-tree.mjs
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const pages=await (await fetch((process.env.PSPDB_DEBUG_URL || 'http://127.0.0.1:9333') + '/json')).json();
const ws=new WebSocket(pages.find(t=>t.type==='page').webSocketDebuggerUrl);
await new Promise(r=>ws.addEventListener('open',r,{once:true}));
let next=0;const pending=new Map();
ws.addEventListener('message',e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(m.error):p.resolve(m.result);}});
function cmd(method,params={}){return new Promise((resolve,reject)=>{const id=++next;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));});}
async function evaluate(expression){const r=await cmd('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));return r.result.value;}
await cmd('Page.enable');await cmd('Runtime.enable');
await cmd('Emulation.setDeviceMetricsOverride',{width:1440,height:940,deviceScaleFactor:1,mobile:false});
await cmd('Page.navigate',{url:process.env.PSPDB_SITE_URL || 'http://127.0.0.1:8000'});
for(let i=0;i<600;i++){if(await evaluate('!!document.querySelector("#browser:not([hidden]) tr.node")'))break;await new Promise(r=>setTimeout(r,50));}
const result=await evaluate(`(()=>{
 const check=(value,message)=>{if(!value)throw new Error(message)};
 check(document.querySelector('header').getBoundingClientRect().height<=48,'Compact header');
 check(!document.querySelector('header button:not(#clear-search), .brand-dot, .subtitle'),'Header decorations and bulk controls removed');
 check(document.querySelector('header .search-bar'),'Search lives in the header');
 check(visible.some(n=>n.extraction)&&visible.every(n=>!n.parent?.extraction),'Initially show categories and collapsed source files');
 check([...nodes.values()].filter(n=>n.type==='directory').every(n=>!collapsed.has(n.path)),'Ordinary folders expanded by default');
 check([...nodes.values()].filter(n=>n.extraction).every(n=>collapsed.has(n.path)),'Extracted files collapsed locally by default');
 for(const item of [...nodes.values()].filter(n=>n.displayName&&n.extraction)){
  jump(item);
  document.dispatchEvent(new KeyboardEvent('keydown',{key:'l',bubbles:true}));
  const descendants=[...nodes.values()].filter(n=>n.path.startsWith(item.path+'/'));
  check(item.children.every(n=>visible.includes(n)),'Opening source reveals contents');
  for(const nested of descendants.filter(n=>n.extraction)){
   check(collapsed.has(nested.path),'Opening parent keeps nested extracted files collapsed');
   check(nested.children.every(n=>!visible.includes(n)),'Nested extracted contents stay hidden');
  }
  const nestedFolder=descendants.find(n=>n.type==='directory'&&n.children.length);
  if(nestedFolder){
   toggle(nestedFolder);toggle(item);toggle(item);
   check(collapsed.has(nestedFolder.path)&&nestedFolder.children.every(n=>!visible.includes(n)),'Reopening preserves nested collapse choices');
  }
 }
 collapsed.clear();render();select(selected || visible[0]);
 check(formatSize(0)==='0 B'&&formatSize(1023)==='1,020 B','Rounded byte sizes');
 check(formatSize(1024)==='1 KiB'&&formatSize(1536)==='1.5 KiB','Binary size conversion');
 check(formatSize(1024**2)==='1 MiB'&&formatSize(1024**3)==='1 GiB','Larger units');
 check(formatSize(123.456*1024**2)==='123 MiB'&&formatSize(12.3456*1024**2)==='12.3 MiB','Three significant digits');
 const sizeNode=[...nodes.values()].find(n=>n.type==='file'&&n.size>1024);
 jump(sizeNode);
 check(rowElements.get(sizeNode.path).querySelector('.size').textContent===formatSize(sizeNode.size),'Rendered readable sizes');
 check(rowElements.get(sizeNode.path).querySelector('.size').title===number.format(sizeNode.size)+' bytes','Exact byte tooltip');
 const initial=visible.length;
 const branch=Array.from(nodes.values()).find(n=>n.depth>3 && n.children.some(c=>c.type==='directory'&&c.children.length>3));
 const nested=branch.children.find(c=>c.type==='directory'&&c.children.length>3);
 const leaf=nested.children[0];
 jump(nested);
 rowElements.get(nested.path).querySelector('.toggle').click();
 check(collapsed.has(nested.path),'Nested folder should collapse');
 check(!visible.includes(leaf),'Nested contents should hide');
 jump(branch); rowElements.get(branch.path).querySelector('.toggle').click();
 check(!visible.includes(nested),'Parent should hide nested folder');
 rowElements.get(branch.path).querySelector('.toggle').click();
 check(visible.includes(nested),'Parent should restore nested folder');
 check(!visible.includes(leaf),'Nested collapse state must survive parent toggle');
 jump(nested);
 check(rowElements.get(nested.path).getAttribute('aria-expanded')==='false','Disclosure aria state');
 select(nested);
 document.dispatchEvent(new KeyboardEvent('keydown',{key:'j',bubbles:true}));
 check(!rowElements.get(selected.path).hidden && selected!==leaf,'j must skip hidden descendants');
 for(const n of nodes.values())if(expandable(n))collapsed.add(n.path);render();select(visible[0]);
 check(visible.length===root.children.length && selected===visible[0],'Collapse all retains top-level categories');
 document.dispatchEvent(new KeyboardEvent('keydown',{key:'h',bubbles:true}));
 check(selected===visible[0],'Top-level boundary');
 jump(leaf);
 check(!rowElements.get(leaf.path).hidden,'Jump must reveal collapsed ancestors');
 check(document.getElementById('tree').getAttribute('aria-activedescendant')===leaf.id,'Active row');
 check(![...rowElements.values()].some(row=>row.querySelector('a:not(.download-link):not(.redump-link):not(.umdatabase-link)')),'No cross-tree links');
 for(const node of [...nodes.values()].filter(n=>(n.redump||[]).length)){
  jump(node);
  const links=[...rowElements.get(node.path).querySelectorAll('.redump-link')];
  check(links.length===(node.redump||[]).length,'Exact matches appear on ISO rows');
  links.forEach((link,i)=>{
   check(link.href==='http://redump.org/disc/'+node.redump[i].id+'/','Numeric Redump URL');
   check(link.target==='_blank'&&link.rel.includes('noopener'),'External link isolation');
   const before=selected;
   link.addEventListener('click',event=>event.preventDefault(),{once:true});
   link.click();
   check(selected===before,'Redump click does not select or toggle tree');
  });
 }
 for(const node of [...nodes.values()].filter(n=>(n.umdatabase||[]).length)){
  jump(node);
  const links=[...rowElements.get(node.path).querySelectorAll('.umdatabase-link')];
  check(links.length===(node.umdatabase||[]).length,'UMDatabase matches appear on ISO rows');
  links.forEach((link,i)=>{
   check(link.href==='https://umdatabase.net/view.php?id='+node.umdatabase[i].id,'UMDatabase entry URL');
   check(link.target==='_blank'&&link.rel.includes('noopener'),'UMDatabase external link isolation');
   const before=selected;
   link.addEventListener('click',event=>event.preventDefault(),{once:true});
   link.click();
   check(selected===before,'UMDatabase link does not toggle or select the ISO');
  });
 }
 check(!nodes.has('psp')&&!rowElements.has('psp'),'No redundant PSP root row');
 check(root.children.every(n=>n.depth===0),'Top-level indentation');

 collapsed.clear();render();select(selected || visible[0]);
 check(visible.length===initial,'Expand all restores every row');
 check(Array.from(rowElements.values()).every(r=>!r.hidden),'All expanded rows displayed');
 check(Number(document.getElementById('tree').getAttribute('aria-rowcount'))===visible.length+1,'Accessible row count');
 const search=document.getElementById('tree-search');
 const query=value=>{search.value=value;search.dispatchEvent(new Event('input',{bubbles:true}));};
 jump(nested); toggle(nested);
 const before={selected,collapsed:[...collapsed].sort().join('|'),scroll:document.getElementById('table-scroll').scrollTop};
 query('EBOOT.BIN');
 check(document.querySelector('header').getBoundingClientRect().height<=48,'Match count stays inline without growing the header');
 check(visible.some(n=>n.type==='file'&&n.name==='EBOOT.BIN'),'Find files in collapsed branches');
 check(visible.every(n=>n.type==='file'&&n.searchText.includes('eboot.bin')),'Flat results contain matching files without ancestor rows');
 const resultNode=visible[0], resultRow=rowElements.get(resultNode.path);
 check(resultNode.nameElement.textContent===resultNode.displayPath&&resultNode.displayPath.includes(label([...nodes.values()].find(n=>n.displayName&&resultNode.path.startsWith(n.path+'/')))),'One-line path uses readable ISO label');
 check(resultRow.getAttribute('aria-level')==='1','Flat result accessibility level');
 check(getComputedStyle(resultRow.querySelector('.name-cell')).paddingLeft==='12px','Flat results have no tree indentation');
 check(document.querySelectorAll('mark').length>0,'Highlight matches');
 query('BuRnOuT EBOOT');
 check(visible.some(n=>n.type==='file'),'Combined title and filename query');
 check(visible.filter(n=>n.type==='file').every(n=>n.searchText.includes('burnout')&&n.searchText.includes('eboot')),'AND matching across ancestor title and filename');
 const file=visible.find(n=>n.type==='file'); select(file);
 document.dispatchEvent(new KeyboardEvent('keydown',{key:'l',bubbles:true}));
 check(selected===file,'Flat results do not navigate to hidden tree nodes');
 query('BURNOUT');
 check(visible.filter(n=>n.type==='file').length>1,'Game match includes contents');
 const orderChecks={name:(a,b)=>new Intl.Collator('en',{numeric:true,sensitivity:'base'}).compare(label(a),label(b)),size:(a,b)=>a.size-b.size,hash:(a,b)=>(a.hash||'').localeCompare(b.hash||'')};
 const defaultPaths=visible.map(n=>n.path).join('|');
 check(['name','size','hash'].every(key=>!document.getElementById('sort-'+key).querySelector('span').textContent),'Default sorting has no icons');
 const matchingPaths=visible.map(n=>n.path).sort().join('|');
 for(const key of ['size','hash','name']) {
  const button=document.getElementById('sort-'+key);
  check(!button.disabled,'Search enables sorting');
  button.click();
  check(visible.every((n,i)=>!i||orderChecks[key](visible[i-1],n)<=0),'Ascending '+key+' order');
  check(document.getElementById('heading-'+key).getAttribute('aria-sort')==='ascending','Accessible ascending sort');
  button.click();
  check(visible.every((n,i)=>!i||orderChecks[key](visible[i-1],n)>=0),'Descending '+key+' order');
  check(document.getElementById('heading-'+key).getAttribute('aria-sort')==='descending','Accessible descending sort');
  check(visible.map(n=>n.path).sort().join('|')===matchingPaths,'Sorting preserves matching occurrences');
  button.click();
  check(visible.map(n=>n.path).join('|')===defaultPaths,'Third click restores default order');
  check(['name','size','hash'].every(key=>!document.getElementById('sort-'+key).querySelector('span').textContent),'Default order clears every sort icon');
  check(document.getElementById('heading-'+key).getAttribute('aria-sort')==='none','Accessible default sort');
 }
 check(selected===file,'Sorting preserves selection');
 query(file.hash);
 check(visible.includes(file),'Full hash search');
 query(file.hash.toUpperCase());
 check(visible.includes(file),'Case-insensitive hash search');
 query(file.hash.slice(0,12));
 check(visible.includes(file),'Short hash search');
 const folder=[...nodes.values()].find(n=>n.name==='SYSDIR'&&n.children.length);
 query('SYSDIR');
 check(folder.children.filter(n=>n.type==='file').every(n=>visible.includes(n))&&!visible.includes(folder),'Folder query lists contained files without a folder row');
 query('<img src=x onerror=alert(1)>');
 check(visible.length===0&&!document.getElementById('search-empty').hidden,'Empty state');
 check(!document.getElementById('search-empty').querySelector('img'),'Query rendered as text');
 document.dispatchEvent(new KeyboardEvent('keydown',{key:'j',bubbles:true}));
 search.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
 check(document.getElementById('sort-size').disabled,'Tree mode disables search sorting');
 check(selected===before.selected,'Clear restores selection');
 check(!document.getElementById('tree').classList.contains('search-results'),'Clear restores tree presentation');
 check(selected.nameElement.textContent===label(selected),'Clear restores short names');
 check([...collapsed].sort().join('|')===before.collapsed,'Clear restores expansion');
 check(document.getElementById('table-scroll').scrollTop===before.scroll,'Clear restores scroll');
 check(document.querySelectorAll('mark').length===0,'Clear removes highlights');
 document.dispatchEvent(new KeyboardEvent('keydown',{key:'/',bubbles:true}));
 check(document.activeElement===search,'Slash focuses search');
 query('eboot');
 search.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
 check(document.activeElement===document.getElementById('tree'),'Enter returns to navigation');
 document.getElementById('clear-search').click();
 check(originals.size===rowElements.size&&[...originals].every(([p,r])=>rowElements.get(p)===r),'Search preserves row identity');
 for(const target of [file,[...nodes.values()].find(n=>n.extraction&&n.parent!==root)]) {
  for(const n of nodes.values())if(expandable(n))collapsed.add(n.path);
  render();select(visible[0]);
  const beforeJump=new Set(collapsed);
  query(target.hash);
  document.getElementById('sort-size').click();
  target.hashElement.dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));
  check(filterNodes!==null,'Double-clicking the hash button preserves search');
  // Large catalogs exercise hundreds of jumps above; browsers may rate-limit
  // history updates. Check the requested URL without relying on that quota.
  const replaceState=history.replaceState;let destination;
  history.replaceState=function(...args){destination=args[2];return replaceState.apply(this,args);};
  try { target.nameElement.dispatchEvent(new MouseEvent('dblclick',{bubbles:true})); }
  finally { history.replaceState=replaceState; }
  check(search.value===''&&filterNodes===null&&savedTree===null,'Double-click leaves search');
  check(selected===target,'Double-click selects the exact occurrence, even with shared hashes');
  check(document.activeElement===document.getElementById('tree'),'Double-click focuses tree navigation');
  check(destination===url(target),'Double-click updates the selected item URL');
  const ancestors=new Set();
  for(let parent=target.parent;parent;parent=parent.parent)ancestors.add(parent.path);
  check([...ancestors].every(path=>!collapsed.has(path)),'Double-click reveals every ancestor');
  check([...beforeJump].filter(path=>!ancestors.has(path)).every(path=>collapsed.has(path)),'Double-click preserves other collapse choices, including the target');
  const rect=rowElements.get(target.path).getBoundingClientRect();
  check(rect.top>=document.querySelector('thead').getBoundingClientRect().bottom-1&&rect.bottom<=document.getElementById('table-scroll').getBoundingClientRect().bottom+1,'Double-click scrolls the selected row into view');
  check(rowElements.get(target.path).getAttribute('aria-selected')==='true','Double-click announces selection');
 }
 collapsed.clear();render();select(selected || visible[0]);
 document.getElementById('tree').focus();
 document.dispatchEvent(new KeyboardEvent('keydown',{key:'End',bubbles:true}));
 check(selected===visible.at(-1)&&rowElements.get(selected.path).isConnected,'End mounts last row');
 const lastRect=rowElements.get(selected.path).getBoundingClientRect();
 const hostRect=document.getElementById('table-scroll').getBoundingClientRect();
 check(lastRect.bottom<=hostRect.bottom+1&&lastRect.top>=hostRect.top,'Last row scrolls into view');
 check(document.querySelectorAll('tr.node').length<150,'Viewport limits mounted rows');
 check(Math.abs(lastRect.height-21)<0.1,'Virtual row height matches layout');
 document.dispatchEvent(new KeyboardEvent('keydown',{key:'Home',bubbles:true}));
 check(selected===visible[0]&&rowElements.get(selected.path).isConnected,'Home mounts first row');
 const topRect=rowElements.get(selected.path).getBoundingClientRect();
 check(topRect.top>=document.querySelector('thead').getBoundingClientRect().bottom-1,'First row below sticky header');
 return {rows:initial,result:'PASS: stable row identity, nested fold state, hidden-row keyboard skipping, top-level boundary, jump reveal, expand/collapse all, aria state, live search, title/path/hash matching, filtered navigation, empty state, search shortcuts and restoration'};
})()`);
assert.ok(result.rows>0);
console.log(JSON.stringify(result));
const download=await evaluate(`(async()=>{
 if(!downloadsEnabled){
  if(!document.getElementById('download-heading').hidden)throw new Error('Download heading should be hidden');
  return null;
 }
 if(document.getElementById('download-heading').hidden)throw new Error('Download heading missing');
 const file=[...nodes.values()].find(n=>n.type==='file'&&n.size>0&&n.size<100000&&n.name.endsWith('.PNG'));
 jump(file);
 for(let i=0;i<100&&!file.downloadCell.querySelector('a');i++)await new Promise(r=>setTimeout(r,50));
 const link=file.downloadCell.querySelector('a');
 if(!link||link.download!==file.name)throw new Error('Missing download or wrong filename');
 if(rowElements.get(file.path).children.length!==4)throw new Error('Download column missing');
 if([...rowElements.values()].some(r=>r.classList.contains('folder')&&r.querySelector('.download-link')))throw new Error('Folder download link');
 return {url:link.href,hash:file.hash,size:file.size,name:file.name};
})()`);
if(download){
 const response=await fetch(download.url);
 assert.equal(response.status,200);
 const bytes=Buffer.from(await response.arrayBuffer());
 assert.equal(bytes.length,download.size);
 assert.equal(createHash('sha256').update(bytes).digest('hex'),download.hash);
 assert.ok(response.headers.get('content-disposition').includes('attachment;'));
 console.log('PASS: live store download matches catalog SHA-256 and size, filename preserved');
}
const extractedDownload=await evaluate(`(async()=>{
 const sources=[...nodes.values()].filter(n=>n.extraction);
 if(!sources.length)return null;
 for(const n of nodes.values())if(expandable(n))collapsed.add(n.path);render();select(visible[0]);
 const source=sources[0];jump(source);
 const row=rowElements.get(source.path);
 if(!row.classList.contains('file')||!row.classList.contains('container'))throw new Error('Extractable file styling');
 if(row.querySelector('.size').textContent!==formatSize(source.size))throw new Error('Source size must remain exact');
 document.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowRight',bubbles:true}));
 if(collapsed.has(source.path)||!visible.includes(source.children[0]))throw new Error('Cannot expand extracted file');
 document.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowLeft',bubbles:true}));
 if(!collapsed.has(source.path)||visible.includes(source.children[0]))throw new Error('Cannot collapse extracted file');
 const child=[...nodes.values()].find(n=>n.path.startsWith(source.path+'/')&&n.type==='file'&&!n.extraction&&n.size>0);
 document.getElementById('tree-search').value=child.hash;applySearch();
 if(!visible.includes(child))throw new Error('Extracted hash search');
 clearSearch();jump(child);
 if(!downloadsEnabled)return null;
 for(let i=0;i<100&&!child.downloadCell.querySelector('a');i++)await new Promise(r=>setTimeout(r,50));
 const link=child.downloadCell.querySelector('a');
 if(!link||link.download!==child.name)throw new Error('Extracted file download missing');
 return {url:link.href,hash:child.hash,size:child.size,occurrences:sources.length};
})()`);
if(extractedDownload){
 const response=await fetch(extractedDownload.url);
 assert.equal(response.status,200);
 const bytes=Buffer.from(await response.arrayBuffer());
 assert.equal(bytes.length,extractedDownload.size);
 assert.equal(createHash('sha256').update(bytes).digest('hex'),extractedDownload.hash);
 console.log('PASS: extraction styling, exact source size, keyboard folding, hash search and verified child download; occurrences='+extractedDownload.occurrences);
}
const availabilityTimeout=await evaluate(`(async()=>{
 if(!downloadsEnabled)return 'SKIP: store not configured';
 const file=[...nodes.values()].find(n=>n.type==='file'&&n.hash);
 const originalFetch=window.fetch;
 window.fetch=(url,options)=>String(url).startsWith('api/availability?')
  ? new Promise((resolve,reject)=>options?.signal?.addEventListener('abort',()=>reject(options.signal.reason),{once:true}))
  : originalFetch(url,options);
 try {
  availability.delete(file.hash);
  jump(file);
  refreshDownloads();
  for(let i=0;i<400&&file.downloadCell.textContent!=='Check failed';i++)await new Promise(r=>setTimeout(r,50));
  if(file.downloadCell.textContent!=='Check failed')throw new Error('Stalled store check never settled');
 } finally {
  window.fetch=originalFetch;
 }
 availability.delete(file.hash);
 await refreshDownloads();
 if(!['Download','Missing'].includes(file.downloadCell.textContent))throw new Error('Store checks did not resume after timeout');
 return 'PASS: stalled store checks report failure and subsequent real checks complete';
})()`);
console.log(availabilityTimeout);
const extractionErrors=await evaluate(`(()=>{
 const check=(value,message)=>{if(!value)throw new Error(message)};
 const packageHash='a'.repeat(64), edatHash='b'.repeat(64), inlineHash='c'.repeat(64), childHash='d'.repeat(64);
 const hostile='<img src=x onerror=alert(1)> '+ 'long-error-detail-'.repeat(150);
 const file=(path,hash,extra={})=>({path,type:'file',sha256:hash,size_bytes:10,...extra});
 const tree=(hash,entries,error)=>({sha256:hash,size_bytes:10,extractor:{name:'extractor',version:'1'},entries,...(error?{error}:{})});
 const fixture={records:{pkg:[{sha256:packageHash,size_bytes:10,metadata:{title:'Error visibility'}}]},trees:{
  pkg:{[packageHash]:tree(packageHash,[
   file('ISO.BIN.EDAT',edatHash),
   file('DATA.PSP',inlineHash,{extraction:tree(inlineHash,[file('decoded.bin',childHash)],hostile)}),
   file('UNCHANGED.PSP',inlineHash),
   ...Array.from({length:200},(_,i)=>file('sibling-'+String(i).padStart(3,'0')+'.bin',childHash)),
  ],'Partial package extraction')},
  edat:{[edatHash]:tree(edatHash,[],'UnsupportedEdat')},
 }};
 clearSearch();rowElements.clear();disclosures.clear();collapsed.clear();visible=[];selected=null;
 build(fixture);
 for(const node of nodes.values())if(node.extraction)collapsed.add(node.path);
 render();
 const source=[...nodes.values()].find(n=>n.hash===packageHash);
 const edat=source.children.find(n=>n.name==='ISO.BIN.EDAT');
 const inline=source.children.find(n=>n.name==='DATA.PSP');
 const sibling=source.children.find(n=>n.name==='UNCHANGED.PSP');
 for(const node of [source,edat,inline]){
  jump(node);
  const row=rowElements.get(node.path), diagnostic=row.querySelector('.extraction-error');
  check(diagnostic&&diagnostic.getBoundingClientRect().width>0,'Error is visible on its source row');
  check(diagnostic.querySelector('.error-icon').getAttribute('aria-hidden')==='true','Error icon does not duplicate accessible text');
  check(document.getElementById(row.getAttribute('aria-describedby')).textContent.includes(node.error),'Accessible source error');
  check(!document.getElementById('selected-error').hidden&&document.getElementById('selected-error-message').textContent.includes(node.error),'Selected source shows full error without hover');
  check(Math.abs(row.getBoundingClientRect().height-21)<0.1,'Errors preserve virtual row height');
 }
 check(!rowElements.get(sibling.path).querySelector('.extraction-error'),'Inline failure does not leak to same-hash sibling');
 check(!document.querySelector('.extraction-error img, #selected-error img'),'Error HTML stays inert text');
 check(document.getElementById('selected-error-message').textContent.includes(hostile),'Long error is not truncated in selection details');
 const panel=document.getElementById('selected-error');
 check(panel.scrollWidth<=panel.clientWidth+1,'Long errors wrap within the selected panel');
 panel.focus();
 panel.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowDown',bubbles:true}));
 check(selected===inline,'Error detail scrolling does not navigate the tree');
 toggle(inline);
 check(visible.includes(inline.children[0]),'Trustworthy children remain navigable after failure');
 jump(source.children.at(-1));
 check(!rowElements.get(edat.path).isConnected,'Distant failed source is virtualized');
 document.getElementById('tree-search').value='UnsupportedEdat';applySearch();
 check(visible.length===1&&visible[0]===edat,'Error search finds an empty failed extraction');
 check(rowElements.get(edat.path).querySelector('.error-message mark')?.textContent==='UnsupportedEdat','Error matches highlight after remount');
 check(!document.getElementById('selected-error').hidden,'Search selection retains full error details');
 clearSearch();jump(sibling);
 check(document.getElementById('selected-error').hidden,'Successful selection clears error details');
 return 'PASS: source-scoped errors, empty failures, partial children, inert long text, accessibility, search and virtual remount';
})()`);
console.log(extractionErrors);
await cmd('Page.navigate',{url:process.env.PSPDB_SITE_URL || 'http://127.0.0.1:8000'});
ws.close();
