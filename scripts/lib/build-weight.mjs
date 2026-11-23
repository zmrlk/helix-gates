// Read generated data only; never evaluate application code in generic adapters.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
export function genericBuild(root, top) {
  const json=p=>JSON.parse(fs.readFileSync(p,'utf8'));
  let dir,manifest,kind,stamp,entries=[];
  const vite=['dist/.vite/manifest.json','dist/manifest.json','build/.vite/manifest.json'].map(p=>path.join(root,p)).find(p=>fs.existsSync(p));
  const next=path.join(root,'.next/build-manifest.json');
  if(fs.existsSync(next)) {
    kind='next';dir=path.dirname(next);stamp=next;manifest=json(next);
    if(!manifest.pages || typeof manifest.pages!=='object') throw new Error('Unsupported Next build manifest (pages required)');
    entries=Object.entries(manifest.pages).filter(([k])=>!['/_app','/_document','/_error'].includes(k)).map(([route,files])=>({route,page:route,files:[...(manifest.rootMainFiles||[]),...(manifest.pages['/_app']||[]),...files],lazy:[],leaf:files.filter(f=>f.endsWith('.js')).at(-1)}));
  } else if(vite) {
    kind='vite';stamp=vite;dir=path.dirname(vite);if(path.basename(dir)==='.vite')dir=path.dirname(dir);manifest=json(vite);
    const walk=(key,seen=new Set())=>{if(seen.has(key))return [];seen.add(key);const v=manifest[key];if(!v?.file)throw new Error('Missing Vite entry '+key);return [v.file,...(v.css||[]),...(v.imports||[]).flatMap(k=>walk(k,seen))];};
    entries=Object.entries(manifest).filter(([,v])=>v.isEntry).map(([key,v])=>{
      const seen=new Set(),files=walk(key,seen);
      return {route:key==='index.html'?'/':key.endsWith('.html')?'/'+key.replace(/\.html$/,''):key,page:key,files,leaf:v.file,
        lazy:[...seen].flatMap(k=>(manifest[k].dynamicImports||[]).flatMap(id=>walk(id)))};
    });
  } else {
    kind='static';dir=path.join(root,'dist');
    if(!fs.existsSync(dir))throw new Error('Unknown build: expected SvelteKit, Vite, Next pages manifest or static dist HTML');
    const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):e.isFile()&&e.name.endsWith('.html')?[path.join(d,e.name)]:[]);
    const html=walk(dir);stamp=html[0];
    entries=html.map(p=>{
      const rel=path.relative(dir,p),source=fs.readFileSync(p,'utf8');
      const files=[...source.matchAll(/<(?:script|link)\b[^>]*(?:src|href)=["']([^"']+)["'][^>]*>/gi)].map(m=>m[1]).filter(f=>/\.(?:js|css)(?:[?#]|$)/.test(f));
      if(files.some(f=>/^(?:https?:)?\/\//.test(f)))throw new Error('External static assets cannot be weighed');
      const normalized=files.map(f=>path.posix.normalize(path.posix.join(f.startsWith('/')?'':path.posix.dirname(rel),f.replace(/^\//,''))).split(/[?#]/)[0]);
      return {route:'/'+rel.replace(/index\.html$/,'').replace(/\.html$/,''),page:rel,files:normalized,leaf:normalized.find(f=>f.endsWith('.js')),lazy:[]};
    });
  }
  if(!entries.length)throw new Error('Build has no recognized UI entries');
  const safe=f=>{
    if(typeof f!=='string')throw new Error('Invalid asset path');
    const p=fs.realpathSync(path.resolve(dir,f));if(!p.startsWith(fs.realpathSync(dir)+path.sep))throw new Error('Asset outside build');return p;
  };
  const cache=new Map(),size=f=>{if(!cache.has(f)){const b=fs.readFileSync(safe(f));cache.set(f,{raw:b.length,gz:zlib.gzipSync(b,{level:6}).length});}return cache.get(f);};
  const uniq=a=>[...new Set(a)],kib=n=>Math.round(n/1024*10)/10,sum=(a,k)=>kib(a.reduce((n,f)=>n+size(f)[k],0));
  const rows=entries.map(e=>{
    const js=uniq(e.files.filter(f=>f.endsWith('.js'))),css=uniq(e.files.filter(f=>f.endsWith('.css'))),lazy=uniq(e.lazy.filter(f=>f.endsWith('.js')&&!js.includes(f)));
    if(!js.length && !css.length)throw new Error('No weighable assets for '+e.route);
    return {route:e.route,page:e.page,files:js.length,js_raw:sum(js,'raw'),js_gz:sum(js,'gz'),css_files:css.length,css_raw:sum(css,'raw'),css_gz:sum(css,'gz'),page_gz:e.leaf?sum([e.leaf],'gz'):0,lazy:lazy.length,lazy_gz:sum(lazy,'gz'),top:js.map(file=>({file,name:file,gz:kib(size(file).gz)})).sort((a,b)=>b.gz-a.gz).slice(0,5)};
  }).sort((a,b)=>b.js_gz-a.js_gz);
  const all=uniq(entries.flatMap(e=>[...e.files,...e.lazy])),js=all.filter(f=>f.endsWith('.js')),css=all.filter(f=>f.endsWith('.css'));
  return {kind,stamp,rows,totals:{js_files:js.length,js_raw:sum(js,'raw'),js_gz:sum(js,'gz'),css_files:css.length,css_raw:sum(css,'raw'),css_gz:sum(css,'gz'),entry_gz:rows[0].js_gz,shell_gz:rows[0].js_gz},biggest:js.map(file=>({file,name:file,raw:kib(size(file).raw),gz:kib(size(file).gz)})).sort((a,b)=>b.gz-a.gz).slice(0,top)};
}
