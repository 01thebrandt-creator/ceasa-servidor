/* Controle Ceasa: abre mesmo sem internet. O app e o config.js usam a versão nova quando há internet (e a guardada quando não há).
   A API do servidor nunca passa pelo cache. */
const V = 'ceasa-v6';
const SHELL = ['./', './index.html', './config.js', './manifest.webmanifest', './icon-192.png', './icon-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(V).then(c => Promise.all(SHELL.map(u => c.add(u).catch(() => null)))).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
function networkFirst(r) {
  return new Promise(resolve => {
    let done = false;
    const fallback = () => caches.match(r).then(h => h || caches.match('./index.html'));
    const t = setTimeout(() => fallback().then(h => { if (h && !done) { done = true; resolve(h); } }), 3500);
    fetch(r).then(res => {
      clearTimeout(t);
      if (res && res.ok) { const c = res.clone(); caches.open(V).then(x => x.put(r, c)).catch(() => {}); }
      if (!done) { done = true; resolve(res); }
    }).catch(() => { clearTimeout(t); if (!done) fallback().then(h => { done = true; resolve(h || Response.error()); }); });
  });
}
self.addEventListener('fetch', e => {
  const r = e.request; if (r.method !== 'GET') return;
  const u = new URL(r.url);
  if (u.origin !== self.location.origin || u.pathname.startsWith('/api/')) return;      // só os arquivos do próprio app; a API nunca é guardada
  if (r.mode === 'navigate' || /(\/|index\.html|config\.js)$/.test(u.pathname)) { e.respondWith(networkFirst(r)); return; }
  e.respondWith(caches.match(r).then(hit => {
    const net = fetch(r).then(res => { if (res && res.ok) { const c = res.clone(); caches.open(V).then(x => x.put(r, c)).catch(() => {}); } return res; }).catch(() => hit);
    return hit || net;
  }));
});
