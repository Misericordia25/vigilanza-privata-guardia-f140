/* Carlo Doga: service worker (funzionamento offline e notifiche push) */
const V = 'cd-2.0.0', CORE = ['./', 'index.html', 'manifest.json', 'favicon-64.png', 'icon-192.png', 'icon-512.png', 'icon-maskable-512.png', 'apple-touch-icon.png'];
self.addEventListener('install', e => {
  e.waitUntil(caches.open(V).then(c => Promise.all(CORE.map(u => c.add(u).catch(() => {})))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(k => Promise.all(k.filter(x => x !== V).map(x => caches.delete(x)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/.netlify/')) return; // i dati passano sempre dal server
  if (r.mode === 'navigate') { // pagina: prima la rete (versione aggiornata), se offline la copia salvata
    e.respondWith(fetch(r).then(x => { const k = x.clone(); caches.open(V).then(c => c.put('index.html', k)); return x })
      .catch(() => caches.match('index.html').then(x => x || caches.match('./'))));
    return;
  }
  e.respondWith(caches.match(r).then(h => h || fetch(r).then(x => { if (x.ok) { const k = x.clone(); caches.open(V).then(c => c.put(r, k)) } return x })));
});
// Notifica push dal server (anche ad app chiusa). Con l'app aperta la notifica fa anche da "sveglia": l'app si sincronizza subito (niente controlli periodici)
self.addEventListener('push', e => {
  let d = {}; try { d = e.data.json() } catch { d = { t: 'Carlo Doga', b: e.data ? e.data.text() : '' } }
  const emg = !!d.ri; // chiamata d'emergenza attiva: vibrazione lunga e notifica che resta finché non la tocchi
  e.waitUntil(Promise.all([
    self.registration.showNotification(d.t || 'Carlo Doga', { body: d.b || '', icon: 'icon-192.png', badge: 'favicon-64.png', vibrate: emg ? [900, 250, 900, 250, 900, 250, 900, 250, 900] : [250, 120, 250], requireInteraction: emg, tag: d.prom ? 'prom-' + d.prom + '-' + (d.n || 0) : d.tg, renotify: !!(d.prom || d.tg), data: { prom: d.prom, go: d.go } }),
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(l => l.forEach(c => c.postMessage({ sync: 1 })))
  ]));
});
self.addEventListener('notificationclick', e => {
  e.notification.close(); const pr = e.notification.data && e.notification.data.prom, go = e.notification.data && e.notification.data.go;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(l => {
    if (l.length) { l[0].postMessage({ sync: 1 }); if (pr) l[0].postMessage({ prom: pr }); if (go) l[0].postMessage({ go }); return l[0].focus() }
    return self.clients.openWindow(pr ? './?prom=' + encodeURIComponent(pr) : go ? './?go=' + go : './');
  }));
});
