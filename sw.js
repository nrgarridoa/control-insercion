// Guarda la app completa en el teléfono para que funcione sin señal.
const CACHE = "control-insercion-v1.4.1";
const ARCHIVOS = [
  "./", "index.html", "style.css", "app.js", "manifest.webmanifest", "icon-192.png", "icon-512.png",
  "vendor/zxing/zxing-reader.js", "vendor/zxing/zxing_reader.wasm",
  "vendor/tesseract/tesseract.min.js", "vendor/tesseract/worker.min.js",
  "vendor/tesseract/core/tesseract-core-lstm.wasm.js", "vendor/tesseract/core/tesseract-core-simd-lstm.wasm.js",
  "vendor/tesseract/core/tesseract-core-relaxedsimd-lstm.wasm.js", "vendor/tesseract/lang/eng.traineddata.gz",
];
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(ARCHIVOS)).then(() => self.skipWaiting())); });
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  const url = new URL(e.request.url);
  if (url.pathname.includes("/vendor/")) {          // librerias pesadas: desde la cache
    e.respondWith(caches.match(e.request, { ignoreSearch: true }).then(r => r || fetch(e.request)));
    return;
  }
  // la app (html, js, css): primero la red para tomar las actualizaciones; sin señal, la cache
  e.respondWith(fetch(e.request).then(r => {
    if (r.ok && url.origin === location.origin) { const c = r.clone(); caches.open(CACHE).then(k => k.put(e.request, c)); }
    return r;
  }).catch(() => caches.match(e.request, { ignoreSearch: true }).then(r => r || caches.match("index.html"))));
});
