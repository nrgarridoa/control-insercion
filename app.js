/* Control de Inserción · PWA de campo (QAQC Drillholes)
 * Inserción continua (por defecto): se recorre la guía en orden y cada muestra pasa por sus pasos; el paso 2 se lee en dos tiempos.
 * Etapa 1: GEO = LAB (todas las que tienen GEO: ASSAY y duplicados; los controles MB/MC no).
 * Etapa 2: barrido en el orden de la guía; se leen juntas la LAB de la bolsita y la del sobre
 *          (mismo número y las dos dicen LAB: las GEO no se envían al laboratorio).
 * Todo se guarda en el teléfono (IndexedDB). Al terminar se exporta un CSV que se importa en la plataforma.
 * El despacho llega en un enlace #g= que genera la plataforma (ver backend ddh_insercion/guia.py).
 */
"use strict";
const VERSION = "1.5.0";
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const n0 = v => (v ?? 0).toLocaleString("es-PE");
const ahora = () => new Date().toISOString();
const hora = ts => ts ? new Date(ts).toLocaleTimeString("es-PE", { hour: "2-digit", minute: "2-digit" }) : "";
const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
  const r = Math.random() * 16 | 0; return (c === "x" ? r : (r & 3 | 8)).toString(16); }));
const esControl = t => /^M[BC]\s*\d/i.test(t || "");
const tramo = m => m.f != null ? `${m.f.toFixed(2)} – ${m.t.toFixed(2)} m` : "Control";
const ALERTA_TXT = { no_coinciden: "GEO ≠ LAB", fuera_guia: "Fuera de la guía", bolsita_sobre: "Bolsita ≠ sobre",
  etiqueta_geo: "Etiqueta GEO", fuera_orden: "Fuera de orden", manual: "Ingreso manual" };

/* ------------------------------------------------------------------ almacenamiento (IndexedDB) */
const idb = {
  db: null,
  abrir() {
    return new Promise((res, rej) => {
      const r = indexedDB.open("control-insercion", 1);
      r.onupgradeneeded = () => {
        const d = r.result;
        d.createObjectStore("despachos", { keyPath: "despacho" });
        const l = d.createObjectStore("lecturas", { keyPath: "uuid" });
        l.createIndex("despacho", "despacho");
      };
      r.onsuccess = () => { idb.db = r.result; res(); };
      r.onerror = () => rej(r.error);
    });
  },
  tx(st, modo, fn) {
    return new Promise((res, rej) => {
      const t = idb.db.transaction(st, modo); const s = t.objectStore(st); const out = fn(s);
      t.oncomplete = () => res(out && "result" in out ? out.result : out); t.onerror = () => rej(t.error);
    });
  },
  put: (st, v) => idb.tx(st, "readwrite", s => s.put(v)),
  get: (st, k) => idb.tx(st, "readonly", s => s.get(k)),
  del: (st, k) => idb.tx(st, "readwrite", s => s.delete(k)),
  all: st => idb.tx(st, "readonly", s => s.getAll()),
  porDespacho: d => idb.tx("lecturas", "readonly", s => s.index("despacho").getAll(d)),
};

/* ------------------------------------------------------------------ enlace #g= (formato I1) */
const b64u = t => Uint8Array.from(atob(t.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
async function inflar(bytes) {
  const s = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new TextDecoder().decode(await new Response(s).arrayBuffer());
}
/* Enlace cifrado #gc= : version(1) | sal(16) | iv(12) | AES-256-GCM (clave PBKDF2-SHA256 de la clave del enlace).
   Cada enlace trae su propia clave (la muestra la plataforma junto al QR); sin espacios ni guiones, en mayúsculas. */
const CLAVE_LS = "clave-campo", ITER = 200000;
const normClave = c => String(c || "").replace(/[\s-]/g, "").toUpperCase();
async function descifrar(bytes, tipo, clave) {
  if (bytes[0] !== 1) throw new Error("Enlace de una versión que esta app no conoce. Actualiza la app.");
  const te = new TextEncoder();
  const base = await crypto.subtle.importKey("raw", te.encode(normClave(clave)), "PBKDF2", false, ["deriveKey"]);
  const k = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: bytes.slice(1, 17), iterations: ITER, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(17, 29), additionalData: te.encode(tipo) }, k, bytes.slice(29)));
}
async function abrirCifrado(bytes, tipo) {
  try { localStorage.removeItem(CLAVE_LS); } catch { /* */ }   // la clave fija de la v1.1 ya no se usa
  let error = "";
  for (;;) {
    const abierto = dialogo(`<div class="clave-h"><span>🔒</span><h3>Clave del despacho</h3>
        <div class="sub">Está junto al QR en la plataforma. Escribe solo letras y números: el guion se pone solo.</div></div>
      ${error ? `<div class="clave-err">${esc(error)}</div>` : ""}
      <input name="c" id="clv" class="clave-in" required autofocus autocomplete="off" autocapitalize="characters" spellcheck="false"
             maxlength="9" placeholder="XXXX-XXXX" pattern="[A-Za-z0-9]{4}-[A-Za-z0-9]{4}" title="8 letras o números">
      <div class="fila" style="margin-top:16px"><button class="big lin" value="no" formnovalidate>Cancelar</button><button class="big pri" value="ok">Abrir despacho</button></div>`);
    const inp = $("#clv");
    if (inp) inp.oninput = () => {   // mayusculas, sin simbolos y guion automatico tras 4 caracteres
      const v = inp.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8);
      inp.value = v.length > 4 ? `${v.slice(0, 4)}-${v.slice(4)}` : v;
    };
    const fd = await abierto;
    if (!fd) throw new Error("Se necesita la clave del enlace para abrirlo");
    try { return await descifrar(bytes, tipo, String(fd.get("c") || "")); }
    catch (e) { if (/versión/.test(e.message)) throw e; error = "Clave incorrecta"; }
  }
}

async function decodificar(token, cifrado = false) {
  const bytes = cifrado ? await abrirCifrado(b64u(token), "g") : b64u(token);
  const lineas = (await inflar(bytes)).split("\n");
  // I2: ...|vencimiento|llave publica del servidor (cifra lo que se exporta)|avance E1|avance E2 (bits por posicion)
  const [ver, despacho, sondaje, tipos, base, n, venceMin, pk, p1, p2] = lineas[0].split("|");
  if (ver !== "I1" && ver !== "I2") throw new Error("Enlace de una versión que esta app no conoce. Actualiza la app.");
  // I2: el vencimiento viaja dentro del contenido cifrado y autenticado (no se puede cambiar)
  if (ver === "I2" && Date.now() > Number(venceMin) * 60000) {
    const f = new Date(Number(venceMin) * 60000).toLocaleString("es-PE", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
    throw new Error(`Este enlace venció el ${f}: pide uno nuevo en la plataforma`);
  }
  const T = tipos.split(";");
  let prev = Number(base), prevTo = null;
  const muestras = [];
  for (const l of lineas.slice(1)) {
    if (!l) continue;
    const p = l.split(",");
    let num;
    if (p[0].startsWith("=")) num = p[0].slice(1); else { prev += p[0] ? Number(p[0]) : 1; num = String(prev); }
    let f = null, t = null;
    if (p[2] !== "-") { f = p[2] === "" ? prevTo : Number(p[2]); t = p[3] === "" ? null : f + Number(p[3]); }
    if (t != null) prevTo = t;
    const tipo = T[Number(p[1])];
    muestras.push({ o: muestras.length + 1, n: num, tipo, f: f == null ? null : f / 100, t: t == null ? null : t / 100,
      dup: p[4] ? String(Number(num) - Number(p[4])) : null, ctrl: esControl(tipo) });
  }
  if (muestras.length !== Number(n)) throw new Error("El enlace está incompleto (¿se cortó al copiarlo?).");
  const bits = t => { if (!t) return []; const b = b64u(t); return muestras.filter((m, i) => (b[i >> 3] >> (i & 7)) & 1).map(m => m.n); };
  return { despacho, sondaje, muestras, cargado: ahora(), vence: ver === "I2" ? Number(venceMin) * 60000 : null,
           pk: pk || "", previo: { e1: bits(p1), e2: bits(p2) } };
}

/* ------------------------------------------------------------------ estado */
const S = { desp: null, lect: [], idx: new Map(), pant: "inicio", usuario: "", camara: null };
try { S.usuario = localStorage.getItem("usuario") || ""; } catch { /* sin almacenamiento */ }

function indexar() {
  S.idx = new Map(S.desp.muestras.map(m => [m.n, m]));
  S.prev = { 1: new Set(S.desp.previo?.e1 || []), 2: new Set(S.desp.previo?.e2 || []) };
}
/* conforme en un turno anterior (ya importado en la plataforma; viene en el enlace) */
const previo = (etapa, n) => !!S.prev?.[etapa]?.has(n);
function lecturasDe(etapa) { return S.lect.filter(l => l.etapa === etapa); }
function ultima(etapa, muestra) {
  let u = null;
  for (const l of S.lect) if (l.etapa === etapa && l.muestra === muestra && (!u || l.ts > u.ts)) u = l;
  return u;
}
function conforme(etapa, muestra) { const u = ultima(etapa, muestra); return u ? u.resultado === "conforme" : previo(etapa, muestra); }
function resumen() {
  const M = S.desp.muestras, prep = M.filter(m => !m.ctrl);
  const e1 = prep.filter(m => conforme(1, m.n)).length, e2 = M.filter(m => conforme(2, m.n)).length;
  const alertas = S.lect.filter(l => l.resultado === "alerta" || l.metodo === "manual");
  const sinExp = S.lect.filter(l => !l.exportado).length;
  return { n: M.length, n1: prep.length, e1, e2, alertas, sinExp };
}
function siguienteE1() { return S.desp.muestras.find(m => !m.ctrl && !ultima(1, m.n) && !previo(1, m.n)) || null; }
/* Insercion continua (como se trabaja en campo): se recorre la guia en orden y cada muestra pasa por sus pasos:
   1 GEO = LAB (todas las que tienen GEO: ASSAY y duplicados; los controles MB/MC no) y 2 bolsita LAB al sobre LAB. */
const pasosDe = m => (m.ctrl ? [2] : [1, 2]);
const tocado = (e, n) => !!ultima(e, n) || previo(e, n);
function actualC() {
  const ms = S.desp.muestras;
  const pend = m => pasosDe(m).find(e => !tocado(e, m.n));
  let max = -1;
  for (const l of S.lect) { const m = S.idx.get(l.muestra); if (m && m.o > max) max = m.o; }
  for (const e of [1, 2]) for (const n of S.prev?.[e] || []) { const m = S.idx.get(n); if (m && m.o > max) max = m.o; }
  const m = ms.find(x => x.o >= max && pend(x)) || ms.find(pend);
  return m ? { m, paso: pend(m), pos: ms.indexOf(m) + 1, total: ms.length } : null;
}
function pasoActual() { return S.etapa === "c" ? (actualC()?.paso ?? 2) : S.etapa; }
function siguienteE2() {
  // despues de la ultima muestra leida en el barrido (en el orden de la guia), contando el turno anterior
  let max = 0;
  for (const l of lecturasDe(2)) { const m = S.idx.get(l.muestra); if (m && m.o > max) max = m.o; }
  for (const n of S.prev?.[2] || []) { const m = S.idx.get(n); if (m && m.o > max) max = m.o; }
  const libre = m => !ultima(2, m.n) && !previo(2, m.n);
  return S.desp.muestras.find(m => m.o > max && libre(m)) || S.desp.muestras.find(libre) || null;
}
async function cargarDespacho(despacho) {
  S.desp = await idb.get("despachos", despacho);
  if (!S.desp) return;
  indexar();
  S.lect = await idb.porDespacho(despacho);
  try { localStorage.setItem("despacho", despacho); } catch { /* */ }
}
async function registrar(etapa, m, datos) {
  const l = { uuid: uuid(), despacho: S.desp.despacho, sondaje: S.desp.sondaje, etapa, orden: m ? m.o : "",
    muestra: m ? m.n : (datos.codigo_1 || ""), resultado: "conforme", alerta: "", detalle: "", codigo_1: "", codigo_2: "",
    texto_1: "", texto_2: "", metodo: "camara", usuario: S.usuario, dispositivo: navigator.userAgent.slice(0, 140),
    ts: ahora(), app: VERSION, exportado: false, ...datos };
  await idb.put("lecturas", l);
  S.lect.push(l);
  return l;
}

/* ------------------------------------------------------------------ avisos: vibracion y sonido */
let audio = null;
function sonar(tipo) {
  try {
    navigator.vibrate?.(tipo === "ok" ? 70 : tipo === "mal" ? [200, 90, 200] : [60, 60, 60]);
    audio = audio || new (window.AudioContext || window.webkitAudioContext)();
    const tonos = tipo === "ok" ? [[880, .09], [1320, .12]] : tipo === "mal" ? [[220, .25], [180, .3]] : [[600, .12]];
    let t = audio.currentTime;
    for (const [f, d] of tonos) {
      const o = audio.createOscillator(), g = audio.createGain();
      o.frequency.value = f; o.type = tipo === "mal" ? "square" : "sine"; g.gain.value = .15;
      o.connect(g); g.connect(audio.destination); o.start(t); o.stop(t + d); t += d + .03;
    }
  } catch { /* sin audio */ }
}
function toast(t, ms = 2600) {
  const e = $("#toast"); e.textContent = t; e.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => { e.hidden = true; }, ms);
}

/* ------------------------------------------------------------------ pantalla de resultado */
let resolverRes = null;
function mostrar({ c, i, t, n, d = [], b }) {
  sonar(c === "ok" ? "ok" : c === "mal" ? "mal" : "aviso");
  const e = $("#res");
  e.className = c; e.hidden = false;
  e.innerHTML = `<div class="ic">${i}</div><h2>${esc(t)}</h2>${n ? `<div class="num">${n}</div>` : ""}${d.map(x => `<p>${esc(x)}</p>`).join("")}
    <div class="bot">${b.map((x, k) => `<button type="button" class="${k ? "b2" : "b1"}" data-k="${k}">${esc(x)}</button>`).join("")}</div>`;
  return new Promise(res => {
    resolverRes = res;
    e.querySelectorAll("button").forEach(x => x.onclick = () => { e.hidden = true; resolverRes = null; res(Number(x.dataset.k)); });
    // insercion continua: los conformes se cierran solos para seguir sin tocar la pantalla
    if (c === "ok" && S.etapa === "c" && b.length === 1) setTimeout(() => { if (resolverRes === res) e.querySelector("button")?.click(); }, 1100);
  });
}

/* ------------------------------------------------------------------ lectura de codigos y de la palabra LAB/GEO */
let zxingListo = false;
function prepararZxing() {
  if (zxingListo) return;
  ZXingWASM.prepareZXingModule({ overrides: { locateFile: (p, pre) => p.endsWith(".wasm") ? "vendor/zxing/" + p : pre + p } });
  zxingListo = true;
}
async function leerCodigos(canvas) {
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const r = await ZXingWASM.readBarcodes(img, { formats: ["Code128"], maxNumberOfSymbols: 4, tryHarder: true, tryRotate: true });
  return r.filter(x => x.isValid && x.text).map(x => ({ text: x.text.trim(), pos: x.position }));
}
let ocr = null, ocrCargando = null;
function prepararOcr() {
  if (ocr || ocrCargando) return ocrCargando;
  ocrCargando = Tesseract.createWorker("eng", 1, {
    workerPath: "vendor/tesseract/worker.min.js", corePath: "vendor/tesseract/core", langPath: "vendor/tesseract/lang", gzip: true,
  }).then(async w => { await w.setParameters({ tessedit_pageseg_mode: "6" }); ocr = w; return w; })
    .catch(e => { ocrCargando = null; throw e; });
  return ocrCargando;
}
function recorteTexto(canvas, pos) {
  // la palabra LAB/GEO va a la derecha, a la altura del numero impreso bajo el codigo (alineado con el codigo)
  const tl = pos.topLeft, tr = pos.topRight, bl = pos.bottomLeft, br = pos.bottomRight;
  const w = Math.hypot(tr.x - tl.x, tr.y - tl.y), h = Math.hypot(bl.x - tl.x, bl.y - tl.y);
  if (w < 40) return null;
  const ux = (tr.x - tl.x) / w, uy = (tr.y - tl.y) / w;
  let vx = -uy, vy = ux;                                   // perpendicular hacia abajo del codigo
  if ((bl.x - tl.x) * vx + (bl.y - tl.y) * vy < 0) { vx = -vx; vy = -vy; }
  const cx = (tl.x + tr.x + bl.x + br.x) / 4, cy = (tl.y + tr.y + bl.y + br.y) / 4;
  const ox = cx + ux * 0.30 * w + vx * (h / 2 + 0.04 * w), oy = cy + uy * 0.30 * w + vy * (h / 2 + 0.04 * w);
  const W = 0.42 * w, H = 0.32 * w, s = Math.max(1, 360 / W);
  const c = document.createElement("canvas"); c.width = Math.round(W * s); c.height = Math.round(H * s);
  const g = c.getContext("2d");
  g.fillStyle = "#fff"; g.fillRect(0, 0, c.width, c.height);
  g.setTransform(s * ux, s * vx, s * uy, s * vy, -s * (ux * ox + uy * oy), -s * (vx * ox + vy * oy));
  try { g.filter = "grayscale(1) contrast(1.6)"; } catch { /* */ }
  g.drawImage(canvas, 0, 0);
  return c;
}
async function palabra(canvas, pos) {
  if (!ocr && ocrCargando) { try { await ocrCargando; } catch { /* sin lector de texto: se pregunta */ } }
  const c = recorteTexto(canvas, pos);
  if (!c || !ocr) return "?";
  const r = await ocr.recognize(c);
  const t = (r.data.text || "").toUpperCase().replace(/\s+/g, " ");
  if (/\bLAB\b|L4B|LA8/.test(t)) return "LAB";
  if (/\bGEO\b|GE0|6EO|CEO/.test(t)) return "GEO";
  if (/LAB/.test(t)) return "LAB";
  if (/GEO/.test(t)) return "GEO";
  return "?";
}

/* ------------------------------------------------------------------ camara */
async function abrirCamara(etapa) {
  if (!S.usuario) { await pedirUsuario(); if (!S.usuario) return; }
  prepararZxing();
  if (etapa !== 1) prepararOcr()?.catch(() => toast("No se pudo cargar el lector de texto: se preguntará LAB/GEO", 4000));
  S.pant = "camara"; S.etapa = etapa; render();
  const v = $("#video");
  try {
    S.stream = await navigator.mediaDevices.getUserMedia({ audio: false,
      video: { facingMode: { ideal: "environment" }, width: { ideal: 1920 }, height: { ideal: 1080 } } });
  } catch (e) {
    toast("No se pudo abrir la cámara: " + (e.message || e), 5000); cerrarCamara(); return;
  }
  v.srcObject = S.stream; await v.play().catch(() => {});
  S.scan = { on: true, clave: "", veces: 0, ocupado: false, desde: Date.now() };
  bucle();
}
/* QR del despacho (el que muestra la plataforma): se lee con la misma camara y se carga como un enlace pegado */
async function escanearQr() {
  prepararZxing();
  S.pant = "qr"; render();
  try {
    S.stream = await navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 720 } } });
  } catch (e) { toast("No se pudo abrir la cámara: " + (e.message || e), 5000); cerrarQr(); return; }
  const v = $("#video"); v.srcObject = S.stream; await v.play().catch(() => {});
  S.qr = { on: true }; bucleQr();
}
function cerrarQr() {
  if (S.qr) S.qr.on = false;
  S.stream?.getTracks().forEach(t => t.stop()); S.stream = null;
  S.pant = "inicio"; render();
}
async function bucleQr() {
  const q = S.qr; if (!q || !q.on) return;
  const v = $("#video");
  if (!v || !v.videoWidth) { setTimeout(bucleQr, 150); return; }
  try {
    const k = Math.min(1, 1280 / Math.max(v.videoWidth, v.videoHeight));
    const c = q.canvas || (q.canvas = document.createElement("canvas"));
    c.width = Math.round(v.videoWidth * k); c.height = Math.round(v.videoHeight * k);
    const g = c.getContext("2d", { willReadFrequently: true }); g.drawImage(v, 0, 0, c.width, c.height);
    const r = await ZXingWASM.readBarcodes(g.getImageData(0, 0, c.width, c.height), { formats: ["QRCode"], maxNumberOfSymbols: 1, tryHarder: true });
    const t = r.find(x => x.isValid && /#gc?=/.test(x.text || ""))?.text;
    if (t) { cerrarQr(); try { await importarEnlace(t); } catch (e) { toast(e.message, 4500); } return; }
    if (r.some(x => x.isValid)) pista("Ese QR no es de un despacho del Control de Inserción", "wa");
  } catch { /* cuadro sin lectura */ }
  setTimeout(bucleQr, 120);
}
function pQr() {
  return `<div class="cam"><video id="video" playsinline muted></video><div class="marco" id="marco"></div>
    <div class="arriba"><small>Control de Inserción</small><b>QR del despacho</b>
      <div class="tip" id="tip">Encuadra el QR que muestra la plataforma</div></div>
    <div class="abajo"><div class="botones"><button data-a="cerrarqr">Cancelar</button><button class="icono" data-a="luz" title="Linterna">💡</button></div></div></div>`;
}
function cerrarCamara() {
  if (S.scan) S.scan.on = false;
  S.stream?.getTracks().forEach(t => t.stop()); S.stream = null;
  S.pant = "desp"; render();
}
async function linterna() {
  const t = S.stream?.getVideoTracks()[0]; if (!t) return;
  S.luz = !S.luz;
  try { await t.applyConstraints({ advanced: [{ torch: S.luz }] }); } catch { toast("Este teléfono no permite encender la linterna desde el navegador"); }
}
function pista(texto, clase = "") { const e = $("#tip"); if (e) { e.textContent = texto; e.className = "tip " + clase; } }
function marco(ok) { $("#marco")?.classList.toggle("ok", ok); }

async function bucle() {
  const sc = S.scan; if (!sc || !sc.on) return;
  const v = $("#video");
  if (sc.ocupado || !$("#res").hidden || !v || !v.videoWidth) { setTimeout(bucle, 150); return; }
  sc.ocupado = true;
  try {
    const k = Math.min(1, 1600 / Math.max(v.videoWidth, v.videoHeight));
    const c = sc.canvas || (sc.canvas = document.createElement("canvas"));
    c.width = Math.round(v.videoWidth * k); c.height = Math.round(v.videoHeight * k);
    c.getContext("2d", { willReadFrequently: true }).drawImage(v, 0, 0, c.width, c.height);
    const cods = await leerCodigos(c);
    const clave = cods.map(x => x.text).sort().join("|") + "#" + cods.length;
    if (clave === sc.clave) sc.veces++; else { sc.clave = clave; sc.veces = 1; sc.desde = Date.now(); }
    const p1 = pasoActual() === 1;
    // lo que se acaba de aceptar sigue en el cuadro (p. ej. la GEO y la LAB del paso 1): no se vuelve a leer hasta que cambie
    if (sc.bloqueo) {
      if (clave === sc.bloqueo && cods.length) { marco(false); pista(p1 ? "✓ Listo · sigue con la siguiente muestra" : "✓ Listo · retira la GEO y acerca la LAB de la bolsita", "ok");
        sc.ocupado = false; if (S.scan?.on) setTimeout(bucle, 110); return; }
      sc.bloqueo = null;
    }
    // paso 2 en dos tiempos: la bolsita de cerca y despues el sobre de cerca (juntas a distancia no se lee el texto LAB)
    if (sc.primero && (p1 || Date.now() - sc.primero.ts > 25000)) { sc.primero = null; if (!p1) pista("Se reinició: vuelve a leer la bolsita", "wa"); }
    if (!cods.length) {
      marco(false);
      if (sc.primero) { sc.vacios = (sc.vacios || 0) + 1; pista(`Bolsita ${sc.primero.text} ✓ · ahora el sobre`, "ok"); }
      else pista(p1 ? "Encuadra la GEO y la LAB juntas" : "Acerca la etiqueta LAB de la bolsita");
    } else if (cods.length === 1) {
      if (p1) {
        marco(false);
        pista("Solo se ve una etiqueta: acerca la otra", Date.now() - sc.desde > 1500 ? "wa" : "");
      } else if (sc.veces < 3) { marco(true); pista("Leyendo…"); }
      else if (!sc.primero) {
        marco(true);
        const t = await palabra(c, cods[0].pos).catch(() => "?");
        sc.primero = { text: cods[0].text, t, ts: Date.now() }; sc.vacios = 0;
        sonar("aviso"); pista(`Bolsita ${cods[0].text} ✓ · ahora el sobre`, "ok");
      } else if (sc.vacios >= 3) {
        const t = await palabra(c, cods[0].pos).catch(() => "?");
        const par = [{ text: sc.primero.text, t: sc.primero.t }, { text: cods[0].text, t }];
        sc.primero = null;
        await decidir(par, null, "camara"); sc.bloqueo = clave; sc.clave = ""; sc.veces = 0;
      } else pista(`Bolsita ${sc.primero.text} ✓ · retírala del cuadro y enfoca el sobre`, Date.now() - sc.primero.ts > 2500 ? "wa" : "ok");
    } else if (cods.length > 2) { marco(false); pista("Hay más de dos etiquetas: deja solo las de esta muestra", "wa"); }
    else if (sc.veces >= 3) { marco(true); sc.primero = null; await decidir(cods, c, "camara"); sc.bloqueo = clave; sc.clave = ""; sc.veces = 0; }
    else { marco(true); pista("Leyendo…"); }
  } catch (e) {
    pista("Error del lector: " + (e.message || e), "wa");
  } finally { sc.ocupado = false; }
  if (S.scan?.on) setTimeout(bucle, 110);
}

/* ------------------------------------------------------------------ reglas de cada etapa */
async function decidir(cods, canvas, metodo, manual = {}) {
  const [a, b] = cods.map(x => x.text);
  if (pasoActual() === 1) return decidirE1(a, b, metodo, canvas, cods);
  let t1 = manual.t1 || cods[0].t || "?", t2 = manual.t2 || cods[1].t || "?";
  if (metodo === "camara" && a === b && canvas) {
    pista("Leyendo el texto de las etiquetas…");
    if (!ocr && ocrCargando) { try { await ocrCargando; } catch { /* */ } }
    [t1, t2] = await Promise.all([palabra(canvas, cods[0].pos), palabra(canvas, cods[1].pos)]);
  }
  return decidirE2(a, b, t1, t2, metodo);
}

async function decidirE1(a, b, metodo, canvas = null, cods = null) {
  const m = S.idx.get(a) || S.idx.get(b);
  const extra = { codigo_1: a, codigo_2: b, metodo };
  if (S.etapa === "c" && a === b && m && !m.ctrl) {
    const act = actualC();
    if (act && act.m.n !== m.n) {
      const k = await mostrar({ c: "wa", i: "↕", t: "No es la que sigue", n: esc(a), d: [`Se esperaba ${act.m.n} (${act.m.tipo})`, "Revisa el orden de la guía"],
        b: ["Reintentar", "Validar igual"] });
      if (k === 0) return;
    }
    if (canvas && ocr && cods?.[1]?.pos) {   // dos LAB en el paso 1 = se saltaron la comparacion con la GEO
      const [w1, w2] = await Promise.all([palabra(canvas, cods[0].pos), palabra(canvas, cods[1].pos)]);
      if (w1 === "LAB" && w2 === "LAB") {
        const k = await mostrar({ c: "wa", i: "?", t: "Son dos etiquetas LAB", n: esc(a), d: ["El paso 1 compara la GEO con la LAB", "Encuadra la GEO y la LAB de esta muestra"],
          b: ["Reintentar", "Son GEO y LAB"] });
        if (k === 0) return;
      }
    }
  }
  if (a !== b) {
    const k = await mostrar({ c: "mal", i: "✕", t: "Etiquetas NO coinciden", n: `${esc(a)}<br>${esc(b)}`,
      d: ["No retires la GEO. Revisa el sobre"], b: ["Registrar alerta y continuar", "Reintentar"] });
    if (k === 0) { await registrar(1, m, { ...extra, resultado: "alerta", alerta: "no_coinciden", detalle: `Etiquetas ${a} / ${b}` }); render(); }
    return;
  }
  if (!m) {
    const k = await mostrar({ c: "mal", i: "✕", t: "Fuera de la guía", n: esc(a), d: ["Esta muestra no está en la guía del despacho"],
      b: ["Registrar alerta", "Reintentar"] });
    if (k === 0) { await registrar(1, null, { ...extra, muestra: a, resultado: "alerta", alerta: "fuera_guia", detalle: "No está en la guía" }); render(); }
    return;
  }
  if (m.ctrl) { await mostrar({ c: "inf", i: "i", t: "Muestra de control", n: esc(a), d: [`${m.tipo} · no pasa por preparación`, "Se revisa en la etapa 2"], b: ["Entendido"] }); return; }
  const u = ultima(1, a);
  if (u && u.resultado === "conforme") { await mostrar({ c: "inf", i: "i", t: "Ya validada", n: esc(a), d: [`Validada a las ${hora(u.ts)}`], b: ["Entendido"] }); return; }
  if (!u && previo(1, a)) { await mostrar({ c: "inf", i: "i", t: "Ya validada", n: esc(a), d: ["Validada en un turno anterior"], b: ["Entendido"] }); return; }
  await mostrar({ c: "ok", i: "✓", t: "Etiquetas conformes", n: esc(a), d: [`${m.tipo} · ${tramo(m)}`, "Ya puedes retirar la etiqueta GEO"], b: ["Continuar"] });
  await registrar(1, m, { ...extra, texto_1: "GEO", texto_2: "LAB", detalle: metodo === "manual" ? (S.detalleManual || "Ingreso manual") : "" });
  render();
}

async function decidirE2(a, b, t1, t2, metodo) {
  const esp = siguienteE2();
  const m = S.idx.get(a === b ? a : (esp && (a === esp.n || b === esp.n) ? esp.n : a)) || S.idx.get(b);
  const extra = { codigo_1: a, codigo_2: b, texto_1: t1, texto_2: t2, metodo };
  if (a !== b) {
    const k = await mostrar({ c: "mal", i: "✕", t: "Bolsita y sobre NO coinciden", n: `${esc(a)}<br>${esc(b)}`,
      d: ["La bolsita está en otro sobre", "Revisa antes de continuar"], b: ["Registrar alerta y continuar", "Reintentar"] });
    if (k === 0) { await registrar(2, m, { ...extra, resultado: "alerta", alerta: "bolsita_sobre", detalle: `Etiquetas ${a} / ${b}` }); render(); }
    return;
  }
  if (t1 === "GEO" || t2 === "GEO") {
    const k = await mostrar({ c: "mal", i: "G", t: "Hay una etiqueta GEO", n: esc(a), d: ["La GEO no se envía al laboratorio", "Cámbiala por la etiqueta LAB"],
      b: ["Reintentar", "Registrar alerta"] });
    if (k === 1) { await registrar(2, m, { ...extra, muestra: a, resultado: "alerta", alerta: "etiqueta_geo", detalle: `Texto leído: ${t1} / ${t2}` }); render(); }
    return;
  }
  if (t1 !== "LAB" || t2 !== "LAB") {
    const k = await mostrar({ c: "wa", i: "?", t: "No se distingue LAB o GEO", n: esc(a), d: ["Se leyó el código pero no el texto de la etiqueta", "Acerca la cámara o confírmalo a mano"],
      b: ["Las dos son LAB", "Hay una GEO", "Reintentar"] });
    if (k === 2) return;
    if (k === 1) { await registrar(2, m, { ...extra, muestra: a, resultado: "alerta", alerta: "etiqueta_geo", detalle: "Confirmado a mano" }); render(); return; }
    extra.texto_1 = extra.texto_1 === "?" ? "LAB*" : extra.texto_1; extra.texto_2 = extra.texto_2 === "?" ? "LAB*" : extra.texto_2;
  }
  if (!m) {
    const k = await mostrar({ c: "mal", i: "✕", t: "Fuera de la guía", n: esc(a), d: ["No pertenece a este despacho"], b: ["Registrar alerta", "Reintentar"] });
    if (k === 0) { await registrar(2, null, { ...extra, muestra: a, resultado: "alerta", alerta: "fuera_guia", detalle: "No está en la guía" }); render(); }
    return;
  }
  const u = ultima(2, a);
  if (u && u.resultado === "conforme") { await mostrar({ c: "inf", i: "i", t: "Ya escaneado", n: esc(a), d: [`Pasó en el barrido a las ${hora(u.ts)}`], b: ["Entendido"] }); return; }
  if (!u && previo(2, a)) { await mostrar({ c: "inf", i: "i", t: "Ya escaneado", n: esc(a), d: ["Pasó en el barrido de un turno anterior"], b: ["Entendido"] }); return; }
  if (u) {   // tenia una alerta y se corrigio: vuelve a pasar sin exigir el orden
    await mostrar({ c: "ok", i: "✓", t: "Corregido · LAB conformes", n: esc(a), d: [`Antes: ${ALERTA_TXT[u.alerta] || u.alerta}`], b: ["Continuar"] });
    await registrar(2, m, { ...extra, detalle: "Corregido tras " + (ALERTA_TXT[u.alerta] || u.alerta) });
    render(); return;
  }
  if (esp && esp.n !== a) {
    const k = await mostrar({ c: "mal", i: "↕", t: "Fuera de orden", n: esc(a), d: [`Se esperaba ${esp.n}`, "Ubica el sobre en su lugar de la guía"],
      b: ["Registrar alerta y continuar", "Reintentar"] });
    if (k === 0) { await registrar(2, m, { ...extra, resultado: "alerta", alerta: "fuera_orden", detalle: `Se esperaba ${esp.n}` }); render(); }
    return;
  }
  const sig = S.desp.muestras.find(x => x.o > m.o && !ultima(2, x.n));
  await mostrar({ c: "ok", i: "✓", t: "LAB conformes y en orden", n: esc(a), d: [`Bolsita y sobre · ${m.tipo} · ${tramo(m)}`, sig ? `Siguiente: ${sig.n}` : "Era la última de la guía"], b: ["Continuar"] });
  await registrar(2, m, { ...extra, detalle: metodo === "manual" ? (S.detalleManual || "Ingreso manual") : "" });
  render();
}

/* ------------------------------------------------------------------ dialogos */
function dialogo(html) {
  const d = $("#dlg"), f = $("#dlgForm");
  f.innerHTML = html;
  d.returnValue = "";
  // Enter / "Ir" del teclado: el navegador usaria el primer boton (Cancelar); se usa el principal
  f.onkeydown = e => { if (e.key === "Enter" && e.target.tagName === "INPUT") { e.preventDefault(); f.querySelector("button.pri")?.click(); } };
  d.showModal();
  return new Promise(res => { d.onclose = () => res(d.returnValue === "ok" ? new FormData(f) : null); });
}
async function pedirUsuario() {
  const fd = await dialogo(`<h3>¿Quién valida?</h3><label>Tu nombre</label><input type="text" name="u" value="${esc(S.usuario)}" required autofocus>
    <div class="fila" style="margin-top:16px"><button class="big lin" value="no" formnovalidate>Cancelar</button><button class="big pri" value="ok">Guardar</button></div>`);
  if (fd) { S.usuario = String(fd.get("u") || "").trim(); try { localStorage.setItem("usuario", S.usuario); } catch { /* */ } render(); }
}
async function ingresoManual() {
  const paso = pasoActual(), e1 = paso === 1;
  const esp = S.etapa === "c" ? actualC()?.m : e1 ? siguienteE1() : siguienteE2();
  S.scan && (S.scan.on = false, S.scan.primero = null);
  const fd = await dialogo(`<h3>Ingreso manual · ${S.etapa === "c" ? `paso ${paso}` : `etapa ${S.etapa}`}</h3>
    <label>${e1 ? "Código GEO" : "Etiqueta de la bolsita"}</label><input type="tel" name="a" value="${esc(esp?.n || "")}" inputmode="numeric" required>
    <label>${e1 ? "Código LAB" : "Etiqueta del sobre"}</label><input type="tel" name="b" value="" inputmode="numeric" required>
    ${e1 ? "" : `<div class="chk"><input type="checkbox" name="lab" id="chkLab" checked><label for="chkLab" style="margin:0;text-transform:none;font-size:15px;color:#111827">Las dos etiquetas dicen LAB</label></div>`}
    <label>Motivo</label><input type="text" name="mot" value="Etiqueta dañada">
    <div class="fila" style="margin-top:16px"><button class="big lin" value="no" formnovalidate>Cancelar</button><button class="big pri" value="ok">Validar</button></div>`);
  if (fd) {
    const a = String(fd.get("a") || "").trim(), b = String(fd.get("b") || "").trim();
    S.detalleManual = String(fd.get("mot") || "Ingreso manual").trim();
    const lab = e1 ? "" : (fd.get("lab") ? "LAB" : "GEO");
    if (a && b) await decidir([{ text: a }, { text: b }], null, "manual", { t1: e1 ? "" : lab, t2: e1 ? "" : lab });
    S.detalleManual = "";
  }
  if (S.scan) { S.scan.on = true; bucle(); }
}

/* ------------------------------------------------------------------ exportar */
const COLUMNAS = ["uuid", "despacho", "sondaje", "etapa", "orden", "muestra", "resultado", "alerta", "detalle", "codigo_1", "codigo_2",
  "texto_1", "texto_2", "metodo", "usuario", "dispositivo", "ts", "app"];
/* Cifrado del archivo que se entrega: ECDH P-256 efimero con la llave publica del servidor + HKDF-SHA256 + AES-256-GCM.
   Solo la plataforma (con su llave privada) lo abre al importarlo. Formato: INSC1.<epk>.<iv>.<cifrado> (base64url). */
const b64uEnc = u => { let s = ""; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
async function cifrarExport(texto, pk) {
  const te = new TextEncoder(), info = te.encode("insercion-csv");
  const pub = await crypto.subtle.importKey("raw", b64u(pk), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const e = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const epk = new Uint8Array(await crypto.subtle.exportKey("raw", e.publicKey));
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, e.privateKey, 256);
  const hk = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  const k = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: epk, info }, hk, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: info }, k, te.encode(texto)));
  return "INSC1." + [epk, iv, ct].map(b64uEnc).join(".");
}
async function exportar() {
  if (!S.lect.length) { toast("Todavía no hay lecturas en este despacho"); return; }
  const q = v => { const s = String(v ?? ""); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const csv = COLUMNAS.join(",") + "\n" + [...S.lect].sort((x, y) => x.ts.localeCompare(y.ts))
    .map(l => COLUMNAS.map(c => q(l[c])).join(",")).join("\n");
  const base = `Insercion_${S.desp.despacho}_${new Date().toISOString().slice(0, 16).replace(/[T:]/g, "-")}`;
  const cifrado = !!S.desp.pk;
  const file = cifrado ? new File([await cifrarExport(csv, S.desp.pk)], base + ".insc", { type: "application/octet-stream" })
                       : new File(["﻿" + csv], base + ".csv", { type: "text/csv" });
  let ok = false;
  if (navigator.canShare && navigator.canShare({ files: [file] })) {
    try { await navigator.share({ files: [file], title: file.name }); ok = true; } catch (e) { if (e.name === "AbortError") return; }
  }
  if (!ok) { const a = document.createElement("a"); a.href = URL.createObjectURL(file); a.download = file.name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 4000); }
  for (const l of S.lect) if (!l.exportado) { l.exportado = true; await idb.put("lecturas", l); }
  render();
  const fd = await dialogo(`<div class="clave-h"><span>📦</span><h3>¿Entregaste el archivo?</h3>
      <div class="sub">${esc(file.name)}${cifrado ? "<br>Va cifrado: solo la plataforma lo puede abrir." : ""}</div></div>
    <p class="aviso-borrar">Al confirmar, el despacho y sus lecturas se <b>borran de este teléfono</b>. Para seguir, otro turno abre un enlace nuevo de la plataforma.</p>
    <div class="fila" style="margin-top:14px"><button class="big lin" value="no" formnovalidate>Todavía no</button><button class="big pri" value="ok">Sí, entregado</button></div>`);
  if (fd) await entregar();
  else toast("Archivo generado. El despacho sigue en el teléfono hasta que confirmes la entrega.", 4000);
}
/* deja solo una constancia (sin numeros de muestra ni tramos) */
async function entregar() {
  const r = resumen(), d = S.desp;
  for (const l of S.lect) await idb.del("lecturas", l.uuid);
  await idb.put("despachos", { despacho: d.despacho, sondaje: d.sondaje, cargado: d.cargado, entregado: ahora(),
    n: r.n, n1: r.n1, e1: r.e1, e2: r.e2, alertas: r.alertas.length, lecturas: S.lect.length, muestras: [] });
  try { localStorage.removeItem("despacho"); } catch { /* */ }
  S.desp = null; S.lect = [];
  toast(`Despacho ${d.despacho} entregado y borrado del teléfono`, 4000);
  ir("inicio");
}
/* quitar un despacho del telefono (pruebas, o uno que ya no se va a trabajar): borra sus lecturas y el despacho */
async function quitarDespacho(id) {
  const d = (await idb.all("despachos")).find(x => x.despacho === id);
  if (!d) return false;
  const r = await resumenDe(d);
  const aviso = r.sinExp ? `<p class="aviso-borrar">Tiene <b>${n0(r.sinExp)} lectura${r.sinExp === 1 ? "" : "s"} sin exportar</b>: se pierden.</p>` : "";
  const ok = await dialogo(`<h3>Eliminar ${esc(id)}</h3><p>${esc(d.sondaje || "")} · E1 ${n0(r.e1)}/${n0(r.n1)} · E2 ${n0(r.e2)}/${n0(r.n)}</p>${aviso}
    <p>Se borra de este teléfono con todas sus lecturas. Para volver a trabajarlo, se abre otra vez el enlace de la plataforma.</p>
    <div class="fila" style="margin-top:16px"><button class="big lin" value="no" formnovalidate>Cancelar</button><button class="big pri peligro" value="ok">Eliminar</button></div>`);
  if (!ok) return false;
  for (const l of await idb.porDespacho(id)) await idb.del("lecturas", l.uuid);
  await idb.del("despachos", id);
  if (S.desp?.despacho === id) { S.desp = null; S.lect = []; try { localStorage.removeItem("despacho"); } catch { /* */ } }
  toast(`Despacho ${id} eliminado del teléfono`);
  return true;
}

/* despachos sin actividad: se borran 3 dias despues de vencido el enlace (o de la ultima lectura, lo que sea despues) */
const H = 3600000, DIAS_INACTIVO = 3;
function limiteBorrado(d, ultimaTs) {
  const venc = d.vence || (Date.parse(d.cargado) || 0) + 48 * H;
  return Math.max(venc, Date.parse(ultimaTs || "") || 0, Date.parse(d.cargado) || 0) + DIAS_INACTIVO * 24 * H;
}
async function limpiezaAuto() {
  const borrados = [];
  for (const d of await idb.all("despachos")) {
    if (d.entregado) { if (Date.now() - Date.parse(d.entregado) > 30 * 24 * H) await idb.del("despachos", d.despacho); continue; }
    const L = await idb.porDespacho(d.despacho);
    if (Date.now() > limiteBorrado(d, L.reduce((a, l) => (l.ts > a ? l.ts : a), ""))) {
      for (const l of L) await idb.del("lecturas", l.uuid);
      await idb.del("despachos", d.despacho); borrados.push(d.despacho);
    }
  }
  if (borrados.length) toast(`Borrados por inactividad: ${borrados.join(", ")}`, 6000);
}

/* ------------------------------------------------------------------ cargar despacho desde el enlace */
async function importarEnlace(texto) {
  const m = String(texto).match(/#(gc?)=([\w-]+)/);
  if (!m) throw new Error("El enlace no es de un despacho del Control de Inserción");
  const d = await decodificar(m[2], m[1] === "gc");
  const previo = await idb.get("despachos", d.despacho);
  if (previo && !previo.entregado && previo.muestras.length !== d.muestras.length) {
    if (!confirm(`El despacho ${d.despacho} ya estaba en el teléfono con otra guía. ¿Reemplazar la guía? (las lecturas se conservan)`)) return;
  }
  await idb.put("despachos", d);
  await cargarDespacho(d.despacho);
  S.pant = "desp"; render();
  toast(`Despacho ${d.despacho} cargado · ${n0(d.muestras.length)} muestras`, 3500);
}
async function pegarEnlace() {
  const abierto = dialogo(`<h3>Pegar enlace del despacho</h3><textarea name="t" id="txtEnlace" rows="5" required placeholder="Mantén presionado aquí y elige Pegar"></textarea>
    <div class="fila" style="margin-top:16px"><button class="big lin" value="no" formnovalidate>Cancelar</button><button class="big pri" value="ok">Cargar</button></div>`);
  try {   // si el navegador deja leer el portapapeles, se rellena solo
    const t = await Promise.race([navigator.clipboard?.readText?.() ?? Promise.resolve(""), new Promise(r => setTimeout(() => r(""), 1200))]);
    const a = $("#txtEnlace"); if (a && !a.value && /#gc?=/.test(t || "")) a.value = t;
  } catch { /* sin permiso: se pega a mano */ }
  const fd = await abierto;
  const t = fd ? String(fd.get("t") || "") : "";
  if (t) try { await importarEnlace(t); } catch (e) { toast(e.message, 4500); }
}

/* ------------------------------------------------------------------ pantallas */
const IC = {
  qr: '<path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3z"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h.01M17 17h4v4h-4"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  home: '<path d="M3 10.5 12 3l9 7.5V21h-6v-6H9v6H3z"/>',
  avance: '<path d="M3 3v18h18"/><path d="m7 15 4-4 3 3 5-6"/>',
  lista: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  cierre: '<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
  cam: '<path d="M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3z"/><circle cx="12" cy="13" r="3"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  buscar: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
  der: '<path d="m9 18 6-6-6-6"/>', atras: '<path d="m15 18-6-6 6-6"/>',
  alerta: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
  ok: '<path d="M20 6 9 17l-5-5"/>', basura: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6"/>', x: '<path d="M18 6 6 18M6 6l12 12"/>', reloj: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  subir: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5M12 3v12"/>',
};
const ico = (k, s = 20) => `<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24">${IC[k]}</svg>`;
const pct = (a, b) => (b ? Math.round(100 * a / b) : 0);
function anillo(p, color, txt) {
  const r = 26, c = 2 * Math.PI * r;
  return `<svg class="anillo" viewBox="0 0 64 64"><circle cx="32" cy="32" r="${r}" class="fondo"/>
    <circle cx="32" cy="32" r="${r}" stroke="${color}" stroke-dasharray="${(c * p / 100).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 32 32)"/>
    <text x="32" y="36" text-anchor="middle">${txt ?? p + "%"}</text></svg>`;
}
const cuando = ts => {
  if (!ts) return "";
  const d = new Date(ts), h = new Date();
  return d.toDateString() === h.toDateString() ? `hoy ${hora(ts)}` : d.toLocaleDateString("es-PE", { day: "2-digit", month: "short" }) + " " + hora(ts);
};

function cabInicio() {
  return `<div class="hero"><div class="hero-t"><span class="logo">${ico("qr", 22)}</span><div><small>QAQC · Drillholes</small><b>Control de Inserción</b></div></div>
    <button class="chip-user" data-a="usuario">${ico("user", 16)}${S.usuario ? esc(S.usuario) : "¿Quién valida?"}</button></div>`;
}
function cabDesp(titulo) {
  const r = resumen();
  return `<div class="cab"><div class="cab-f"><button class="atras" data-a="home" aria-label="Despachos">${ico("atras", 22)}</button>
    <div><small>${esc(S.desp.sondaje || "")} · ${n0(r.n)} muestras</small><b>${esc(titulo)}</b></div></div></div>`;
}
function nav(activa) {
  const it = (k, i, t) => `<button class="${activa === k ? "on" : ""}" data-a="${k}">${ico(i, 22)}<span>${t}</span></button>`;
  return `<nav class="nav">${it("home", "home", "Despachos")}${it("desp", "avance", "Avance")}${it("muestras", "lista", "Muestras")}${it("resumen", "cierre", "Cierre")}</nav>`;
}

async function resumenDe(d) {
  const L = d.despacho === S.desp?.despacho ? S.lect : await idb.porDespacho(d.despacho);
  const ult = (e, n) => { let u = null; for (const l of L) if (l.etapa === e && l.muestra === n && (!u || l.ts > u.ts)) u = l; return u; };
  const pv = { 1: new Set(d.previo?.e1 || []), 2: new Set(d.previo?.e2 || []) };
  const ok = (e, n) => { const u = ult(e, n); return u ? u.resultado === "conforme" : pv[e].has(n); };
  const prep = d.muestras.filter(m => !m.ctrl);
  const e1 = prep.filter(m => ok(1, m.n)).length, e2 = d.muestras.filter(m => ok(2, m.n)).length;
  const ultima = L.reduce((a, l) => (l.ts > a ? l.ts : a), "");
  return { n: d.muestras.length, n1: prep.length, e1, e2, alertas: L.filter(l => l.resultado === "alerta").length,
           sinExp: L.filter(l => !l.exportado).length, ultima, borra: limiteBorrado(d, ultima) };
}

async function pHome() {
  const todos = (await idb.all("despachos")).sort((a, b) => b.cargado.localeCompare(a.cargado));
  const lista = todos.filter(d => !d.entregado), entregados = todos.filter(d => d.entregado).sort((a, b) => b.entregado.localeCompare(a.entregado));
  const filas = await Promise.all(lista.map(async d => ({ d, r: await resumenDe(d) })));
  const fecha = t => new Date(t).toLocaleString("es-PE", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
  const tarjeta = ({ d, r }) => {
    const p = pct(r.e1 + r.e2, r.n1 + r.n), fin = r.e1 >= r.n1 && r.e2 >= r.n;
    return `<div class="dwrap"><button class="dcard" data-a="abrir" data-d="${esc(d.despacho)}">
      ${anillo(p, fin ? "#17633A" : "#012B77")}
      <div class="dt"><b>${esc(d.despacho)}</b><small>${esc(d.sondaje || "")} · ${n0(r.n)} muestras</small>
        <div class="tags"><span>E1 ${n0(r.e1)}/${n0(r.n1)}</span><span>E2 ${n0(r.e2)}/${n0(r.n)}</span>
          ${r.alertas ? `<span class="t-mal">${n0(r.alertas)} alerta${r.alertas === 1 ? "" : "s"}</span>` : ""}${r.sinExp ? `<span class="t-wa">${n0(r.sinExp)} sin exportar</span>` : ""}
          ${fin && !r.sinExp ? `<span class="t-ok">Completo</span>` : ""}</div>
        <em>${r.ultima ? "Última lectura " + cuando(r.ultima) : "Cargado " + cuando(d.cargado)}</em>
        ${r.borra - Date.now() < 24 * H ? `<em class="borra">Se borra el ${fecha(r.borra)} si no hay actividad</em>` : ""}</div>${ico("der")}</button>
      <button class="dquita" data-a="quitar" data-d="${esc(d.despacho)}" aria-label="Eliminar ${esc(d.despacho)}">${ico("basura", 19)}</button></div>`;
  };
  const constancia = d => `<div class="ecard">${ico("ok", 18)}<div><b>${esc(d.despacho)}</b><small>${esc(d.sondaje || "")} · E1 ${n0(d.e1)}/${n0(d.n1)} · E2 ${n0(d.e2)}/${n0(d.n)}${d.alertas ? ` · ${n0(d.alertas)} alerta${d.alertas === 1 ? "" : "s"}` : ""}</small>
      <em>Entregado ${fecha(d.entregado)} · borrado del teléfono</em></div><button class="ib" data-a="quitarc" data-d="${esc(d.despacho)}" aria-label="Quitar">${ico("x", 16)}</button></div>`;
  return cabInicio() + `<div class="cuerpo">
    <div class="acciones">
      <button class="accion pri" data-a="qr">${ico("qr", 30)}<b>Escanear QR</b><span>del despacho en la plataforma</span></button>
      <button class="accion" data-a="pegar">${ico("link", 28)}<b>Pegar enlace</b><span>si te lo enviaron por mensaje</span></button></div>
    <div class="sec">Despachos en el teléfono <span>${n0(lista.length)}</span></div>
    ${filas.length ? filas.map(tarjeta).join("") : `<div class="card vacio">${ico("qr", 40)}<p>Todavía no hay despachos.<br>Escanea el QR que muestra la plataforma en <b>Control de Inserción</b> para empezar.</p></div>`}
    ${entregados.length ? `<div class="sec">Entregados <span>${n0(entregados.length)}</span></div>${entregados.map(constancia).join("")}` : ""}
    <div class="pie">Al entregar el archivo, el despacho se borra de este teléfono · v${VERSION}</div></div>`;
}

function pDesp() {
  const r = resumen(), p1 = pct(r.e1, r.n1), p2 = pct(r.e2, r.n);
  const al1 = r.alertas.filter(l => l.etapa === 1).length, al2 = r.alertas.filter(l => l.etapa === 2).length;
  const s1 = siguienteE1(), s2 = siguienteE2();
  const tipos = {}; S.desp.muestras.forEach(m => { tipos[m.tipo] = (tipos[m.tipo] || 0) + 1; });
  const act = [...S.lect].sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, 6);
  const etapa = (e, tit, sub, p, al, sig, hecho, total, cls) => `<div class="card etapa">
      <div class="et-h">${anillo(p, p === 100 ? "#17633A" : "#012B77")}<div><h4>${tit}</h4><div class="sub">${sub}</div>
        <div class="tags"><span>${n0(hecho)} de ${n0(total)}</span>${al ? `<span class="t-mal">${al} alerta${al === 1 ? "" : "s"}</span>` : ""}</div></div></div>
      ${sig ? `<div class="sig">Siguiente <b class="mono">${esc(sig.n)}</b><span>${esc(sig.tipo)} · ${tramo(sig)}</span></div>` : `<div class="sig ok">${ico("ok", 16)} Etapa completa</div>`}
      <button class="big ${cls}" data-a="e${e}">${ico("cam", 20)}Solo ${e === 1 ? "etapa 1" : "etapa 2"}</button></div>`;
  const a = actualC(), pc = pct(r.e1 + r.e2, r.n1 + r.n);
  const continua = `<div class="card etapa cont">
      <div class="et-h">${anillo(pc, pc === 100 ? "#17633A" : "#012B77")}<div><h4>Inserción continua</h4>
        <div class="sub">En el orden de la guía, muestra por muestra: GEO = LAB y al sobre</div>
        <div class="tags"><span>${n0(r.e1 + r.e2)} de ${n0(r.n1 + r.n)} pasos</span>${r.alertas.length ? `<span class="t-mal">${r.alertas.length} alerta${r.alertas.length === 1 ? "" : "s"}</span>` : ""}</div></div></div>
      ${a ? `<div class="sig">Va en <b class="mono">${esc(a.m.n)}</b><span>${a.pos} de ${a.total} · ${a.paso === 1 ? "paso 1 · GEO = LAB" : "paso 2 · al sobre"}</span></div>`
        : `<div class="sig ok">${ico("ok", 16)} Todas las muestras pasaron</div>`}
      <button class="big pri" data-a="ec">${ico("cam", 20)}${r.e1 + r.e2 ? "Continuar" : "Iniciar"} inserción</button></div>`;
  return cabDesp(S.desp.despacho) + `<div class="cuerpo con-nav">
    <div class="tipos">${Object.entries(tipos).map(([t, n]) => `<span class="${esControl(t) ? "ctl" : ""}">${esc(t)} · <b>${n0(n)}</b></span>`).join("")}</div>
    ${continua}
    <div class="sec">Corregir por etapa</div>
    ${etapa(1, "Etapa 1 · GEO = LAB", "Muestras con GEO: la GEO y la LAB juntas", p1, al1, s1, r.e1, r.n1, "lin")}
    ${etapa(2, "Etapa 2 · Al sobre", "La LAB de la bolsita y la del sobre, en el orden de la guía", p2, al2, s2, r.e2, r.n, "lin")}
    <div class="card"><h4>Actividad reciente</h4>${act.length ? `<div class="act">${act.map(l => `<div><span class="pt ${l.resultado === "alerta" ? "mal" : l.metodo === "manual" ? "wa" : "ok"}"></span>
      <span class="mono">${esc(l.muestra)}</span><span class="sub">E${l.etapa} · ${esc(l.resultado === "alerta" ? ALERTA_TXT[l.alerta] || l.alerta : l.metodo === "manual" ? "Manual" : "Conforme")}</span><em>${cuando(l.ts)}</em></div>`).join("")}</div>`
      : '<div class="sub">Sin lecturas todavía</div>'}</div>
  </div>` + nav("desp");
}

const FILTROS = [["todas", "Todas"], ["p1", "Pendientes E1"], ["p2", "Pendientes E2"], ["alertas", "Alertas"], ["ctl", "Controles"]];
function estadoMuestra(m) {
  const u1 = m.ctrl ? null : ultima(1, m.n), u2 = ultima(2, m.n);
  const st = (u, e) => !u ? (previo(e, m.n) ? "ok" : "pend") : u.resultado === "conforme" ? (u.metodo === "manual" ? "man" : "ok") : "mal";
  return { e1: m.ctrl ? "na" : st(u1, 1), e2: st(u2, 2) };
}
function pMuestras() {
  const q = (S.q || "").trim(), f = S.filtro || "todas";
  const M = S.desp.muestras.filter(m => {
    if (q && !m.n.includes(q)) return false;
    const e = estadoMuestra(m);
    return f === "todas" || (f === "p1" && !m.ctrl && e.e1 !== "ok" && e.e1 !== "man") || (f === "p2" && e.e2 !== "ok" && e.e2 !== "man")
      || (f === "alertas" && (e.e1 === "mal" || e.e2 === "mal")) || (f === "ctl" && m.ctrl);
  });
  const cel = s => `<i class="st ${s}">${s === "ok" ? ico("ok", 13) : s === "man" ? "M" : s === "mal" ? ico("x", 13) : s === "na" ? "–" : ""}</i>`;
  return cabDesp("Muestras") + `<div class="cuerpo con-nav">
    <div class="buscador">${ico("buscar", 18)}<input id="qm" type="search" inputmode="numeric" placeholder="Buscar número de muestra" value="${esc(q)}"></div>
    <div class="filtros">${FILTROS.map(([k, t]) => `<button class="${f === k ? "on" : ""}" data-a="filtro" data-f="${k}">${t}</button>`).join("")}</div>
    <div class="card lm"><div class="lm-h"><span>Muestra</span><span>E1</span><span>E2</span></div>
      ${M.slice(0, 400).map(m => { const e = estadoMuestra(m); return `<button class="lm-f" data-a="muestra" data-n="${esc(m.n)}">
        <div><b class="mono">${esc(m.n)}</b><small><span class="tp ${m.ctrl ? "ctl" : ""}">${esc(m.tipo)}</span> ${tramo(m)}${m.dup ? ` · dup. de ${esc(m.dup)}` : ""}</small></div>${cel(e.e1)}${cel(e.e2)}</button>`; }).join("")
      || '<div class="vacio">Ninguna muestra con ese filtro</div>'}
      ${M.length > 400 ? `<div class="sub" style="padding:8px">… ${n0(M.length - 400)} más: usa el buscador</div>` : ""}</div>
    <div class="ley">${cel("ok")} conforme ${cel("man")} manual ${cel("mal")} alerta ${cel("pend")} pendiente</div>
  </div>` + nav("muestras");
}
async function verMuestra(n) {
  const m = S.idx.get(n); if (!m) return;
  const L = S.lect.filter(l => l.muestra === n).sort((a, b) => b.ts.localeCompare(a.ts));
  await dialogo(`<h3 class="mono">${esc(n)}</h3><div class="sub">${esc(m.tipo)} · ${tramo(m)} · orden ${m.o} en la guía${m.dup ? ` · duplicado de ${esc(m.dup)}` : ""}</div>
    <div class="hist">${L.length ? L.map(l => `<div><b>E${l.etapa}</b><span class="${l.resultado === "alerta" ? "r" : ""}">${esc(l.resultado === "alerta" ? ALERTA_TXT[l.alerta] || l.alerta : "Conforme")}${l.metodo === "manual" ? " · manual" : ""}</span>
      <em>${cuando(l.ts)}${l.usuario ? " · " + esc(l.usuario) : ""}</em>${l.detalle ? `<small>${esc(l.detalle)}</small>` : ""}</div>`).join("") : ""}
      ${[1, 2].filter(e => previo(e, n) && !L.some(l => l.etapa === e)).map(e => `<div><b>E${e}</b><span>Conforme</span><em>en un turno anterior</em></div>`).join("")}
      ${!L.length && !previo(1, n) && !previo(2, n) ? '<div class="sub">Sin lecturas</div>' : ""}</div>
    <div class="fila" style="margin-top:14px"><button class="big pri" value="ok">Cerrar</button></div>`);
}

function pResumen() {
  const r = resumen();
  const f1 = S.desp.muestras.filter(m => !m.ctrl && !conforme(1, m.n)), f2 = S.desp.muestras.filter(m => !conforme(2, m.n));
  const lineas = r.alertas.slice().sort((a, b) => b.ts.localeCompare(a.ts)).map(l =>
    `<div><span><b>E${l.etapa}</b> <span class="mono">${esc(l.muestra)}</span></span><span class="${l.metodo === "manual" || l.alerta === "fuera_orden" ? "a" : "r"}">${esc(l.resultado === "alerta" ? ALERTA_TXT[l.alerta] || l.alerta : "Ingreso manual")}</span></div>`).join("");
  const falt = (arr, e) => arr.length ? `<div class="card"><h4>Pendientes en la etapa ${e} (${n0(arr.length)})</h4><div class="lista">${arr.slice(0, 40).map(m => `<div><span class="mono">${esc(m.n)}</span><span class="sub">${esc(m.tipo)}</span></div>`).join("")}${arr.length > 40 ? `<div><span class="sub">… y ${n0(arr.length - 40)} más</span></div>` : ""}</div></div>` : "";
  return cabDesp("Cierre") + `<div class="cuerpo con-nav">
    <div class="card"><div class="cont3"><div><b>${n0(r.e1)}/${n0(r.n1)}</b><span>Etapa 1</span></div><div><b>${n0(r.e2)}/${n0(r.n)}</b><span>Etapa 2</span></div><div><b style="color:${r.alertas.length ? "#B42318" : "#17633A"}">${n0(r.alertas.length)}</b><span>alertas</span></div></div></div>
    <div class="card exp"><div class="envio"><span class="punto" style="background:${r.sinExp ? "#8A5A00" : "#17633A"}"></span>${r.sinExp ? `${n0(r.sinExp)} lecturas sin exportar` : S.lect.length ? "Todo exportado" : "Sin lecturas"}</div>
      <button class="big ok" data-a="exportar">${ico("subir", 20)}Exportar y entregar</button>
      <div class="sub">${S.desp.pk ? "El archivo va cifrado: solo la plataforma lo puede abrir. " : ""}Al confirmar la entrega, el despacho se borra de este teléfono.</div></div>
    <div class="card"><h4>Alertas</h4><div class="lista">${lineas || '<div><span class="sub">Sin alertas</span></div>'}</div></div>
    ${falt(f1, 1)}${falt(f2, 2)}
    <button class="big lin" data-a="borrar" style="color:#B42318;margin-bottom:12px">Quitar este despacho del teléfono</button></div>` + nav("resumen");
}
function txtArriba() {
  if (S.etapa !== "c") return `<small>Despacho ${esc(S.desp.despacho)} · Etapa ${S.etapa}</small><b>${S.etapa === 1 ? "GEO = LAB" : "Barrido · bolsita y sobre"}</b>`;
  const a = actualC();
  return `<small>Despacho ${esc(S.desp.despacho)} · Inserción continua</small><b>${!a ? "Despacho completo" : a.paso === 1 ? "Paso 1 · GEO = LAB" : "Paso 2 · bolsita y sobre"}</b>`;
}
function txtEsperada() {
  if (S.etapa !== "c") {
    const m = S.etapa === 1 ? siguienteE1() : siguienteE2();
    return m ? `Siguiente en la guía<b class="mono">${esc(m.n)}</b>${esc(m.tipo)} · ${tramo(m)}` : "<b>Etapa completa</b>";
  }
  const a = actualC();
  if (!a) return `<b>Todas las muestras pasaron</b>Ve a Resumen para exportar y entregar`;
  const m = a.m, sig = S.desp.muestras.find(x => x.o > m.o);
  const paso = e => `<span class="${tocado(e, m.n) ? "ok" : e === a.paso ? "on" : ""}">${e === 1 ? "1 · GEO = LAB" : "2 · Al sobre"}</span>`;
  return `${a.pos} de ${a.total}<b class="mono">${esc(m.n)}</b>${esc(m.tipo)} · ${tramo(m)}
    <div class="pasos">${pasosDe(m).map(paso).join("")}</div>${sig ? `<small class="desp">Después: ${esc(sig.n)} · ${esc(sig.tipo)}</small>` : ""}`;
}
function pCamara() {
  const e1 = pasoActual() === 1;
  return `<div class="cam"><video id="video" playsinline muted></video><div class="marco" id="marco"></div>
    <div class="arriba"><div id="cab">${txtArriba()}</div>
      <div class="tip" id="tip">${e1 ? "Encuadra la GEO y la LAB juntas" : "Acerca la etiqueta LAB de la bolsita"}</div></div>
    <div class="abajo"><div class="esperada">${txtEsperada()}</div>
      <div class="botones"><button data-a="cerrar">Pausar</button><button data-a="manual">Ingreso manual</button><button class="icono" data-a="luz" title="Linterna">💡</button></div></div></div>`;
}
async function render() {
  const app = $("#app");
  if (S.pant === "qr") { if (!$("#video")) app.innerHTML = pQr(); return; }
  if (S.pant === "camara") {
    if (!$("#video")) app.innerHTML = pCamara();
    else {
      const e = document.querySelector(".esperada"); if (e) e.innerHTML = txtEsperada();
      const c = $("#cab"); if (c) c.innerHTML = txtArriba();
    }
    return;
  }
  if (!S.desp && S.pant !== "inicio") S.pant = "inicio";
  const html = S.pant === "desp" ? pDesp() : S.pant === "muestras" ? pMuestras() : S.pant === "resumen" ? pResumen() : await pHome();
  app.innerHTML = html;
  const qm = $("#qm");
  if (qm) qm.oninput = () => { S.q = qm.value; const pos = qm.selectionStart; render().then(() => { const x = $("#qm"); if (x) { x.focus(); x.setSelectionRange(pos, pos); } }); };
}
function ir(p) { S.pant = p; window.scrollTo(0, 0); render(); }

document.addEventListener("click", async e => {
  const b = e.target.closest("[data-a]"); if (!b) return;
  e.preventDefault();
  const a = b.dataset.a;
  try { audio = audio || new (window.AudioContext || window.webkitAudioContext)(); audio.resume?.(); } catch { /* */ }
  if (a === "pegar") pegarEnlace();
  else if (a === "qr") escanearQr();
  else if (a === "cerrarqr") cerrarQr();
  else if (a === "abrir") { await cargarDespacho(b.dataset.d); S.q = ""; S.filtro = "todas"; ir("desp"); }
  else if (a === "home") ir("inicio");
  else if (a === "desp" || a === "muestras" || a === "resumen") ir(a);
  else if (a === "filtro") { S.filtro = b.dataset.f; render(); }
  else if (a === "muestra") verMuestra(b.dataset.n);
  else if (a === "ec") abrirCamara("c");
  else if (a === "e1") abrirCamara(1);
  else if (a === "e2") abrirCamara(2);
  else if (a === "cerrar") cerrarCamara();
  else if (a === "manual") ingresoManual();
  else if (a === "luz") linterna();
  else if (a === "exportar") exportar();
  else if (a === "usuario") pedirUsuario();
  else if (a === "quitarc") { await idb.del("despachos", b.dataset.d); render(); }
  else if (a === "borrar") { if (await quitarDespacho(S.desp.despacho)) ir("inicio"); }
  else if (a === "quitar") { if (await quitarDespacho(b.dataset.d)) render(); }
});

/* ------------------------------------------------------------------ inicio */
(async function iniciar() {
  await idb.abrir();
  try { await navigator.storage?.persist?.(); } catch { /* */ }
  S.pant = "inicio";
  try { await limpiezaAuto(); } catch { /* */ }
  if (/#gc?=/.test(location.hash)) {
    try { await importarEnlace(location.href); } catch (e) { toast(e.message, 5000); }
    history.replaceState(null, "", location.pathname);
  }
  render();
  // enlace abierto con la app ya abierta: solo cambia el '#'
  window.addEventListener("hashchange", async () => {
    if (!/#gc?=/.test(location.hash)) return;
    const h = location.href; history.replaceState(null, "", location.pathname);
    try { await importarEnlace(h); } catch (e) { toast(e.message, 5000); }
  });
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
})();
