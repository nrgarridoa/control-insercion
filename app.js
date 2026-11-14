/* Control de Inserción · PWA de campo (QAQC Drillholes)
 * Etapa 1: GEO = LAB (solo muestras preparadas; los controles MB/MC no pasan por preparación).
 * Etapa 2: barrido en el orden de la guía; se leen juntas la LAB de la bolsita y la del sobre
 *          (mismo número y las dos dicen LAB: las GEO no se envían al laboratorio).
 * Todo se guarda en el teléfono (IndexedDB). Al terminar se exporta un CSV que se importa en la plataforma.
 * El despacho llega en un enlace #g= que genera la plataforma (ver backend ddh_insercion/guia.py).
 */
"use strict";
const VERSION = "1.2.0";
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
    const fd = await dialogo(`<h3>Clave del enlace</h3>${error ? `<div class="sub" style="color:#B42318">${esc(error)}</div>` : ""}
      <label>La clave que acompaña a este enlace (p. ej. K7M4-QX9P)</label>
      <input name="c" required autofocus autocomplete="off" autocapitalize="characters" spellcheck="false" style="text-transform:uppercase;letter-spacing:.12em;font-family:monospace;font-size:20px">
      <div class="fila" style="margin-top:16px"><button class="big lin" value="no" formnovalidate>Cancelar</button><button class="big pri" value="ok">Abrir</button></div>`);
    if (!fd) throw new Error("Se necesita la clave del enlace para abrirlo");
    try { return await descifrar(bytes, tipo, String(fd.get("c") || "")); }
    catch (e) { if (/versión/.test(e.message)) throw e; error = "Clave incorrecta"; }
  }
}

async function decodificar(token, cifrado = false) {
  const bytes = cifrado ? await abrirCifrado(b64u(token), "g") : b64u(token);
  const lineas = (await inflar(bytes)).split("\n");
  const [ver, despacho, sondaje, tipos, base, n] = lineas[0].split("|");
  if (ver !== "I1") throw new Error("Enlace de una versión que esta app no conoce. Actualiza la app.");
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
  return { despacho, sondaje, muestras, cargado: ahora() };
}

/* ------------------------------------------------------------------ estado */
const S = { desp: null, lect: [], idx: new Map(), pant: "inicio", usuario: "", camara: null };
try { S.usuario = localStorage.getItem("usuario") || ""; } catch { /* sin almacenamiento */ }

function indexar() {
  S.idx = new Map(S.desp.muestras.map(m => [m.n, m]));
}
function lecturasDe(etapa) { return S.lect.filter(l => l.etapa === etapa); }
function ultima(etapa, muestra) {
  let u = null;
  for (const l of S.lect) if (l.etapa === etapa && l.muestra === muestra && (!u || l.ts > u.ts)) u = l;
  return u;
}
function conforme(etapa, muestra) { const u = ultima(etapa, muestra); return !!u && u.resultado === "conforme"; }
function resumen() {
  const M = S.desp.muestras, prep = M.filter(m => !m.ctrl);
  const e1 = prep.filter(m => conforme(1, m.n)).length, e2 = M.filter(m => conforme(2, m.n)).length;
  const alertas = S.lect.filter(l => l.resultado === "alerta" || l.metodo === "manual");
  const sinExp = S.lect.filter(l => !l.exportado).length;
  return { n: M.length, n1: prep.length, e1, e2, alertas, sinExp };
}
function siguienteE1() { return S.desp.muestras.find(m => !m.ctrl && !ultima(1, m.n)) || null; }
function siguienteE2() {
  // despues de la ultima muestra leida en el barrido (en el orden de la guia)
  let max = 0;
  for (const l of lecturasDe(2)) { const m = S.idx.get(l.muestra); if (m && m.o > max) max = m.o; }
  return S.desp.muestras.find(m => m.o > max && !ultima(2, m.n)) || S.desp.muestras.find(m => !ultima(2, m.n)) || null;
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
  if (etapa === 2) prepararOcr()?.catch(() => toast("No se pudo cargar el lector de texto: se preguntará LAB/GEO", 4000));
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
function cerrarCamara() {
  if (S.scan) S.scan.on = false;
  S.stream?.getTracks().forEach(t => t.stop()); S.stream = null;
  S.pant = "inicio"; render();
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
    if (!cods.length) { pista(S.etapa === 1 ? "Encuadra la GEO y la LAB juntas" : "Encuadra la LAB de la bolsita y la del sobre"); marco(false); }
    else if (cods.length === 1) {
      marco(false);
      pista(S.etapa === 1 ? "Solo se ve una etiqueta: acerca la otra" : "Solo se ve una etiqueta LAB: acerca la bolsita al sobre",
        Date.now() - sc.desde > 1500 ? "wa" : "");
    } else if (cods.length > 2) { marco(false); pista("Hay más de dos etiquetas: deja solo las de esta muestra", "wa"); }
    else if (sc.veces >= 3) { marco(true); await decidir(cods, c, "camara"); sc.clave = ""; sc.veces = 0; }
    else { marco(true); pista("Leyendo…"); }
  } catch (e) {
    pista("Error del lector: " + (e.message || e), "wa");
  } finally { sc.ocupado = false; }
  if (S.scan?.on) setTimeout(bucle, 110);
}

/* ------------------------------------------------------------------ reglas de cada etapa */
async function decidir(cods, canvas, metodo, manual = {}) {
  const [a, b] = cods.map(x => x.text);
  if (S.etapa === 1) return decidirE1(a, b, metodo);
  let t1 = manual.t1 || "?", t2 = manual.t2 || "?";
  if (metodo === "camara" && a === b) {
    pista("Leyendo el texto de las etiquetas…");
    if (!ocr && ocrCargando) { try { await ocrCargando; } catch { /* */ } }
    [t1, t2] = await Promise.all([palabra(canvas, cods[0].pos), palabra(canvas, cods[1].pos)]);
  }
  return decidirE2(a, b, t1, t2, metodo);
}

async function decidirE1(a, b, metodo) {
  const m = S.idx.get(a) || S.idx.get(b);
  const extra = { codigo_1: a, codigo_2: b, metodo };
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
  d.showModal();
  return new Promise(res => { d.onclose = () => res(d.returnValue === "ok" ? new FormData(f) : null); });
}
async function pedirUsuario() {
  const fd = await dialogo(`<h3>¿Quién valida?</h3><label>Tu nombre</label><input type="text" name="u" value="${esc(S.usuario)}" required autofocus>
    <div class="fila" style="margin-top:16px"><button class="big lin" value="no" formnovalidate>Cancelar</button><button class="big pri" value="ok">Guardar</button></div>`);
  if (fd) { S.usuario = String(fd.get("u") || "").trim(); try { localStorage.setItem("usuario", S.usuario); } catch { /* */ } render(); }
}
async function ingresoManual() {
  const e1 = S.etapa === 1;
  const esp = e1 ? siguienteE1() : siguienteE2();
  S.scan && (S.scan.on = false);
  const fd = await dialogo(`<h3>Ingreso manual · etapa ${S.etapa}</h3>
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
async function exportar() {
  if (!S.lect.length) { toast("Todavía no hay lecturas en este despacho"); return; }
  const q = v => { const s = String(v ?? ""); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const csv = "﻿" + COLUMNAS.join(",") + "\n" + [...S.lect].sort((x, y) => x.ts.localeCompare(y.ts))
    .map(l => COLUMNAS.map(c => q(l[c])).join(",")).join("\n");
  const nombre = `Insercion_${S.desp.despacho}_${new Date().toISOString().slice(0, 10)}.csv`;
  const file = new File([csv], nombre, { type: "text/csv" });
  let ok = false;
  if (navigator.canShare && navigator.canShare({ files: [file] })) {
    try { await navigator.share({ files: [file], title: nombre }); ok = true; } catch (e) { if (e.name === "AbortError") return; }
  }
  if (!ok) { const a = document.createElement("a"); a.href = URL.createObjectURL(file); a.download = nombre; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 4000); }
  for (const l of S.lect) if (!l.exportado) { l.exportado = true; await idb.put("lecturas", l); }
  toast("CSV exportado: " + nombre, 3500); render();
}

/* ------------------------------------------------------------------ cargar despacho desde el enlace */
async function importarEnlace(texto) {
  const m = String(texto).match(/#(gc?)=([\w-]+)/);
  if (!m) throw new Error("El enlace no es de un despacho del Control de Inserción");
  const d = await decodificar(m[2], m[1] === "gc");
  const previo = await idb.get("despachos", d.despacho);
  if (previo && previo.muestras.length !== d.muestras.length) {
    if (!confirm(`El despacho ${d.despacho} ya estaba en el teléfono con otra guía. ¿Reemplazar la guía? (las lecturas se conservan)`)) return;
  }
  await idb.put("despachos", d);
  await cargarDespacho(d.despacho);
  S.pant = "inicio"; render();
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
function cab(titulo) {
  if (!S.desp) return `<div class="cab"><small>QAQC · Drillholes</small><b>${esc(titulo)}</b></div>`;
  const r = resumen();
  return `<div class="cab"><small>Despacho ${esc(S.desp.despacho)} · ${esc(S.desp.sondaje || "")}</small><b>${esc(titulo)}</b>
    <div class="lin"><span>E1 ${n0(r.e1)}/${n0(r.n1)}</span><span>E2 ${n0(r.e2)}/${n0(r.n)}</span><span>${n0(r.alertas.length)} alertas</span></div></div>`;
}
async function pInicio() {
  const lista = (await idb.all("despachos")).sort((a, b) => b.cargado.localeCompare(a.cargado));
  if (!S.desp) {
    return cab("Control de Inserción") + `<div class="cuerpo">
      <div class="card"><div class="vacio">Abre en este teléfono el <b>enlace del despacho</b> que te envían desde la plataforma, o pégalo aquí.</div>
        <button class="big pri" data-a="pegar">Pegar enlace del despacho</button></div>
      ${lista.length ? `<div class="card"><h4>Despachos en el teléfono</h4>${lista.map(d => `<div class="desp"><div class="t"><b>${esc(d.despacho)}</b><small>${esc(d.sondaje || "")} · ${n0(d.muestras.length)} muestras</small></div><button data-a="abrir" data-d="${esc(d.despacho)}">Abrir</button></div>`).join("")}</div>` : ""}
      ${pie()}</div>`;
  }
  const r = resumen();
  const p1 = r.n1 ? Math.round(100 * r.e1 / r.n1) : 0, p2 = r.n ? Math.round(100 * r.e2 / r.n) : 0;
  const al1 = r.alertas.filter(l => l.etapa === 1).length, al2 = r.alertas.filter(l => l.etapa === 2).length;
  const c = {}; S.desp.muestras.forEach(m => { c[m.tipo] = (c[m.tipo] || 0) + 1; });
  return cab("Control de Inserción") + `<div class="cuerpo">
    <div class="card"><h4>Guía cargada</h4><div class="sub">${n0(r.n)} muestras · ${n0(r.n1)} preparadas · ${n0(r.n - r.n1)} controles</div></div>
    <div class="card"><h4>Etapa 1 · GEO = LAB</h4><div class="prog"><i style="width:${p1}%"></i></div>
      <div class="sub">${n0(r.e1)} de ${n0(r.n1)} muestras preparadas · ${al1} alertas</div>
      <button class="big pri" data-a="e1">${r.e1 ? "Continuar" : "Iniciar"} etapa 1</button></div>
    <div class="card"><h4>Etapa 2 · Barrido (bolsita y sobre)</h4><div class="prog"><i style="width:${p2}%"></i></div>
      <div class="sub">${n0(r.e2)} de ${n0(r.n)} · ${al2} alertas</div>
      <button class="big ${r.e1 ? "pri" : "lin"}" data-a="e2">${r.e2 ? "Continuar" : "Iniciar"} barrido</button></div>
    <div class="card"><h4>Cierre</h4><button class="big sc" data-a="resumen">Ver resumen y exportar</button>
      <div class="envio"><span class="punto" style="background:${r.sinExp ? "#8A5A00" : "#17633A"}"></span>${r.sinExp ? `${n0(r.sinExp)} lecturas sin exportar` : (S.lect.length ? "Todo exportado" : "Sin lecturas")} · guardado en el teléfono</div></div>
    <div class="card"><h4>Otros despachos</h4>${lista.filter(d => d.despacho !== S.desp.despacho).map(d => `<div class="desp"><div class="t"><b>${esc(d.despacho)}</b><small>${esc(d.sondaje || "")} · ${n0(d.muestras.length)} muestras</small></div><button data-a="abrir" data-d="${esc(d.despacho)}">Abrir</button></div>`).join("") || '<div class="sub">Ninguno</div>'}
      <button class="big lin" data-a="pegar">Pegar enlace de otro despacho</button></div>
    ${pie()}</div>`;
}
function pie() {
  return `<div class="sub" style="text-align:center;margin:6px 0 20px">${S.usuario ? `Valida: <b>${esc(S.usuario)}</b> · ` : ""}<a href="#" data-a="usuario">${S.usuario ? "cambiar" : "indica tu nombre"}</a> · v${VERSION}</div>`;
}
function pResumen() {
  const r = resumen();
  const f1 = S.desp.muestras.filter(m => !m.ctrl && !conforme(1, m.n)), f2 = S.desp.muestras.filter(m => !conforme(2, m.n));
  const lineas = r.alertas.slice().sort((a, b) => b.ts.localeCompare(a.ts)).map(l =>
    `<div><span><b>E${l.etapa}</b> <span class="mono">${esc(l.muestra)}</span></span><span class="${l.metodo === "manual" || l.alerta === "fuera_orden" ? "a" : "r"}">${esc(l.resultado === "alerta" ? ALERTA_TXT[l.alerta] || l.alerta : "Ingreso manual")}</span></div>`).join("");
  const falt = (arr, e) => arr.length ? `<div class="card"><h4>Pendientes en la etapa ${e} (${n0(arr.length)})</h4><div class="lista">${arr.slice(0, 40).map(m => `<div><span class="mono">${esc(m.n)}</span><span class="sub">${esc(m.tipo)}</span></div>`).join("")}${arr.length > 40 ? `<div><span class="sub">… y ${n0(arr.length - 40)} más</span></div>` : ""}</div></div>` : "";
  return cab("Resumen") + `<div class="cuerpo">
    <div class="card"><h4>Resultado</h4><div class="cont3"><div><b>${n0(r.e1)}/${n0(r.n1)}</b><span>Etapa 1</span></div><div><b>${n0(r.e2)}/${n0(r.n)}</b><span>Etapa 2</span></div><div><b style="color:${r.alertas.length ? "#B42318" : "#17633A"}">${n0(r.alertas.length)}</b><span>alertas</span></div></div></div>
    <div class="card"><h4>Alertas</h4><div class="lista">${lineas || '<div><span class="sub">Sin alertas</span></div>'}</div></div>
    ${falt(f1, 1)}${falt(f2, 2)}
    <button class="big ok" data-a="exportar">Exportar CSV</button>
    <div class="envio" style="justify-content:center">${r.sinExp ? `${n0(r.sinExp)} lecturas sin exportar` : "Todo exportado"}</div>
    <button class="big lin" data-a="inicio">Volver</button>
    <button class="big lin" data-a="borrar" style="color:#B42318;margin-bottom:24px">Quitar este despacho del teléfono</button></div>`;
}
function pCamara() {
  const e1 = S.etapa === 1, m = e1 ? siguienteE1() : siguienteE2();
  return `<div class="cam"><video id="video" playsinline muted></video><div class="marco" id="marco"></div>
    <div class="arriba"><small>Despacho ${esc(S.desp.despacho)} · Etapa ${S.etapa}</small><b>${e1 ? "GEO = LAB" : "Barrido · bolsita y sobre"}</b>
      <div class="tip" id="tip">${e1 ? "Encuadra la GEO y la LAB juntas" : "Encuadra la LAB de la bolsita y la del sobre"}</div></div>
    <div class="abajo"><div class="esperada">${m ? `Siguiente en la guía<b class="mono">${esc(m.n)}</b>${esc(m.tipo)} · ${tramo(m)}` : "<b>Etapa completa</b>"}</div>
      <div class="botones"><button data-a="cerrar">Pausar</button><button data-a="manual">Ingreso manual</button><button class="icono" data-a="luz" title="Linterna">💡</button></div></div></div>`;
}
async function render() {
  const app = $("#app");
  if (S.pant === "camara") {
    if (!$("#video")) app.innerHTML = pCamara();
    else { const e = document.querySelector(".esperada"); const m = S.etapa === 1 ? siguienteE1() : siguienteE2();
      if (e) e.innerHTML = m ? `Siguiente en la guía<b class="mono">${esc(m.n)}</b>${esc(m.tipo)} · ${tramo(m)}` : "<b>Etapa completa</b>"; }
    return;
  }
  app.innerHTML = S.pant === "resumen" && S.desp ? pResumen() : await pInicio();
}

document.addEventListener("click", async e => {
  const b = e.target.closest("[data-a]"); if (!b) return;
  e.preventDefault();
  const a = b.dataset.a;
  try { audio = audio || new (window.AudioContext || window.webkitAudioContext)(); audio.resume?.(); } catch { /* */ }
  if (a === "pegar") pegarEnlace();
  else if (a === "abrir") { await cargarDespacho(b.dataset.d); S.pant = "inicio"; render(); }
  else if (a === "e1") abrirCamara(1);
  else if (a === "e2") abrirCamara(2);
  else if (a === "cerrar") cerrarCamara();
  else if (a === "manual") ingresoManual();
  else if (a === "luz") linterna();
  else if (a === "resumen") { S.pant = "resumen"; render(); }
  else if (a === "inicio") { S.pant = "inicio"; render(); }
  else if (a === "exportar") exportar();
  else if (a === "usuario") pedirUsuario();
  else if (a === "borrar") {
    const r = resumen();
    if (!confirm(`¿Quitar el despacho ${S.desp.despacho} del teléfono?${r.sinExp ? ` Hay ${r.sinExp} lecturas sin exportar.` : ""}`)) return;
    for (const l of S.lect) await idb.del("lecturas", l.uuid);
    await idb.del("despachos", S.desp.despacho);
    S.desp = null; S.lect = []; S.pant = "inicio"; render();
  }
});

/* ------------------------------------------------------------------ inicio */
(async function iniciar() {
  await idb.abrir();
  try { await navigator.storage?.persist?.(); } catch { /* */ }
  if (/#gc?=/.test(location.hash)) {
    try { await importarEnlace(location.href); } catch (e) { toast(e.message, 5000); }
    history.replaceState(null, "", location.pathname);
  } else {
    let ult = ""; try { ult = localStorage.getItem("despacho") || ""; } catch { /* */ }
    if (ult) await cargarDespacho(ult);
  }
  render();
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
})();
