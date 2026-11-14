# Control de Inserción · app de campo (PWA)

App web instalable para validar en el laboratorio de QAQC la inserción y el ensobrado de las muestras de un
despacho, según su guía de inserción. Funciona en Android y iPhone desde el navegador, sin instalar APK, y sin
señal una vez abierta.

## Cómo se usa
1. En la plataforma (QAQC › Drillholes › Control de Inserción) se carga la guía en PDF y se comparte el
   **enlace del despacho**. Al abrirlo en el celular, la app carga el despacho completo y lo guarda.
2. **Etapa 1 · GEO = LAB:** se encuadran juntas la etiqueta GEO y la LAB de cada muestra preparada. Los
   controles MB/MC no pasan por esta etapa.
3. **Etapa 2 · Barrido:** en el orden de la guía, se encuadran juntas la LAB de la bolsita y la del sobre.
   Deben tener el mismo número y las dos deben decir LAB: las GEO no se envían al laboratorio.
4. **Exportar CSV** y subirlo a la plataforma (Importar validación).

Cada lectura queda guardada en el teléfono al instante (IndexedDB) y tiene un identificador único, así que
reimportar el mismo archivo no duplica nada.

## Técnica
- Códigos de barras: [zxing-wasm](https://github.com/Sec-ant/zxing-wasm) (MIT), varias etiquetas por imagen.
- Palabra LAB/GEO junto al código: [tesseract.js](https://github.com/naptha/tesseract.js) (Apache-2.0) con
  el modelo `eng` (best_int). Si no se distingue, la app lo pregunta.
- Todo va en `vendor/` y queda en la caché del service worker (unos 16 MB), sin depender de internet.
- Formato del enlace: ver `backend/app/modules/ddh_insercion/guia.py` en la plataforma. Los datos van después
  del `#`, que el navegador no envía a ningún servidor. La plataforma los entrega cifrados (`#gc=`, AES-256-GCM
  con clave PBKDF2-SHA256 de la clave de campo, ver `backend/app/core/cifrado_campo.py`): la app pide la clave
  la primera vez y puede recordarla en el teléfono. Este repositorio no contiene datos.

Requiere HTTPS (la cámara solo funciona en un sitio seguro). Al publicar una versión nueva, subir
`CACHE` en `sw.js` y `VERSION` en `app.js`.
