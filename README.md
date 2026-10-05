# Portal RRPP

Web app sin dependencias (solo Node 22.5+). Cada persona entra con usuario y contraseña.

## Roles
- **RRPP**: carga su lista (uno por uno o pegando muchos: `Nombre, DNI, x3` / `Nombre +2`), edita/borra mientras no haya ingresado y la carga esté abierta. Ve el tablero.
- **Recepción**: busca por nombre/DNI/RRPP, marca "Ingresó" (con cantidad si vienen acompañantes), deshace, y registra gente sin lista.
- **Admin**: ve y edita todo, carga listas por un RRPP, crea usuarios, cambia claves, administra eventos (% de asistencia esperado, capacidad, abrir/cerrar listas) y descarga CSV.
- **Tablero unificado** (todos): En lista · Esperamos · Ingresaron, y detalle por RRPP.

## Cómo se calcula "Esperamos"
Por RRPP: asistencia histórica (ingresaron / lista en otros eventos, si hay ≥20 personas de historial) o, si no, el % del evento (65% por defecto). Esperados = máx(ingresaron, lista × %) + gente sin lista.

## Correr
```
ADMIN_PASSWORD=unaClaveFuerte node server.js
```
Variables: `PORT` (3000), `DB_PATH` (./data/portal.db), `ADMIN_USER` (admin), `ADMIN_PASSWORD` (si falta, se genera y se imprime en consola), `COOKIE_SECURE=1` (detrás de https).

## Publicar
Subilo a un hosting que corra Node 22+ (Render, Railway, Fly.io…), con **disco persistente** para `DB_PATH` y HTTPS. Hacé copia periódica de `data/portal.db`.

## Límites
Un solo servidor, SQLite, actualización por consulta cada 5–8 s (no websockets), sin recuperación de clave por mail (el admin la resetea).
