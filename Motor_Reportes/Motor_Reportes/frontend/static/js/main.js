/* eslint-env browser */
"use strict";

let archivoSeleccionado = null;
let reglasFirewallActuales = [];

// ── Carga de archivo y preview ──────────────────────────────────────────────
document.getElementById("fileUpload").addEventListener("change", function (e) {
    const file = e.target.files[0];
    const zona = document.getElementById("zonaArchivo");
    const zonaNotif = document.getElementById("zonaArchivoNombre");

    if (!file) {
        archivoSeleccionado = null;
        zona.classList.remove("activa");
        zonaNotif.style.display = "none";
        document.getElementById("panelPreview").style.display = "none";
        return;
    }

    archivoSeleccionado = file;
    zona.classList.add("activa");
    zonaNotif.style.display = "flex";
    zonaNotif.textContent = "✓  " + file.name;

    const reader = new FileReader();
    reader.onload = function (ev) {
        mostrarPreview(file.name, ev.target.result);
    };
    reader.readAsText(file);
});

function mostrarPreview(nombre, contenido) {
    const panelPreview = document.getElementById("panelPreview");
    const thead = document.getElementById("theadPreview");
    const tbody = document.getElementById("tbodyPreview");
    thead.innerHTML = "";
    tbody.innerHTML = "";

    let filas = [];
    let cabeceras = [];

    if (nombre.toLowerCase().endsWith(".json")) {
        try {
            const datos = JSON.parse(contenido);
            const lista = Array.isArray(datos) ? datos : (datos.filas || []);
            if (lista.length > 0) {
                cabeceras = Object.keys(lista[0]);
                filas = lista;
            }
        } catch (_) {
            panelPreview.style.display = "none";
            return;
        }
    } else {
        const lineas = contenido.split("\n").filter(function (l) { return l.trim(); });
        if (lineas.length < 2) { panelPreview.style.display = "none"; return; }
        cabeceras = lineas[0].split(",").map(function (c) { return c.trim(); });
        for (let i = 1; i <= lineas.length - 1; i++) {
            const vals = lineas[i].split(",").map(function (v) { return v.trim(); });
            const obj = {};
            cabeceras.forEach(function (h, idx) { obj[h] = vals[idx] || ""; });
            filas.push(obj);
        }
    }

    if (cabeceras.length === 0) { panelPreview.style.display = "none"; return; }

    const totalFilas = filas.length;
    const labelEl = document.getElementById("labelPreview");
    if (labelEl) {
        panelPreview.removeEventListener("toggle", panelPreview._toggleHandler);
        panelPreview._toggleHandler = function () {
            labelEl.textContent = (panelPreview.open ? "▼" : "▶") + " Vista Previa (" + totalFilas + " registros)";
        };
        panelPreview.addEventListener("toggle", panelPreview._toggleHandler);
        labelEl.textContent = "▶ Vista Previa (" + totalFilas + " registros)";
    }

    const trHead = document.createElement("tr");
    cabeceras.forEach(function (h) {
        const th = document.createElement("th");
        th.textContent = h;
        trHead.appendChild(th);
    });
    thead.appendChild(trHead);

    filas.forEach(function (fila) {
        const tr = document.createElement("tr");
        cabeceras.forEach(function (h) {
            const td = document.createElement("td");
            td.textContent = fila[h] !== undefined ? fila[h] : "";
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });

    panelPreview.style.display = "block";
}

// ── Análisis principal ────────────────────────────────────────────────────────
async function procesarMotor() {
    if (!archivoSeleccionado) {
        alert("Por favor selecciona un archivo CSV o JSON antes de analizar.");
        return;
    }

    const btn = document.getElementById("btnProcesar");
    btn.textContent = "Analizando...";
    btn.disabled = true;

    try {
        const formData = new FormData();
        formData.append("archivo", archivoSeleccionado);

        const resp = await fetch("/analizar", { method: "POST", body: formData });
        const resultado = await resp.json();

        if (!resp.ok) {
            alert("Error del servidor: " + (resultado.error || resp.status));
            return;
        }

        renderizarIngesta(resultado.ingesta);
        renderizarTokens(resultado.tokens);
        renderizarRegexTeorico(resultado.regex_teorico || []);
        renderizarArbol(resultado.estructura);
        renderizarSemantica(resultado.analisis_semantico);
        if (typeof actualizarAFDParaAtaque === "function") {
            actualizarAFDParaAtaque(resultado.analisis_semantico.tipo_ataque || "SIN_ATAQUE");
        }
        renderizarFuentes(resultado.fuentes_top || []);
        renderizarMitigacion(resultado.acciones_mitigacion, resultado.reglas_firewall);
        await enviarNotificacionAutomatica(resultado);

    } catch (err) {
        console.error(err);
        alert("Error de red o respuesta inesperada del servidor.");
    } finally {
        btn.textContent = "Analizar Tráfico";
        btn.disabled = false;
    }
}

// ── Renderizadores ────────────────────────────────────────────────────────────
function renderizarIngesta(ingesta) {
    if (!ingesta) return;
    const el = document.getElementById("outIngesta");
    const lineas = [
        "Filas totales:      " + ingesta.filas_totales,
        "Filas válidas:      " + ingesta.filas_validas,
        "Filas descartadas:  " + ingesta.filas_descartadas,
    ];
    const motivos = ingesta.motivos_descarte || {};
    Object.keys(motivos).forEach(function (k) {
        lineas.push("  " + k + ": " + motivos[k]);
    });
    el.textContent = lineas.join("\n");
    document.getElementById("panelIngesta").style.display = "block";
}

function renderizarTokens(tokens) {
    if (!tokens) return;
    const tbody = document.getElementById("outTokens");
    const etiquetas = {
        flow_records: "FLOW_RECORD",
        syn_solo: "SYN_SOLO",
        puerto_amplificador_origen: "PUERTO_AMPLIFICADOR",
        icmp_flood_candidato: "ICMP_FLOOD_CANDIDATO",
        http_request_alta_frecuencia: "HTTP_HIGH_FREQ",
    };

    const fragmento = document.createDocumentFragment();
    Object.keys(etiquetas).forEach(function (k) {
        const tr = document.createElement("tr");
        const td1 = document.createElement("td");
        td1.style.cssText = "color:#fca5a5;font-weight:bold;";
        td1.textContent = etiquetas[k];
        const td2 = document.createElement("td");
        td2.style.cssText = "color:#38bdf8;font-family:monospace;";
        td2.textContent = tokens[k] !== undefined ? tokens[k] : 0;
        tr.appendChild(td1);
        tr.appendChild(td2);
        fragmento.appendChild(tr);
    });
    tbody.innerHTML = "";
    tbody.appendChild(fragmento);
}

function renderizarRegexTeorico(reglas) {
    const panel = document.getElementById("panelRegexTeorico");
    const tbody = document.getElementById("tbodyRegexTeorico");
    tbody.innerHTML = "";
    if (!reglas || reglas.length === 0) { panel.style.display = "none"; return; }
    const frag = document.createDocumentFragment();
    reglas.forEach(function (r) {
        const tr = document.createElement("tr");
        [esc(r.token), esc(r.patron), esc(r.ejemplo)].forEach(function (val) {
            const td = document.createElement("td");
            td.style.cssText = "font-family:monospace;font-size:12px;";
            td.textContent = val;
            tr.appendChild(td);
        });
        frag.appendChild(tr);
    });
    tbody.appendChild(frag);
    panel.style.display = "block";
}

function renderizarArbol(estructura) {
    if (!estructura) return;
    const ast = estructura.arbol_sintactico;
    const divArbol = document.getElementById("outArbol");

    function generarNodo(nodo) {
        const li = document.createElement("li");
        if (typeof nodo === "string") {
            const span = document.createElement("span");
            span.className = "hoja";
            span.textContent = nodo;
            li.appendChild(span);
            return li;
        }
        const span = document.createElement("span");
        span.className = "nodo-padre";
        span.textContent = nodo.etiqueta || "";
        li.appendChild(span);
        if (Array.isArray(nodo.hijos) && nodo.hijos.length > 0) {
            const ul = document.createElement("ul");
            nodo.hijos.forEach(function (hijo) {
                ul.appendChild(generarNodo(hijo));
            });
            li.appendChild(ul);
        }
        return li;
    }

    const raizUl = document.createElement("ul");
    raizUl.className = "arbol-sintactico";
    const raizLi = document.createElement("li");
    const raizSpan = document.createElement("span");
    raizSpan.className = "nodo-raiz";
    raizSpan.textContent = ast.raiz || "Sesion_de_Trafico";
    raizLi.appendChild(raizSpan);
    const ramosUl = document.createElement("ul");
    (ast.nodos || []).forEach(function (n) { ramosUl.appendChild(generarNodo(n)); });
    raizLi.appendChild(ramosUl);
    raizUl.appendChild(raizLi);

    divArbol.innerHTML = "";
    divArbol.appendChild(raizUl);
}

function renderizarSemantica(sem) {
    if (!sem) return;

    const lblTipo = document.getElementById("lblTipoAtaque");
    lblTipo.textContent = sem.tipo_ataque || "-";
    lblTipo.className = "badge-ataque " + claseSeveridad(sem.severidad);

    document.getElementById("lblSeveridad").textContent = sem.severidad || "-";
    document.getElementById("lblRegla").textContent = sem.regla_aplicada || "-";

    const obj = sem.objetivo;
    document.getElementById("lblObjetivo").textContent = obj
        ? obj.ip + ":" + obj.puerto + " (" + obj.servicio + ")"
        : "No identificado";

    const grid = document.getElementById("gridMetricas");
    grid.innerHTML = "";
    const metricas = sem.metricas || {};
    const etiquetas = {
        pps_pico: "PPS pico",
        bps_pico_humano: "Ancho de banda",
        fuentes_distintas: "Fuentes únicas",
        duracion_segundos: "Duración (s)",
        ratio_syn_sin_ack: "Ratio SYN/total",
        ratio_amplificacion: "Factor amplif.",
        ratio_icmp: "Ratio ICMP",
    };
    Object.keys(etiquetas).forEach(function (k) {
        if (metricas[k] === undefined) return;
        const div = document.createElement("div");
        div.className = "metrica-item";
        const lbl = document.createElement("span");
        lbl.className = "metrica-label";
        lbl.textContent = etiquetas[k];
        const val = document.createElement("span");
        val.className = "metrica-valor";
        val.textContent = metricas[k];
        div.appendChild(lbl);
        div.appendChild(val);
        grid.appendChild(div);
    });
}

function renderizarFuentes(fuentes) {
    const panel = document.getElementById("panelFuentes");
    const tbody = document.getElementById("tbodyFuentes");
    tbody.innerHTML = "";
    if (!fuentes || fuentes.length === 0) { panel.style.display = "none"; return; }

    const frag = document.createDocumentFragment();
    fuentes.forEach(function (f) {
        const tr = document.createElement("tr");
        [esc(f.ip), f.paquetes, f.porcentaje + "%"].forEach(function (val) {
            const td = document.createElement("td");
            td.textContent = val;
            tr.appendChild(td);
        });
        frag.appendChild(tr);
    });
    tbody.appendChild(frag);
    panel.style.display = "block";
}

function renderizarMitigacion(acciones, reglas) {
    const lista = document.getElementById("listAcciones");
    lista.innerHTML = "";
    const frag = document.createDocumentFragment();
    (acciones || []).forEach(function (accion) {
        const li = document.createElement("li");
        li.textContent = accion;
        frag.appendChild(li);
    });
    lista.appendChild(frag);

    reglasFirewallActuales = reglas || [];
    const divReglas = document.getElementById("outReglas");
    if (reglasFirewallActuales.length === 0) {
        divReglas.textContent = "Sin reglas generadas.";
        document.getElementById("btnCopiarReglas").style.display = "none";
        return;
    }
    divReglas.textContent = JSON.stringify(reglasFirewallActuales, null, 2);
    document.getElementById("btnCopiarReglas").style.display = "inline-block";
}

// ── Utilidades ────────────────────────────────────────────────────────────────
function esc(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function claseSeveridad(sev) {
    const mapa = { CRITICA: "sev-critica", ALTA: "sev-alta", MEDIA: "sev-media", BAJA: "sev-baja" };
    return mapa[sev] || "";
}

function copiarReglas() {
    const texto = JSON.stringify(reglasFirewallActuales, null, 2);
    navigator.clipboard.writeText(texto).then(function () {
        const btn = document.getElementById("btnCopiarReglas");
        const original = btn.textContent;
        btn.textContent = "¡Copiado!";
        setTimeout(function () { btn.textContent = original; }, 2000);
    });
}

// ── Notificación automática ────────────────────────────────────────────────────
async function enviarNotificacionAutomatica(resultado) {
    const correo = document.getElementById("inpCorreo").value.trim();
    const estadoEl = document.getElementById("estadoNotificacion");

    if (!correo) return;

    estadoEl.style.color = "#94a3b8";
    estadoEl.textContent = "Enviando reporte por correo...";

    try {
        const resp = await fetch("/notificar", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ correo, resultado }),
        });
        const res = await resp.json();
        estadoEl.style.color = res.status === "success" ? "#10b981" : "#fca5a5";
        estadoEl.textContent = res.message || "Respuesta desconocida.";
    } catch (err) {
        estadoEl.style.color = "#fca5a5";
        estadoEl.textContent = "Error de red al enviar notificación.";
    }
}
