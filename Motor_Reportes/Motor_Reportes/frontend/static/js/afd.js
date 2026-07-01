"use strict";
/* ═══════════════════════════════════════════════════
   AFD — Autómata Finito Determinista
   Analizador Léxico de Tráfico DDoS
   ═══════════════════════════════════════════════════ */

const AFD_R = 30;
const NS = "http://www.w3.org/2000/svg";

const AFD_ESTADOS = {
  q0:   { x:115, y:320, label:"q0",   sub:"inicio",      tipo:"inicio",
          desc:"Estado inicial — lee el campo 'protocol' del registro de tráfico entrante." },
  q1:   { x:325, y:190, label:"q1",   sub:"tcp",          tipo:"normal",
          desc:"Protocolo TCP confirmado. Evalúa flags TCP y puerto destino para clasificar el token." },
  q2:   { x:325, y:345, label:"q2",   sub:"udp",          tipo:"normal",
          desc:"Protocolo UDP confirmado. Verifica si el puerto origen es un reflector de amplificación." },
  q3:   { x:325, y:500, label:"q3",   sub:"icmp",         tipo:"normal",
          desc:"Protocolo ICMP detectado — candidato directo a ICMP_FLOOD_CANDIDATO." },
  q4:   { x:560, y:90,  label:"q4",   sub:"syn_solo",     tipo:"normal",
          desc:"TCP con flag SYN y sin ACK — candidato a SYN Flood. Emite token SYN_SOLO." },
  q5:   { x:560, y:500, label:"q5",   sub:"puerto_amp",   tipo:"normal",
          desc:"UDP desde puerto amplificador conocido (53, 123, 389, 161…). Emite PUERTO_AMPLIFICADOR." },
  q6:   { x:560, y:255, label:"q6",   sub:"http_freq",    tipo:"normal",
          desc:"TCP hacia puerto 80 o 443 con alta frecuencia desde la misma IP. Emite HTTP_HIGH_FREQ." },
  qT:   { x:780, y:305, label:"qT",   sub:"token ✓",      tipo:"aceptacion",
          desc:"Estado de aceptación — el token ha sido clasificado y se añade a la lista léxica." },
  qERR: { x:115, y:530, label:"qERR", sub:"error",        tipo:"error",
          desc:"Protocolo desconocido — la fila es descartada. Se incrementa el contador de errores." },
};

const AFD_TRANSICIONES = [
  { de:"q0",   a:"q1",   et:"TCP",         curva:0   },
  { de:"q0",   a:"q2",   et:"UDP",         curva:0   },
  { de:"q0",   a:"q3",   et:"ICMP",        curva:0   },
  { de:"q0",   a:"qERR", et:"otro",         curva:0   },
  { de:"q1",   a:"q4",   et:"SYN ∧ ¬ACK", curva:0   },
  { de:"q1",   a:"q6",   et:"p∈{80,443}",  curva:0   },
  { de:"q1",   a:"qT",   et:"TCP otros",   curva:-95 },
  { de:"q2",   a:"q5",   et:"p∈amp",       curva:0   },
  { de:"q2",   a:"qT",   et:"UDP otros",   curva:0   },
  { de:"q3",   a:"qT",   et:"ICMP_FLOOD",  curva:0   },
  { de:"q4",   a:"qT",   et:"SYN_SOLO",    curva:0   },
  { de:"q5",   a:"qT",   et:"PUERTO_AMP",  curva:0   },
  { de:"q6",   a:"qT",   et:"HTTP_FREQ",   curva:0   },
];

const CAMINO_POR_ATAQUE = {
  "SYN_FLOOD":    ["q0","q1","q4","qT"],
  "AMPLIFICACION":["q0","q2","q5","qT"],
  "HTTP_FLOOD":   ["q0","q1","q6","qT"],
  "PING_FLOOD":   ["q0","q3","qT"],
  "VOLUMETRICO":  ["q0","q1","qT"],
  "SIN_ATAQUE":   ["q0"],
};

const TOKEN_POR_PENULTIMO = {
  q3:"ICMP_FLOOD_CANDIDATO", q4:"SYN_SOLO",
  q5:"PUERTO_AMPLIFICADOR",  q6:"HTTP_HIGH_FREQ",
};

const AMP_PORTS = new Set([53,123,389,161,1900,11211,19,17]);

// ── Helpers SVG ──────────────────────────────────────────────────────────────
function mk(tag, attrs) {
  const e = document.createElementNS(NS, tag);
  Object.entries(attrs).forEach(([k,v]) => e.setAttribute(k, v));
  return e;
}

function edgePt(cx, cy, tx, ty, r) {
  const dx=tx-cx, dy=ty-cy, L=Math.sqrt(dx*dx+dy*dy);
  return { x: cx+r*dx/L, y: cy+r*dy/L };
}

function ctrlPt(x1,y1,x2,y2,curva) {
  const mx=(x1+x2)/2, my=(y1+y2)/2;
  const dx=x2-x1, dy=y2-y1, L=Math.sqrt(dx*dx+dy*dy);
  return { x: mx+(-dy/L)*curva, y: my+(dx/L)*curva };
}

function buildPath(xS,yS,xE,yE,curva) {
  if (curva===0) {
    const s=edgePt(xS,yS,xE,yE,AFD_R), e=edgePt(xE,yE,xS,yS,AFD_R);
    return { d:`M${s.x.toFixed(1)} ${s.y.toFixed(1)} L${e.x.toFixed(1)} ${e.y.toFixed(1)}`,
             lx:(s.x+e.x)/2, ly:(s.y+e.y)/2 };
  }
  const cp=ctrlPt(xS,yS,xE,yE,curva);
  const s=edgePt(xS,yS,cp.x,cp.y,AFD_R), e=edgePt(xE,yE,cp.x,cp.y,AFD_R);
  return {
    d:`M${s.x.toFixed(1)} ${s.y.toFixed(1)} Q${cp.x.toFixed(1)} ${cp.y.toFixed(1)} ${e.x.toFixed(1)} ${e.y.toFixed(1)}`,
    lx: 0.25*s.x+0.5*cp.x+0.25*e.x,
    ly: 0.25*s.y+0.5*cp.y+0.25*e.y,
  };
}

// ── Inicialización del SVG ───────────────────────────────────────────────────
function initAFD() {
  const svg = document.getElementById("svgAFD");
  if (!svg) return;
  svg.setAttribute("viewBox","0 0 900 620");
  svg.style.width = "100%";
  svg.style.maxHeight = "620px";

  // Marcadores de flecha
  const defs = mk("defs",{});
  [["arr-gray","#475569"],["arr-blue","#3b82f6"],["arr-green","#10b981"]].forEach(([id,col]) => {
    const m = mk("marker",{ id, markerWidth:"8", markerHeight:"6", refX:"7", refY:"3", orient:"auto" });
    m.appendChild(mk("polygon",{ points:"0 0,8 3,0 6", fill:col }));
    defs.appendChild(m);
  });
  svg.appendChild(defs);

  // Transiciones (detrás de los estados)
  const gT = mk("g",{ id:"afd-g-trans" });
  AFD_TRANSICIONES.forEach(tr => {
    const s=AFD_ESTADOS[tr.de], e=AFD_ESTADOS[tr.a];
    const { d, lx, ly } = buildPath(s.x,s.y,e.x,e.y,tr.curva);
    gT.appendChild(mk("path",{
      id:`afd-tr-${tr.de}-${tr.a}`, d,
      fill:"none", stroke:"#2d3f55", "stroke-width":"1.5",
      "marker-end":"url(#arr-gray)"
    }));
    const tl = mk("text",{
      id:`afd-tl-${tr.de}-${tr.a}`,
      x:lx.toFixed(1), y:(ly-8).toFixed(1),
      "text-anchor":"middle", "font-size":"16",
      fill:"#90adc4", "font-family":"'Courier New',monospace"
    });
    tl.textContent = tr.et;
    gT.appendChild(tl);
  });
  svg.appendChild(gT);

  // Flecha de entrada al estado inicial
  const q0 = AFD_ESTADOS["q0"];
  svg.appendChild(mk("line",{
    x1:q0.x-65, y1:q0.y, x2:q0.x-AFD_R-1, y2:q0.y,
    stroke:"#3b82f6", "stroke-width":"2", "marker-end":"url(#arr-blue)"
  }));

  // Estados
  const gS = mk("g",{ id:"afd-g-estados" });
  Object.entries(AFD_ESTADOS).forEach(([id,est]) => {
    const g = mk("g",{ id:`afd-est-${id}`, cursor:"pointer" });
    const baseStroke = est.tipo==="error" ? "#ef4444"
                     : est.tipo==="aceptacion" ? "#3b82f6" : "#334155";

    g.appendChild(mk("circle",{
      id:`afd-circ-${id}`, cx:est.x, cy:est.y, r:AFD_R,
      fill:"#0f172a", stroke:baseStroke, "stroke-width":"1.8",
      "stroke-dasharray": est.tipo==="error" ? "5,3" : "none"
    }));

    // Doble anillo para el estado de aceptación
    if (est.tipo==="aceptacion") {
      g.appendChild(mk("circle",{
        cx:est.x, cy:est.y, r:AFD_R-6,
        fill:"none", stroke:"#3b82f6", "stroke-width":"1.5"
      }));
    }

    const lbl = mk("text",{
      x:est.x, y:est.y+5, "text-anchor":"middle",
      "font-size":"16", "font-weight":"bold",
      fill:"#e8f0fe", "font-family":"'Courier New',monospace"
    });
    lbl.textContent = est.label;
    g.appendChild(lbl);

    const sub = mk("text",{
      x:est.x, y:est.y+AFD_R+17, "text-anchor":"middle",
      "font-size":"17", fill:"#7eb8d4", "font-family":"sans-serif"
    });
    sub.textContent = est.sub;
    g.appendChild(sub);

    g.addEventListener("click", () => mostrarInfoEstado(id));
    gS.appendChild(g);
  });
  svg.appendChild(gS);
}

// ── Resaltado de camino ──────────────────────────────────────────────────────
function resetAFD() {
  Object.keys(AFD_ESTADOS).forEach(id => {
    const c = document.getElementById(`afd-circ-${id}`);
    if (!c) return;
    const t = AFD_ESTADOS[id].tipo;
    c.setAttribute("fill","#0f172a");
    c.setAttribute("stroke", t==="error" ? "#ef4444" : t==="aceptacion" ? "#3b82f6" : "#334155");
    c.setAttribute("stroke-width","1.8");
  });
  AFD_TRANSICIONES.forEach(tr => {
    const p = document.getElementById(`afd-tr-${tr.de}-${tr.a}`);
    if (p) { p.setAttribute("stroke","#2d3f55"); p.setAttribute("stroke-width","1.5"); p.setAttribute("marker-end","url(#arr-gray)"); }
    const l = document.getElementById(`afd-tl-${tr.de}-${tr.a}`);
    if (l) l.setAttribute("fill","#4a6180");
  });
  const info = document.getElementById("afd-info-card");
  if (info) info.style.display = "none";
  const res = document.getElementById("simResultado");
  if (res) res.style.display = "none";
}

function destacarCamino(camino) {
  resetAFD();
  camino.forEach(id => {
    const c = document.getElementById(`afd-circ-${id}`);
    if (c) { c.setAttribute("fill","#1e3a5f"); c.setAttribute("stroke","#3b82f6"); c.setAttribute("stroke-width","2.5"); }
  });
  for (let i=0; i<camino.length-1; i++) {
    const p = document.getElementById(`afd-tr-${camino[i]}-${camino[i+1]}`);
    if (p) { p.setAttribute("stroke","#3b82f6"); p.setAttribute("stroke-width","2.5"); p.setAttribute("marker-end","url(#arr-blue)"); }
    const l = document.getElementById(`afd-tl-${camino[i]}-${camino[i+1]}`);
    if (l) l.setAttribute("fill","#93c5fd");
  }
  mostrarInfoEstado(camino[camino.length-1]);
}

function mostrarInfoEstado(id) {
  const est = AFD_ESTADOS[id];
  if (!est) return;
  document.getElementById("afd-info-label").textContent = est.label;
  document.getElementById("afd-info-sub").textContent   = est.sub;
  document.getElementById("afd-info-desc").textContent  = est.desc;
  document.getElementById("afd-info-card").style.display = "block";
}

// ── Simulador ────────────────────────────────────────────────────────────────
function simularFlujoAFD(protocol, flags, dstPort, srcPort) {
  const fset  = new Set((flags||"").split(",").map(f=>f.trim().toUpperCase()).filter(Boolean));
  const proto = (protocol||"").toUpperCase().trim();
  const camino = ["q0"];

  let cur;
  if      (proto==="TCP")  cur="q1";
  else if (proto==="UDP")  cur="q2";
  else if (proto==="ICMP") cur="q3";
  else                     cur="qERR";
  camino.push(cur);

  if (cur==="q1") {
    const isSyn  = fset.has("SYN") && !fset.has("ACK");
    const isHttp = [80,443].includes(Number(dstPort));
    if (isSyn)       camino.push("q4");
    else if (isHttp) camino.push("q6");
  } else if (cur==="q2") {
    if (AMP_PORTS.has(Number(srcPort))) camino.push("q5");
  }

  if (cur !== "qERR") camino.push("qT");
  return camino;
}

function caminoAToken(camino) {
  if (camino.includes("qERR")) return "DESCARTADO";
  const penultimo = camino[camino.length-2];
  return TOKEN_POR_PENULTIMO[penultimo] || "FLOW_RECORD";
}

function ejecutarSimulador() {
  const proto   = document.getElementById("simProtocolo").value;
  const flags   = (document.getElementById("simFlags")   || {}).value || "";
  const dstPort = (document.getElementById("simDstPort") || {}).value || "0";
  const srcPort = (document.getElementById("simSrcPort") || {}).value || "0";

  const camino = simularFlujoAFD(proto, flags, dstPort, srcPort);
  destacarCamino(camino);

  const token = caminoAToken(camino);
  const res = document.getElementById("simResultado");
  if (res) {
    res.textContent = "Camino: " + camino.join(" → ") + "   |   Token emitido: " + token;
    res.style.display = "block";
  }
}

function actualizarAFDParaAtaque(tipoAtaque) {
  const camino = CAMINO_POR_ATAQUE[tipoAtaque] || ["q0"];
  destacarCamino(camino);
}

function actualizarSimForm() {
  const proto = (document.getElementById("simProtocolo")||{}).value;
  const gF = document.getElementById("simGrupoFlags");
  const gP = document.getElementById("simGrupoSrcPort");
  if (gF) gF.style.display = proto==="TCP"  ? "flex" : "none";
  if (gP) gP.style.display = proto==="UDP"  ? "flex" : "none";
}

document.addEventListener("DOMContentLoaded", () => {
  initAFD();
  actualizarSimForm();
});
