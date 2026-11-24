import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const DOCS = join(ROOT, "docs");

const candidates = [
  process.env.ANATOMY_KIT,
  join(process.env.HOME || "", ".agents/skills/anatomy/kit/iso-kit.mjs"),
  join(process.env.HOME || "", ".codex/skills/anatomy/kit/iso-kit.mjs"),
].filter(Boolean);
const kitPath = candidates.find((candidate) => {
  try {
    readFileSync(candidate);
    return true;
  } catch {
    return false;
  }
});
if (!kitPath) {
  throw new Error(
    "Cannot find iso-kit.mjs. Set ANATOMY_KIT to the anatomy kit path, " +
    "or install the anatomy skill under ~/.agents/skills/anatomy.",
  );
}
const k = await import(pathToFileURL(kitPath).href);

const WIDTH = 680;
const HEIGHT = 430;

const PLATE = { x: -128, y: -64, w: 262, d: 128, r: 8 };
const PLATE_H = 12;
const FOOT_H = 5;
const MAG = { x: -112, y: -20, w: 44, d: 40, r: 3 };
const MAG_H = 24;
const POST = [-98, 0];
const POST_TOP = 122;
const CLAMP_Z = 100;
const DIAL = [58, 0];
const DIAL_R = 20;
const DIAL_Z = 82;
const DIAL_H = 10;
const DIAL_TOP = DIAL_Z + DIAL_H;
const PER_TURN = 4;
const RAIL_FROM = 2;
const RAIL_TO = 124;
const CARRIAGE = { x: -28, y: -24, w: 56, d: 48, r: 3 };
const CARRIAGE_Z = 3;
const CARRIAGE_TOP = 8;
const HEIGHTS = [22, 16, 10, 6];
const BLOCK_W = 15.6;
const STEP = 16;
const TIP_R = 2.6;
const CENTRE = -24 + BLOCK_W / 2;
const STOPS = HEIGHTS.map((_, index) => DIAL[0] - CENTRE - STEP * index);
const HOME = 88;
const REACH = [STOPS[STOPS.length - 1] - 6, HOME];
const CANARY = [92, -43];
const DRAWER = { x: 84, y: 36, w: 34, d: 22, r: 2 };

const P = k.fitProjection(
  [
    ...k.boxCorners(PLATE, -PLATE_H - FOOT_H, 0),
    [POST[0], POST[1], POST_TOP + 2],
    [DIAL[0] + DIAL_R, 0, DIAL_TOP],
    [CANARY[0] + 5, CANARY[1], 20],
  ],
  WIDTH,
  HEIGHT,
  { pad: 34, azimuth: 42 },
);

const at = (point) => k.iso(point, P);
const S = (paths, style) => k.solidSvg(paths, style);
const L = (d, style) => k.lineSvg(d, style);
const D = (points, style) => k.dotsSvg(points, style);
const byDepth = (points) => [...points].sort(
  (a, b) => k.depthOf([a[0], a[1], 0], P) - k.depthOf([b[0], b[1], 0], P),
);

function plate() {
  const out = [`<path class="iso-halo" d="${k.haloOf(PLATE, -PLATE_H - FOOT_H, PLATE_H, P)}"/>`];
  for (const [x, y] of byDepth(k.corners(PLATE, 22))) {
    out.push(S(k.cylinder(x, y, 7, -PLATE_H - FOOT_H, 1.6, P, 28), { tone: "lo" }));
    out.push(S(k.cylinder(x, y, 5.4, -PLATE_H - FOOT_H + 1.6, FOOT_H - 1.6, P, 28), { tone: "mid" }));
  }
  out.push(S(k.slabOf(PLATE, -PLATE_H, PLATE_H, P, 8, 1.6), { tone: "mid" }));
  out.push(L(k.planOutline(k.insetPlan(PLATE, 5), 0, P), { tone: "lo" }));
  const screws = k.corners(PLATE, 10);
  out.push(L(screws.map(([x, y]) => k.ring(x, y, 2.2, 0, P, 16)).join(""), { tone: "lo" }));
  out.push(D(screws.map(([x, y]) => at([x, y, 0])), { size: 0.5 }));

  const strip = { x: -110, y: PLATE.y + PLATE.d - 15, w: 230, d: 7, r: 1 };
  out.push(S(k.slabOf(strip, 0, 0.6, P, 3), { tone: "lo", crease: "none" }));
  const ticks = k.topTicks(strip.x + 4, strip.x + strip.w - 4, 4, 5, strip.y + 0.8, 0.6, [2, 3.6], P);
  out.push(L(ticks.minor, { tone: "lo" }), L(ticks.major, { tone: "mid" }));
  out.push(D([at([strip.x + 2, strip.y + 3.5, 0.6]), at([strip.x + strip.w - 2, strip.y + 3.5, 0.6])], { size: 0.45 }));

  const label = { x: -104, y: 42, w: 44, d: 12, r: 2 };
  out.push(S(k.slabOf(label, 0, 0.8, P, 4), { tone: "lo", crease: "none" }));
  out.push(L(k.planOutline(k.insetPlan(label, 1.6), 0.8, P), { tone: "faint" }));
  out.push(k.faceTextSvg(k.topMatrix([label.x + 6, label.y + 7.5], 0.8, P), "MEM", { size: 3.2, tone: "lo" }));
  out.push(D([at([label.x + label.w - 4, label.y + 3, 0.8]), at([label.x + label.w - 4, label.y + label.d - 3, 0.8])], { size: 0.4 }));

  return out.join("");
}

function rails() {
  const out = [];
  for (const y of [-20, 15]) {
    out.push(S(k.slabOf({ x: RAIL_FROM, y, w: RAIL_TO - RAIL_FROM, d: 5, r: 1 }, 0, 3, P, 3, 0.4), { tone: "mid" }));
    out.push(D([RAIL_FROM + 6, RAIL_TO - 6].map((x) => at([x, y + 2.5, 3])), { size: 0.4 }));
  }
  for (const x of [RAIL_FROM - 5, RAIL_TO]) {
    out.push(S(k.slabOf({ x, y: -23, w: 5, d: 46, r: 1.2 }, 0, 7, P, 3, 0.5), { tone: "mid" }));
    out.push(D([at([x + 2.5, -18, 7]), at([x + 2.5, 18, 7])], { size: 0.45 }));
  }
  return out.join("");
}

function fixture() {
  const out = [];
  out.push(S(k.slabOf(MAG, 0, 11, P, 6, 0.8), { tone: "mid" }));
  out.push(S(k.slabOf(k.insetPlan(MAG, 0.8), 11, MAG_H - 11, P, 6, 0.8), { tone: "mid" }));
  out.push(L(k.planOutline(k.insetPlan(MAG, 3), MAG_H, P), { tone: "faint" }));
  out.push(D([
    at([MAG.x + 5, MAG.y + 5, MAG_H]),
    at([MAG.x + 5, MAG.y + MAG.d - 5, MAG_H]),
    at([MAG.x + MAG.w - 5, MAG.y + 5, MAG_H]),
  ], { size: 0.45 }));

  const knob = [MAG.x + 32, MAG.y + 28];
  out.push(S(k.cylinder(knob[0], knob[1], 6, MAG_H, 4, P, 32), { tone: "mid" }));
  out.push(L(k.knurl(knob[0], knob[1], 6, MAG_H, MAG_H + 4, 36, P), { tone: "lo" }));
  out.push(L(k.lineOnTop([knob[0], knob[1]], [knob[0] + 6, knob[1]], MAG_H + 4, P), { tone: "hi" }));
  out.push(D([at([knob[0], knob[1], MAG_H + 4])], { size: 0.5, tone: "hi" }));

  out.push(S(k.cylinder(POST[0], POST[1], 5, MAG_H, 4, P, 28), { tone: "mid" }));
  const clamp = { x: POST[0] - 7, y: POST[1] - 7, w: 14, d: 14, r: 2.5 };
  out.push(S(k.cylinder(POST[0], POST[1], 3.2, MAG_H + 4, CLAMP_Z - 4 - MAG_H - 4, P, 28), { tone: "mid", crease: "none" }));
  out.push(L([60, 80].map((z) => k.sideArc(POST[0], POST[1], 3.2, z, P, 16)).join(""), { tone: "faint" }));
  out.push(S(k.slabOf(clamp, CLAMP_Z - 4, 12, P, 4, 0.6), { tone: "mid" }));
  out.push(S(k.cylinder(POST[0], POST[1], 3.2, CLAMP_Z + 8, POST_TOP - CLAMP_Z - 8, P, 28), { tone: "mid", crease: "none" }));
  out.push(S(k.cylinder(POST[0], POST[1], 3.8, POST_TOP, 2, P, 28), { tone: "mid" }));

  const arm = { x: POST[0] + 7, y: -3, w: DIAL[0] - DIAL_R - POST[0] - 7 + 2, d: 6, r: 2 };
  out.push(S(k.slabOf(arm, CLAMP_Z, 4, P, 4, 0.5), { tone: "mid" }));
  out.push(D([at([arm.x + 4, 0, CLAMP_Z + 4]), at([arm.x + arm.w - 5, 0, CLAMP_Z + 4])], { size: 0.45 }));

  const thumb = [clamp.x + 7, clamp.y + clamp.d + 3];
  out.push(S(k.slabOf({ x: thumb[0] - 1.4, y: clamp.y + clamp.d, w: 2.8, d: 3, r: 0.8 }, CLAMP_Z + 1, 4, P, 2), { tone: "mid", crease: "none" }));
  out.push(S(k.cylinder(thumb[0], thumb[1] + 1.4, 2.6, CLAMP_Z, 6, P, 20), { tone: "mid" }));
  out.push(L(k.knurl(thumb[0], thumb[1] + 1.4, 2.6, CLAMP_Z, CLAMP_Z + 6, 18, P), { tone: "lo" }));
  return out.join("");
}

function carriage() {
  const out = [`<path class="iso-halo" d="${k.haloOf(k.insetPlan(CARRIAGE, 3), CARRIAGE_Z, 0.1, P)}" style="filter:blur(4px)"/>`];
  out.push(S(k.slabOf(CARRIAGE, CARRIAGE_Z, CARRIAGE_TOP - CARRIAGE_Z, P, 5, 0.6), { tone: "mid" }));
  out.push(D([-22, -8, 8, 22].map((x) => at([x, CARRIAGE.y + CARRIAGE.d - 2.6, CARRIAGE_TOP])), { size: 0.4, tone: "lo" }));
  out.push(L(k.lineOnTop([CARRIAGE.x, -15.5], [CARRIAGE.x + CARRIAGE.w, -15.5], CARRIAGE_TOP, P), { tone: "faint" }));
  out.push(L(k.lineOnTop([CARRIAGE.x, 15.5], [CARRIAGE.x + CARRIAGE.w, 15.5], CARRIAGE_TOP, P), { tone: "faint" }));

  HEIGHTS.forEach((height, index) => {
    const plan = { x: -24 + STEP * index, y: -12, w: BLOCK_W, d: 24, r: 1 };
    out.push(S(k.slabOf(plan, CARRIAGE_TOP, height, P, 3, 0.5), { tone: "hi", crease: "lo" }));
    out.push(L(k.planOutline(k.insetPlan(plan, 2), CARRIAGE_TOP + height, P, 3), { tone: "faint" }));
    out.push(D([at([plan.x + 3, plan.y + plan.d - 3, CARRIAGE_TOP + height])], { size: 0.38, tone: "lo" }));
  });

  const handle = [CARRIAGE.x + CARRIAGE.w - 8, CARRIAGE.y + CARRIAGE.d + 3];
  out.push(S(k.slabOf({ x: handle[0] - 2, y: CARRIAGE.y + CARRIAGE.d - 1, w: 4, d: 4, r: 1 }, CARRIAGE_Z + 1, 3, P, 2), { tone: "mid", crease: "none" }));
  out.push(S(k.cylinder(handle[0], handle[1] + 1, 3, CARRIAGE_Z, 5, P, 20), { tone: "mid" }));
  out.push(L(k.knurl(handle[0], handle[1] + 1, 3, CARRIAGE_Z, CARRIAGE_Z + 5, 18, P), { tone: "lo" }));
  return out.join("");
}

function plunger() {
  const out = [];
  out.push(S(k.cylinder(DIAL[0], DIAL[1], TIP_R, 0, 2.4, P, 20), { tone: "hi", lit: true }));
  out.push(S(k.cylinder(DIAL[0], DIAL[1], 1.4, 2.4, 50, P, 16), { tone: "hi", crease: "none", lit: true }));
  return out.join("");
}

function dial() {
  const out = [];
  const [x, y] = DIAL;
  out.push(S(k.cylinder(x, y, 2.9, 54, DIAL_Z - 54, P, 20), { tone: "mid" }));
  out.push(L(k.sideArc(x, y, 2.9, 60, P, 12), { tone: "lo" }));
  out.push(S(k.slabOf({ x: x - DIAL_R - 6, y: -4, w: 8, d: 8, r: 1.5 }, DIAL_Z + 2, CLAMP_Z - DIAL_Z - 2, P, 3, 0.4), { tone: "mid" }));
  out.push(S(k.cylinder(x, y, DIAL_R, DIAL_Z, DIAL_H, P, 64, 0.8), { tone: "hi", crease: "lo" }));
  out.push(L(k.knurl(x, y, DIAL_R, DIAL_TOP - 3.4, DIAL_TOP, 84, P, 0.3), { tone: "lo" }));
  out.push(L(k.sideArc(x, y, DIAL_R, DIAL_TOP - 3.4, P, 40), { tone: "faint" }));
  out.push(L(k.ring(x, y, DIAL_R - 2.2, DIAL_TOP, P, 64), { tone: "lo" }));
  const ticks = k.radialTicks(x, y, DIAL_R - 3, 50, 5, DIAL_TOP, [1.3, 2.8], P);
  out.push(L(ticks.minor, { tone: "lo" }), L(ticks.major, { tone: "mid" }));
  out.push(S(k.slabOf({ x: x + DIAL_R - 1, y: -2.4, w: 5, d: 4.8, r: 1.2 }, DIAL_Z + 2, 5, P, 3), { tone: "mid" }));
  out.push(S(k.slabOf({ x: x + DIAL_R + 3.6, y: -3.2, w: 2.6, d: 6.4, r: 1.2 }, DIAL_Z + 1.2, 6.6, P, 3), { tone: "mid" }));
  out.push(L(k.ring(x, y, 1.6, DIAL_TOP, P, 16), { tone: "mid" }));
  return out.join("");
}

function canary() {
  const [x, y] = CANARY;
  const out = [];
  out.push(S(k.cylinder(x, y, 4, 0, 4, P, 20), { tone: "mid" }));
  out.push(S(k.cylinder(x, y, 2.4, 4, 10, P, 20), { tone: "mid", crease: "none" }));
  out.push(L(k.sideArc(x, y, 2.4, 8, P, 14), { tone: "faint" }));
  out.push(S(k.cylinder(x, y, 4.4, 14, 4, P, 24), { tone: "hi" }));
  out.push(`<path data-part="canary-glow" d="${k.ring(x, y, 3.3, 18, P, 24)}" fill="var(--anatomy-red)" opacity="0.18"/>`);
  out.push(L(k.ring(x, y, 4.4, 18, P, 24), { tone: "lo" }));
  return out.join("");
}

function drawer() {
  const out = [];
  out.push(S(k.slabOf(DRAWER, 0, 10, P, 4, 0.6), { tone: "mid" }));
  out.push(L(k.planOutline(k.insetPlan(DRAWER, 2.2), 10, P), { tone: "faint" }));
  out.push(S(k.slabOf({ x: DRAWER.x + 3, y: DRAWER.y + DRAWER.d - 1, w: 6, d: 3, r: 1 }, 4, 2, P, 2, 0.3), { tone: "mid", crease: "none" }));
  out.push(S(k.slabOf({ x: DRAWER.x + 9, y: DRAWER.y + DRAWER.d - 1, w: 16, d: 3, r: 1.2 }, 4, 3, P, 3, 0.4), { tone: "mid" }));
  out.push(D([at([DRAWER.x + 15, DRAWER.y + DRAWER.d + 0.5, 7]), at([DRAWER.x + 21, DRAWER.y + DRAWER.d + 0.5, 7])], { size: 0.4 }));
  return out.join("");
}

const needleAt = (turns) => {
  const angle = turns * Math.PI * 2;
  const [x, y] = DIAL;
  return k.lineOnTop(
    [x - Math.sin(angle) * 3.4, y + Math.cos(angle) * 3.4],
    [x + Math.sin(angle) * (DIAL_R - 4), y - Math.cos(angle) * (DIAL_R - 4)],
    DIAL_TOP + 0.2,
    P,
  );
};

const svg = k.figureSvg({
  width: WIDTH,
  height: HEIGHT,
  label: "A memory-safety bench: four severity trays on a carriage under a lit probe, a dial gauge that reads the finding count, a canary lamp, and a heap drawer.",
  body: [
    plate(),
    rails(),
    fixture(),
    drawer(),
    canary(),
    `<g data-part="carriage" transform="${k.translateAlong(P, [HOME, 0, 0])}">${carriage()}</g>`,
    `<g data-part="plunger" transform="${k.translateAlong(P, [0, 0, CARRIAGE_TOP])}">${plunger()}</g>`,
    dial(),
    `<path data-part="needle" class="iso-line" data-tone="lit" data-free="start" d="${needleAt(0)}" style="stroke-width:1.1"/>`,
  ],
});

const payload = {
  svg,
  projection: P,
  stops: STOPS,
  home: HOME,
  reach: REACH,
  base: CARRIAGE_TOP,
  heights: HEIGHTS,
  dial: { x: DIAL[0], y: DIAL[1], top: DIAL_TOP, radius: DIAL_R, perTurn: PER_TURN, tipRadius: TIP_R },
  severities: ["critical", "high", "medium", "low"],
  canary: CANARY,
};

mkdirSync(DOCS, { recursive: true });
const rules = JSON.parse(readFileSync(join(ROOT, "boar_rules.json"), "utf8"));
writeFileSync(join(DOCS, "rules.js"), `window.BOAR_RULES = ${JSON.stringify(rules)};\n`);
writeFileSync(join(DOCS, "iso.css"), k.ISO_CSS);
writeFileSync(join(DOCS, "hero.js"), `window.BOAR_HERO = ${JSON.stringify(payload)};\n`);
writeFileSync(join(DOCS, "hero.svg"), k.figureSvg({
  width: WIDTH,
  height: HEIGHT,
  label: "A memory-safety bench: four severity trays on a carriage under a lit probe, a dial gauge that reads the finding count, a canary lamp, and a heap drawer.",
  standalone: "dark",
  body: [
    plate(),
    rails(),
    fixture(),
    drawer(),
    canary(),
    `<g transform="${k.translateAlong(P, [HOME, 0, 0])}">${carriage()}</g>`,
    `<g transform="${k.translateAlong(P, [0, 0, CARRIAGE_TOP])}">${plunger()}</g>`,
    dial(),
    `<path class="iso-line" data-tone="lit" d="${needleAt(0)}" style="stroke-width:1.1"/>`,
  ],
}));
console.log(`wrote docs/hero.svg, docs/hero.js, docs/rules.js, docs/iso.css (${rules.rules.length} rules)`);
