// Generates web/src/dark.generated.css from web/src/style.css.
//
// The light stylesheet hard-codes its colours in hundreds of rules, so the dark
// theme is derived from it instead of maintained by hand: every rule that sets a
// colour is repeated under :root[data-theme=dark] with the colour remapped.
//  - Neutral greys are inverted (white surfaces become dark, dark text becomes light).
//  - Pale tints (e.g. the light crimson hover) become dark tints of the same hue.
//  - Saturated brand colours (the crimson buttons) are kept.
//  - Rules that already sit on a dark or brand-coloured background (the hero
//    banner, primary buttons) and everything inside them are kept as they are.
// Run automatically by `npm run build`; re-run after editing style.css.
import fs from 'node:fs';
import postcss from 'postcss';

const SRC = new URL('../web/src/style.css', import.meta.url);
const OUT = new URL('../web/src/dark.generated.css', import.meta.url);
const ROOT = ':root[data-theme=dark]';

const COLOR_PROPS = /^(color|background(-color|-image)?|border(-(top|right|bottom|left|block|inline)(-start|-end)?)?(-color)?|outline(-color)?|fill|stroke|text-decoration(-color)?|caret-color|column-rule(-color)?|--.*)$/;
const COLOR_TOKEN = /#[0-9a-fA-F]{3,8}\b|\brgba?\([^)]*\)|\b(white|black)\b/g;

function parse(token) {
  if (token === 'white') return [255, 255, 255, 1];
  if (token === 'black') return [0, 0, 0, 1];
  if (token.startsWith('rgb')) {
    const p = token.slice(token.indexOf('(') + 1, -1).split(/[\s,/]+/).filter(Boolean).map(Number);
    return [p[0], p[1], p[2], p[3] ?? 1];
  }
  let h = token.slice(1);
  if (h.length <= 4) h = [...h].map(c => c + c).join('');
  const n = i => parseInt(h.slice(i, i + 2), 16);
  return [n(0), n(2), n(4), h.length === 8 ? n(6) / 255 : 1];
}
function toHsl([r, g, b]) {
  r /= 255; g /= 255; b /= 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b), l = (max + min) / 2, d = max - min;
  if (!d) return [0, 0, l];
  const s = d / (1 - Math.abs(2 * l - 1));
  let h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return [(h * 60 + 360) % 360, s, l];
}
function fromHsl(h, s, l, a) {
  const c = (1 - Math.abs(2 * l - 1)) * s, x = c * (1 - Math.abs(((h / 60) % 2) - 1)), m = l - c / 2;
  const [r, g, b] = h < 60 ? [c, x, 0] : h < 120 ? [x, c, 0] : h < 180 ? [0, c, x] : h < 240 ? [0, x, c] : h < 300 ? [x, 0, c] : [c, 0, x];
  const hex = v => Math.round((v + m) * 255).toString(16).padStart(2, '0');
  return '#' + hex(r) + hex(g) + hex(b) + (a < 1 ? Math.round(a * 255).toString(16).padStart(2, '0') : '');
}
const invert = l => 0.08 + 0.86 * Math.pow(1 - l, 0.8);

function mapColor(token, isText) {
  const rgba = parse(token), [h, s, l] = toHsl(rgba), a = rgba[3];
  if (s < 0.22 || l > 0.97) {
    // Near-white surfaces: keep cards a little lighter than the page behind them.
    const nl = l >= 0.955 ? 0.11 + (l - 0.955) : invert(l);
    return fromHsl(h, s * 0.5, nl, a);
  }
  if (isText) return l < 0.62 ? fromHsl(h, Math.min(s, 0.75), Math.max(0.66, 1 - l), a) : token;
  if (l > 0.8) return fromHsl(h, s * 0.45, invert(l), a);
  return token;
}

function colorsIn(value) { return [...value.matchAll(COLOR_TOKEN)].map(m => parse(m[0])).map(toHsl); }
function backgroundKind(rule) {
  let kind = 'light';
  rule.walkDecls(/^background(-color|-image)?$/, d => {
    const cs = colorsIn(d.value);
    if (!cs.length) return;
    if (cs.every(([, , l]) => l < 0.3)) kind = 'dark';
    else if (cs.some(([, s, l]) => s > 0.35 && l > 0.25 && l < 0.75)) kind = 'brand';
  });
  return kind;
}
function scope(selector) {
  return selector.split(',').map(s => s.trim()).map(s =>
    s.startsWith(':root') ? ROOT + s.slice(5) : s.startsWith('html') ? 'html[data-theme=dark]' + s.slice(4) : ROOT + ' ' + s).join(',');
}

const css = postcss.parse(fs.readFileSync(SRC, 'utf8'));
const out = postcss.root();
const keepContexts = new Set();
css.walkRules(rule => {
  if (backgroundKind(rule) === 'dark') {
    for (const sel of rule.selectors) { const m = sel.match(/(\.[\w-]+)(?::[\w-]+)?$/); if (m) keepContexts.add(m[1]); }
  }
});
const insideKeptContext = sel => [...keepContexts].some(c => new RegExp('\\' + c + '(?![\\w-])[^,]*\\s').test(sel));

css.walkRules(rule => {
  if (rule.parent.type === 'atrule' && /keyframes/.test(rule.parent.name)) return;
  const decls = [];
  rule.each(n => { if (n.type === 'decl' && !/shadow/.test(n.prop) && COLOR_PROPS.test(n.prop) && COLOR_TOKEN.test(n.value)) decls.push(n); COLOR_TOKEN.lastIndex = 0; });
  if (!decls.length) return;
  const keep = backgroundKind(rule) !== 'light' || rule.selectors.every(insideKeptContext);
  const copy = postcss.rule({ selector: scope(rule.selector) });
  for (const d of decls) {
    const isText = /^(color|caret-color|text-decoration(-color)?)$/.test(d.prop);
    const value = keep ? d.value : d.value.replace(COLOR_TOKEN, t => mapColor(t, isText));
    copy.append({ prop: d.prop, value, important: d.important });
  }
  let target = out;
  for (let p = rule.parent; p && p.type === 'atrule'; p = p.parent) {
    const at = postcss.atRule({ name: p.name, params: p.params }); at.append(copy.clone()); target = null;
    out.append(at); break;
  }
  if (target) out.append(copy);
});
out.prepend(postcss.rule({ selector: ROOT, nodes: [postcss.decl({ prop: 'color-scheme', value: 'dark' })] }));
fs.writeFileSync(OUT, '/* Generated by scripts/dark-theme.mjs from style.css. Do not edit by hand. */\n' + out.toString().replace(/\n\s*/g, '').replace(/}/g, '}\n'));
console.log('dark theme: ' + out.nodes.length + ' rules written');
