// Interface translation.
//
// The screens are written in English. Instead of threading a t() call through
// every component, this module watches the rendered page and swaps interface
// text that exactly matches an entry in the selected language's dictionary
// (web/src/i18n/<code>.json, keyed by the English text). Anything that is not
// a dictionary entry, which covers record names, notes and other user data,
// is left as it is. Typed input, code blocks, article bodies and anything
// marked data-no-translate are never touched.
//
// When React later changes a text node, the observer sees the new English
// text and translates it again, so the page stays consistent.

export type Lang = 'en' | 'es-419' | 'fr' | 'zh-CN' | 'hi';
export const languages: { code: Lang; label: string }[] = [
  { code: 'en', label: 'English' },
  { code: 'es-419', label: 'Español (Latinoamérica)' },
  { code: 'fr', label: 'Français' },
  { code: 'zh-CN', label: '中文（简体）' },
  { code: 'hi', label: 'हिन्दी' },
];

const loaders: Record<Exclude<Lang, 'en'>, () => Promise<{ default: Record<string, string> }>> = {
  'es-419': () => import('./i18n/es-419.json'),
  fr: () => import('./i18n/fr.json'),
  'zh-CN': () => import('./i18n/zh-CN.json'),
  hi: () => import('./i18n/hi.json'),
};

const SKIP = 'input,textarea,pre,code,script,style,[contenteditable],[data-no-translate],.article-content';
const ATTRS = ['placeholder', 'title', 'aria-label', 'alt'] as const;
const STORE_KEY = 'infraledger.lang';

let dict = new Map<string, string>();
let current: Lang = 'en';
// The English text behind each node we changed, and the text we put there.
const textState = new WeakMap<Text, { en: string; shown: string }>();
const attrState = new WeakMap<Element, Record<string, { en: string; shown: string }>>();

function lookup(text: string): string {
  const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(text)!;
  const hit = m[2] && dict.get(m[2]);
  return hit ? m[1] + hit + m[3] : text;
}
/** Translate a string built in code (for example a confirmation dialog). */
export function tx(text: string): string { return current === 'en' ? text : lookup(text); }

function translateText(node: Text) {
  const parent = node.parentElement;
  if (!parent || parent.closest(SKIP)) return;
  const value = node.nodeValue ?? '';
  const state = textState.get(node);
  const en = state && value === state.shown ? state.en : value;
  const shown = current === 'en' ? en : lookup(en);
  if (shown !== value) node.nodeValue = shown;
  if (shown !== en || state) textState.set(node, { en, shown });
}
function translateAttrs(el: Element) {
  if (el.closest(SKIP) && !(el.matches('input,textarea') && !el.closest('[data-no-translate]'))) return;
  for (const name of ATTRS) {
    const value = el.getAttribute(name);
    if (value == null) continue;
    const states = attrState.get(el) ?? {};
    const state = states[name];
    const en = state && value === state.shown ? state.en : value;
    const shown = current === 'en' ? en : lookup(en);
    if (shown !== value) el.setAttribute(name, shown);
    states[name] = { en, shown };
    attrState.set(el, states);
  }
}
function translateTree(root: Node) {
  if (root.nodeType === Node.TEXT_NODE) { translateText(root as Text); return; }
  if (!(root instanceof Element)) return;
  translateAttrs(root);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (n.nodeType === Node.TEXT_NODE) translateText(n as Text); else translateAttrs(n as Element);
  }
}

let observer: MutationObserver | undefined;
function observe() {
  observer = new MutationObserver(records => {
    observer!.disconnect();
    for (const r of records) {
      if (r.type === 'characterData') translateText(r.target as Text);
      else if (r.type === 'attributes') translateAttrs(r.target as Element);
      else r.addedNodes.forEach(translateTree);
    }
    start();
  });
  start();
}
function start() {
  observer!.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: [...ATTRS] });
}

export function getLang(): Lang { return current; }
const listeners = new Set<() => void>();
export function subscribeLang(fn: () => void) { listeners.add(fn); return () => { listeners.delete(fn); }; }

export async function setLang(lang: Lang) {
  dict = lang === 'en' ? new Map() : new Map(Object.entries((await loaders[lang]()).default).filter(([k, v]) => v && k !== v));
  current = lang;
  document.documentElement.lang = lang;
  try { localStorage.setItem(STORE_KEY, lang); } catch { /* storage unavailable: choice lasts this visit */ }
  if (!observer) observe();
  observer!.disconnect();
  translateTree(document.body);
  start();
  listeners.forEach(fn => fn());
}

export function initLang() {
  let saved: string | null = null;
  try { saved = localStorage.getItem(STORE_KEY); } catch { /* ignore */ }
  const lang = languages.some(l => l.code === saved) ? saved as Lang : 'en';
  observe();
  if (lang !== 'en') void setLang(lang);
}
