import {useSyncExternalStore} from 'react';
import {getLang, languages, setLang, subscribeLang, type Lang} from './i18n';

// Per-browser display preferences: colour theme and interface language.
// They are conveniences only, so a browser that blocks storage simply falls
// back to light mode and English on the next visit.

export type Theme = 'light' | 'dark';
const THEME_KEY = 'infraledger.theme';
const themeListeners = new Set<() => void>();

export function getTheme(): Theme { return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light'; }
export function setTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem(THEME_KEY, theme); } catch { /* storage unavailable */ }
  themeListeners.forEach(fn => fn());
}
/** Apply the saved theme before the first render so the page does not flash. */
export function initTheme() {
  let saved: string | null = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch { /* ignore */ }
  document.documentElement.dataset.theme = saved === 'dark' ? 'dark' : 'light';
}
const subscribeTheme = (fn: () => void) => { themeListeners.add(fn); return () => { themeListeners.delete(fn); }; };

const sun = <svg className="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>;
const moon = <svg className="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></svg>;
const globe = <svg className="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>;

export function Preferences() {
  const theme = useSyncExternalStore(subscribeTheme, getTheme);
  const lang = useSyncExternalStore(subscribeLang, getLang);
  const dark = theme === 'dark';
  return <div className="preferences">
    <label className="language-picker" title="Language">{globe}
      <select aria-label="Language" data-no-translate value={lang} onChange={e => void setLang(e.target.value as Lang)}>
        {languages.map(l => <option key={l.code} value={l.code} lang={l.code}>{l.label}</option>)}
      </select>
    </label>
    <button type="button" className="icon-button theme-toggle" role="switch" aria-checked={dark}
      aria-label="Dark mode" title={dark ? 'Switch to light mode' : 'Switch to dark mode'}
      onClick={() => setTheme(dark ? 'light' : 'dark')}>{dark ? sun : moon}</button>
  </div>;
}
