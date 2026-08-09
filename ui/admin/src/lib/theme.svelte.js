// Theme preference. localStorage, never anything server-side — a UI
// preference belongs to the browser it was chosen in (the same doctrine
// as regnmed's portal).
//
// "system" removes the data-theme attribute entirely, which hands the
// choice back to daisyUI's --default/--prefersdark pair, i.e. the OS.

export const THEMES = [
  "system",
  "light",
  "dark",
  "dim",
  "nord",
  "corporate",
  "sunset",
];

const KEY = "postbud-admin-theme";

let theme = $state(localStorage.getItem(KEY) || "system");

export const themePref = {
  get value() {
    return theme;
  },
  set(next) {
    theme = THEMES.includes(next) ? next : "system";
    localStorage.setItem(KEY, theme);
    apply();
  },
};

export function apply() {
  if (theme === "system") {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = theme;
  }
}
