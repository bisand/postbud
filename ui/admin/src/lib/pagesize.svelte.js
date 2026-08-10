// Rows per page. localStorage, like the theme — a UI preference belongs
// to the browser it was chosen in, and outliving the tab is the point:
// an operator who prefers 100 rows should not have to say so again
// tomorrow.
//
// The list of choices stops at 100 because the SERVER stops at 100
// (MAX_PAGE_SIZE in admin.rs). Offering more here would silently clamp
// and leave the operator reading a number that is not what they got —
// which is the confusion this whole control exists to remove.

export const PAGE_SIZES = [10, 25, 50, 100];

const KEY = "postbud-admin-page-size";
const DEFAULT = 10;

function load() {
  const stored = Number(localStorage.getItem(KEY));
  return PAGE_SIZES.includes(stored) ? stored : DEFAULT;
}

let size = $state(load());

export const pageSize = {
  get value() {
    return size;
  },
  set(next) {
    const n = Number(next);
    size = PAGE_SIZES.includes(n) ? n : DEFAULT;
    localStorage.setItem(KEY, String(size));
  },
};
