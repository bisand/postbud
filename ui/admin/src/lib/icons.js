// Hand-rolled 24×24 outline icons, one per section — no icon library, no
// CDN. Stroke follows currentColor so the active/hover states color them
// for free.

const svg = (paths) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" stroke-width="1.7" stroke-linecap="round"
        stroke-linejoin="round" width="20" height="20">${paths}</svg>`;

export const icons = {
  // The mark: an envelope on the move — a mail carrier's whole job.
  // Slightly larger than the section icons; the speed lines are what
  // make it read as "delivery", not "inbox".
  logo:
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"' +
    ' stroke="currentColor" stroke-width="1.8" stroke-linecap="round"' +
    ' stroke-linejoin="round" width="26" height="26">' +
    '<rect x="7" y="6" width="14.5" height="11.5" rx="2"/>' +
    '<path d="M7.5 7.5l6.75 5 6.75-5"/>' +
    '<path d="M2 9.25h3.5"/><path d="M0.9 12h4.6"/><path d="M2 14.75h3.5"/>' +
    "</svg>",
  // Four tiles.
  dashboard: svg(
    '<rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/>' +
      '<rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/>' +
      '<rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/>' +
      '<rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/>',
  ),
  // Envelope.
  messages: svg(
    '<rect x="3" y="5.5" width="18" height="13" rx="2"/>' +
      '<path d="M3.5 7l8.5 6 8.5-6"/>',
  ),
  // Shield with a bar: blocked.
  suppressions: svg(
    '<path d="M12 3.5l7 2.5v5.2c0 4.3-2.9 7.4-7 9.3-4.1-1.9-7-5-7-9.3V6z"/>' +
      '<path d="M9 12h6"/>',
  ),
  // Two people.
  tenants: svg(
    '<circle cx="9" cy="8.5" r="3"/>' +
      '<path d="M3.5 19.5c0-3 2.5-5 5.5-5s5.5 2 5.5 5"/>' +
      '<circle cx="16.5" cy="9.5" r="2.4"/>' +
      '<path d="M16.5 14.5c2.6 0 4.5 1.8 4.5 4.3"/>',
  ),
  // Arrow bouncing back.
  bounces: svg(
    '<path d="M4 7h11a5 5 0 0 1 0 10H9"/>' + '<path d="M12 13.5L8.5 17l3.5 3.5"/>',
  ),
  // Globe: sending domains.
  domains: svg(
    '<circle cx="12" cy="12" r="8.5"/>' +
      '<ellipse cx="12" cy="12" rx="3.8" ry="8.5"/>' +
      '<path d="M4 9.5h16M4 14.5h16"/>',
  ),
  // A report with a tick: what a receiver concluded about our mail.
  // Deliberately not a shield -- suppressions already owns that shape,
  // and these are somebody else's findings rather than a defence.
  dmarc: svg(
    '<path d="M6.5 3.5h7L18 8v12a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5V4a.5.5 0 0 1 .5-.5z"/>' +
      '<path d="M13.5 3.5V8H18"/>' +
      '<path d="M8.75 14.25l2.25 2.25 4.25-4.75"/>',
  ),
  // Person with a key: user administration.
  users: svg(
    '<circle cx="10" cy="8" r="3.2"/>' +
      '<path d="M4 20c0-3.3 2.7-5.5 6-5.5 1.2 0 2.3.3 3.2.8"/>' +
      '<circle cx="17" cy="15.5" r="2.2"/>' +
      '<path d="M18.6 17.1L21 19.5M19.8 18.3l1.4-1.4"/>',
  ),
  // Door with arrow: sign out.
  signout: svg(
    '<path d="M13 4H6.5A1.5 1.5 0 0 0 5 5.5v13A1.5 1.5 0 0 0 6.5 20H13"/>' +
      '<path d="M16 8.5L19.5 12 16 15.5"/>' +
      '<path d="M9.5 12h10"/>',
  ),
  // Swatch: theme.
  theme: svg(
    '<path d="M12 3.5a8.5 8.5 0 1 0 0 17c1.4 0 2-.9 2-1.8 0-.8-.5-1.2-.5-2 0-1 .8-1.7 1.9-1.7h1.8c1.8 0 3.3-1.3 3.3-3.2C20.5 7 16.7 3.5 12 3.5z"/>' +
      '<circle cx="8" cy="9" r="1"/><circle cx="12" cy="7" r="1"/>' +
      '<circle cx="16" cy="9" r="1"/><circle cx="7.5" cy="13.5" r="1"/>',
  ),
};
