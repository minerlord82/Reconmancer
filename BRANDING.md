# Reconmancer v0.1.4 — The Arcane Atlas

Reconmancer uses a **dark purple, silver, moonlit fantasy-tech** identity. The v0.1.4 interface follows the user-supplied mockup with a gothic panorama, enchanted navigation, illustrated reconnaissance engines, luminous line icons and quiet teal status indicators.

## Theme implementation

- `reconmancer/web/static/css/arcane-v014.css` — final override layer, loaded after the original app/component CSS (which is preserved).
- `reconmancer/web/templates/base.html` — shared sidebar branding, persistent navigation, visual context and theme stylesheet.
- `reconmancer/web/templates/overview.html` — live metric, storage and engine links over scenic artwork.
- `reconmancer/web/templates/index.html` — same panoramic brand header on the quest registry.

## Local image assets

- `arcane-banner.webp` — cropped from the supplied mockup; fully contained and centered, no horizontal cropping.
- `arcane-banner-mobile.webp` — centered compact banner for smaller screens.
- `arcane-world.webp` — original atmospheric composite (dark sky, moon, clouds, castle silhouettes, runic circles) for the site-wide background.
- `arcane-sidebar.webp` — moonlit tower and cloaked magician illustration.
- `arcane-quest.webp` — mountain and castle vignette behind the live quest title.
- `arcane-storage.webp` — enchanted lantern/storage vignette behind the real disk usage indicator.
- `arcane-httpx.webp`, `arcane-katana.webp`, `arcane-nuclei.webp` — three separate fantasy-tech engine card illustrations.
- `rune-*.webp` — transparent violet/silver linework for all ten existing sidebar icon categories, preserving the original icon assets for backward compatibility.

All assets are local, with no fonts, image CDNs, scripts, or runtime network resources. The app remains **Flask + vanilla HTML/CSS/JS**. Image painting is frontend-only; scan throughput and execution routines are unmodified.

## UI rules

Design for a viewport from 390px through 1920px; on mobile the sidebar becomes horizontally scrollable. Real content remains in semantic HTML and is not embedded in decorative images. Buttons, forms, evidence links, alerts and tables remain keyboard-accessible. Photos and screenshot thumbnails use `object-fit: contain` and centered alignment when they should not be cropped.
