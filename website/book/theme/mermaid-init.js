// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1
//
// Draws every ```mermaid fence of the page with the vendored mermaid library.
// The page's policy refuses inline styles, so the CSS mermaid writes into each
// diagram goes into a constructed stylesheet before the diagram is laid out,
// and each style attribute is set again through the CSSOM, which the policy
// allows.
// No specification governs this: our own design.
(async () => {
  const fences = [...document.querySelectorAll('pre > code.language-mermaid')];
  if (fences.length === 0) {
    return;
  }
  const darkThemes = ['ayu', 'navy', 'coal'];
  const html = document.documentElement;
  const isDark = () => darkThemes.some((theme) => html.classList.contains(theme));
  const drawnDark = isDark();
  mermaid.initialize({
    startOnLoad: false,
    theme: drawnDark ? 'dark' : 'default',
    htmlLabels: false,
    flowchart: { htmlLabels: false },
  });
  const sheet = new CSSStyleSheet();
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
  const sources = fences.map((code) => code.textContent);
  let css = '';
  for (const [i, source] of sources.entries()) {
    const { svg } = await mermaid.render(`mermaid-probe-${i}`, source);
    const parsed = new DOMParser().parseFromString(svg, 'image/svg+xml');
    for (const style of parsed.querySelectorAll('style')) {
      css += style.textContent.replaceAll(`#mermaid-probe-${i}`, `#mermaid-${i}`);
    }
  }
  sheet.replaceSync(css);
  for (const [i, source] of sources.entries()) {
    const { svg } = await mermaid.render(`mermaid-${i}`, source);
    const figure = document.createElement('div');
    figure.className = 'mermaid';
    figure.innerHTML = svg;
    for (const element of figure.querySelectorAll('[style]')) {
      element.style.cssText = element.getAttribute('style');
    }
    fences[i].parentElement.replaceWith(figure);
  }
  new MutationObserver(() => {
    if (isDark() !== drawnDark) {
      window.location.reload();
    }
  }).observe(html, { attributes: true, attributeFilter: ['class'] });
})();
