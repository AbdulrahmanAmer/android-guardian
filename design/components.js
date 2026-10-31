// Android Guardian components, direction "Cutout". Builds the measured shapes and drives the two lifted elements.
// Parameters: see components.css header. Geometry is generated here so the CSS variables stay the single source.
(function () {
  const px = (el, name) => parseFloat(getComputedStyle(el).getPropertyValue(name));

  /* Reference silhouette (pin 604045368818569690, deskewed 14.96°), traced with `bench trace --path`, in units of
     the band width. The band is fastened to the screen edge (x = 1 there); its free side tapers into the edge with
     an S-curve at the top (0 → 0.74 W tall) and at the bottom (0.95 W tall). Mirrored here for a left-edge mount. */
  const TOP_OGEE = [[0.9841, 0.0053], [0.9206, 0.0212], [0.8519, 0.1429], [0.7249, 0.2540], [0.6614, 0.2857], [0.5450, 0.3175], [0.4444, 0.3175], [0.3545, 0.3333], [0.2169, 0.3968], [0.1217, 0.4815], [0.0741, 0.5450], [0.0159, 0.6878], [0.0053, 0.7407]];
  const BOTTOM_OGEE = [[0.0000, 0], [0.0265, 0.1217], [0.0688, 0.2116], [0.1429, 0.3068], [0.2011, 0.3545], [0.2804, 0.4021], [0.3545, 0.4285], [0.6138, 0.4603], [0.7143, 0.5026], [0.7778, 0.5449], [0.8519, 0.6190], [0.9101, 0.7090], [0.9894, 0.9523]]; // y from the start of the bottom taper
  const BOTTOM_H = 0.9523;

  /** Catmull-Rom through points → SVG cubic segments (smooth, passes through every traced point). */
  function smooth(pts) {
    let d = `M${pts[0][0]} ${pts[0][1]}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[Math.max(0, i - 1)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(pts.length - 1, i + 2)];
      const c1 = [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6], c2 = [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6];
      d += ` C${c1[0].toFixed(2)} ${c1[1].toFixed(2)} ${c2[0].toFixed(2)} ${c2[1].toFixed(2)} ${p2[0].toFixed(2)} ${p2[1].toFixed(2)}`;
    }
    return d;
  }

  /** Rail: the reference band (traced silhouette) mounted on the left edge, with a round notch at the active step. */
  function buildRail(rail) {
    // Ratios measured from the reference (see components.css). Custom properties holding calc() do not resolve to
    // numbers in getComputedStyle, so the derived sizes are computed here from the band width.
    // In the reference the first ring centre is 1.02 W from the band's top (the top taper included), the last ring
    // centre is 1.50 W from the band's bottom, and the bottom taper is 0.95 W tall. Band length for n steps:
    // 1.02 W + 1.46 W (n − 1) + 1.50 W  → 5.44 W for three steps (reference: 5.45 W).
    const W = px(rail, '--w'), first = W * 1.02, pitch = W * 1.46;
    const steps = rail.querySelectorAll('li').length, ball = px(rail, '--ball'), gap = px(rail, '--gap');
    const topH = 0.7407 * W, botH = BOTTOM_H * W;
    const bottomStart = first + pitch * (steps - 1) + 1.5 * W - botH; // y where the bottom taper begins
    const H = bottomStart + botH;
    const boxW = W + ball / 2 + gap + 8, notchX = W + gap + 10, notchR = ball / 2 + gap;
    rail.style.height = H + 'px';
    // mirror x (1 - x) so the attached side is the left window edge, scale by W
    const top = TOP_OGEE.map(([x, y]) => [(1 - x) * W, y * W]);
    const bottom = BOTTOM_OGEE.map(([x, y]) => [(1 - x) * W, bottomStart + y * W]);
    const d = `${smooth(top)} L${(1 - 0.0053) * W} ${bottomStart} ${smooth(bottom).replace(/^M[^C]*/, '')} L0 ${H} L0 0 Z`;
    let svg = rail.querySelector(':scope > svg');
    if (!svg) { svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); rail.prepend(svg); }
    svg.setAttribute('viewBox', `0 0 ${boxW} ${H}`); svg.setAttribute('preserveAspectRatio', 'none'); svg.setAttribute('aria-hidden', 'true');
    svg.style.inset = '0'; svg.style.height = '100%';
    const id = 'ag-rail-mask-' + Math.random().toString(36).slice(2, 7);
    svg.innerHTML = `<defs><mask id="${id}"><rect width="${boxW}" height="${H}" fill="#fff"/><circle class="notch" cx="${notchX}" cy="${first}" r="${notchR}" fill="#000"/></mask></defs>
      <path fill="var(--rail)" mask="url(#${id})" d="${d}"/>`;
    rail.style.setProperty('--steps', steps);
    rail.querySelectorAll('li').forEach((li, i) => {
      li.style.setProperty('--i', i);
      if (!li.querySelector('svg')) li.insertAdjacentHTML('afterbegin', '<svg viewBox="0 0 100 100" aria-hidden="true"><circle class="track" cx="50" cy="50" r="41.5"/><circle class="arc" cx="50" cy="50" r="41.5" pathLength="100"/></svg>');
      li.addEventListener('click', () => rail.dispatchEvent(new CustomEvent('ag:step', { detail: { index: i } })));
    });
    const ballEl = rail.querySelector('.ag-ball');
    rail.activate = (i) => {
      rail.style.setProperty('--active', i);
      svg.querySelector('.notch').setAttribute('cy', first + i * pitch);
      rail.querySelectorAll('li').forEach((li, j) => li.classList.toggle('active', j === i));
      if (ballEl) { const li = rail.querySelectorAll('li')[i]; ballEl.firstChild.nodeValue = li.querySelector('.n').textContent; const s = ballEl.querySelector('small'); if (s) s.textContent = li.querySelector('.label').textContent; }
    };
    /** progress 0..100 of a step's ring; marks it busy (action colour) while < 100, done at 100 */
    rail.setProgress = (i, p) => { const li = rail.querySelectorAll('li')[i]; li.style.setProperty('--p', p); li.classList.toggle('busy', p > 0 && p < 100); li.classList.toggle('done', p >= 100); };
    rail.activate(+px(rail, '--active') || 0);
  }

  /** Chip: tab hanging from the top edge with concave fillets. */
  function buildChip(chip) {
    const h = px(chip, '--h'), f = px(chip, '--fillet'), w = chip.getBoundingClientRect().width, r = h / 2, bw = w + 2 * f;
    let svg = chip.querySelector(':scope > svg');
    if (!svg) { svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); chip.prepend(svg); }
    svg.setAttribute('viewBox', `0 0 ${bw} ${h}`); svg.setAttribute('preserveAspectRatio', 'none'); svg.setAttribute('aria-hidden', 'true');
    svg.innerHTML = `<path fill="var(--rail)" d="M0 0 A${f} ${f} 0 0 1 ${f} ${f} V${h - r} A${r} ${r} 0 0 0 ${f + r} ${h} H${bw - f - r} A${r} ${r} 0 0 0 ${bw - f} ${h - r} V${f} A${f} ${f} 0 0 1 ${bw} 0 Z"/>`;
  }

  /** Tab bar: wave notch from the measured cubic, ball nested in it, 300 ms ease-in-out tab change. */
  function buildTabbar(bar) {
    const H = px(bar, '--h'), D = H * 0.45, NW = H * 1.49, C1 = 0.10, C2 = 0.80;
    const tabs = bar.querySelectorAll('li'), N = tabs.length; bar.style.setProperty('--n', N);
    let svg = bar.querySelector(':scope > svg');
    if (!svg) { svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); bar.prepend(svg); }
    const W = () => bar.getBoundingClientRect().width;
    svg.setAttribute('preserveAspectRatio', 'none'); svg.setAttribute('aria-hidden', 'true');
    if (!svg.querySelector('path')) svg.innerHTML = '<path fill="var(--rail)"/>';
    const path = svg.querySelector('path');
    const notchPath = (cx, w) => {
      const hw = NW / 2, l = cx - hw, r = cx + hw, f = D + D;
      return `M0 ${D} H${l.toFixed(1)} C${(l + C1 * hw).toFixed(1)} ${D} ${(l + C2 * hw).toFixed(1)} ${f} ${cx.toFixed(1)} ${f} C${(r - C2 * hw).toFixed(1)} ${f} ${(r - C1 * hw).toFixed(1)} ${D} ${r.toFixed(1)} ${D} H${w} V${D + H} H0 Z`;
    };
    const ball = bar.querySelector('.ag-ball'), ballD = H * 0.6;
    bar.activate = (i) => {
      const w = W(); svg.setAttribute('viewBox', `0 0 ${w} ${D + H}`);
      const cx = (i + 0.5) * w / N;
      bar.style.setProperty('--active', i);
      path.style.d = `path("${notchPath(cx, w)}")`;
      tabs.forEach((li, j) => li.classList.toggle('active', j === i));
      if (ball) { ball.style.transform = `translateX(${(cx - ballD / 2).toFixed(1)}px)`; ball.textContent = tabs[i].textContent; }
    };
    tabs.forEach((li, i) => li.addEventListener('click', () => { bar.activate(i); bar.dispatchEvent(new CustomEvent('ag:tab', { detail: { index: i } })); }));
    bar.activate(+px(bar, '--active') || 0);
    new ResizeObserver(() => bar.activate(+px(bar, '--active') || 0)).observe(bar);
  }

  function init(root = document) {
    root.querySelectorAll('.ag-rail').forEach(buildRail);
    root.querySelectorAll('.ag-chip').forEach(buildChip);
    root.querySelectorAll('.ag-tabbar').forEach(buildTabbar);
  }
  window.AG = { init, buildRail, buildChip, buildTabbar };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => init()); else init();
})();
