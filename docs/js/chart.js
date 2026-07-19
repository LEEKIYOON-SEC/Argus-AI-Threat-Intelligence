/**
 * Argus Dashboard — 외부 라이브러리 없는 Canvas 막대 차트 (호버 툴팁 포함)
 */

function cssVar(name, fallback) {
  const v = getComputedStyle(document.body).getPropertyValue(name).trim();
  return v || fallback;
}

function drawBarChart(canvasId, data, options = {}) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !data || data.length === 0) return;

  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.parentElement.getBoundingClientRect();
  const h = options.height || 200;
  canvas.width = rect.width * dpr;
  canvas.height = h * dpr;
  canvas.style.width = rect.width + 'px';
  canvas.style.height = h + 'px';
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const w = rect.width;
  const pad = { top: 16, right: 12, bottom: 34, left: 34 };
  const chartW = w - pad.left - pad.right;
  const chartH = h - pad.top - pad.bottom;

  const values = data.map(d => d.value);
  const maxVal = Math.max(...values, 1);
  const gridColor = cssVar('--border', '#232b39');
  const axisText = cssVar('--text-faint', '#5c6675');
  const barColor = cssVar('--accent', '#58a6ff');

  ctx.clearRect(0, 0, w, h);

  // 가로 그리드 + Y 라벨
  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  ctx.fillStyle = axisText;
  ctx.font = '10px -apple-system, sans-serif';
  ctx.textAlign = 'right';
  const ySteps = 4;
  for (let i = 0; i <= ySteps; i++) {
    const y = pad.top + chartH - (chartH / ySteps) * i;
    const val = Math.round((maxVal / ySteps) * i);
    ctx.globalAlpha = 0.5;
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
    ctx.globalAlpha = 1;
    ctx.fillText(String(val), pad.left - 7, y + 3);
  }

  const gap = chartW / data.length;
  const barW = Math.max(3, gap * 0.62);
  const bars = [];

  data.forEach((d, i) => {
    const x = pad.left + gap * i + (gap - barW) / 2;
    const barH = Math.max((d.value / maxVal) * chartH, d.value > 0 ? 2 : 0);
    const y = pad.top + chartH - barH;
    bars.push({ x, y, w: barW, h: barH, ...d });

    const r = Math.min(4, barW / 2);
    ctx.fillStyle = d.color || barColor;
    ctx.beginPath();
    ctx.moveTo(x, pad.top + chartH);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.lineTo(x + barW - r, y);
    ctx.quadraticCurveTo(x + barW, y, x + barW, y + r);
    ctx.lineTo(x + barW, pad.top + chartH);
    ctx.closePath();
    ctx.fill();

    // X 라벨 (혼잡 방지: 최대 ~10개)
    if (data.length <= 12 || i % Math.ceil(data.length / 10) === 0) {
      ctx.fillStyle = axisText;
      ctx.font = '9px -apple-system, sans-serif';
      ctx.textAlign = 'center';
      const lbl = (d.label || '').slice(5); // MM-DD
      ctx.fillText(lbl, x + barW / 2, h - pad.bottom + 15);
    }
  });

  // ---- 호버 툴팁 ----
  let tip = canvas.parentElement.querySelector('.chart-tip');
  if (!tip) {
    tip = document.createElement('div');
    tip.className = 'chart-tip';
    tip.style.cssText = 'position:absolute;pointer-events:none;display:none;padding:5px 9px;border-radius:6px;font-size:11px;font-weight:600;white-space:nowrap;z-index:10;transform:translate(-50%,-120%);';
    canvas.parentElement.style.position = 'relative';
    canvas.parentElement.appendChild(tip);
  }
  canvas.onmousemove = (e) => {
    const b = canvas.getBoundingClientRect();
    const mx = e.clientX - b.left, my = e.clientY - b.top;
    const hit = bars.find(bar => mx >= bar.x - 2 && mx <= bar.x + bar.w + 2 && my >= bar.y - 6);
    if (hit) {
      tip.style.display = 'block';
      tip.style.left = (hit.x + hit.w / 2) + 'px';
      tip.style.top = hit.y + 'px';
      tip.style.background = cssVar('--surface-3', '#1b222e');
      tip.style.color = cssVar('--text', '#e8eef6');
      tip.style.boxShadow = '0 4px 14px rgba(0,0,0,.35)';
      tip.textContent = `${hit.label} · ${hit.value}건`;
    } else {
      tip.style.display = 'none';
    }
  };
  canvas.onmouseleave = () => { tip.style.display = 'none'; };
}
