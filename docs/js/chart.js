/**
 * Argus Dashboard - 간단한 Canvas 기반 Bar Chart
 * 외부 라이브러리 없이 순수 Canvas API 사용
 */

function drawBarChart(canvasId, data, options = {}) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !data || data.length === 0) return;

  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;

  // Canvas 크기 설정 (HiDPI 대응)
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = (options.height || 200) * dpr;
  canvas.style.width = rect.width + 'px';
  canvas.style.height = (options.height || 200) + 'px';
  ctx.scale(dpr, dpr);

  const w = rect.width;
  const h = options.height || 200;
  const padding = { top: 20, right: 20, bottom: 40, left: 50 };
  const chartW = w - padding.left - padding.right;
  const chartH = h - padding.top - padding.bottom;

  // 최대값
  const values = data.map(d => d.value);
  const maxVal = Math.max(...values, 1);

  // 배경 클리어
  ctx.clearRect(0, 0, w, h);

  // Y축 가이드라인
  ctx.strokeStyle = '#30363d';
  ctx.lineWidth = 0.5;
  ctx.fillStyle = '#6e7681';
  ctx.font = '11px -apple-system, sans-serif';
  ctx.textAlign = 'right';

  const ySteps = 4;
  for (let i = 0; i <= ySteps; i++) {
    const y = padding.top + chartH - (chartH / ySteps) * i;
    const val = Math.round((maxVal / ySteps) * i);
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(w - padding.right, y);
    ctx.stroke();
    ctx.fillText(val.toString(), padding.left - 8, y + 4);
  }

  // 바 그리기
  const barWidth = Math.max(4, (chartW / data.length) * 0.6);
  const gap = chartW / data.length;

  data.forEach((d, i) => {
    const x = padding.left + gap * i + (gap - barWidth) / 2;
    const barH = (d.value / maxVal) * chartH;
    const y = padding.top + chartH - barH;

    // 바 색상
    const color = d.color || options.barColor || '#1f6feb';
    ctx.fillStyle = color;

    // 둥근 모서리 바
    const radius = Math.min(3, barWidth / 2);
    ctx.beginPath();
    ctx.moveTo(x + radius, y);
    ctx.lineTo(x + barWidth - radius, y);
    ctx.quadraticCurveTo(x + barWidth, y, x + barWidth, y + radius);
    ctx.lineTo(x + barWidth, padding.top + chartH);
    ctx.lineTo(x, padding.top + chartH);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.fill();

    // X축 라벨
    ctx.fillStyle = '#6e7681';
    ctx.font = '10px -apple-system, sans-serif';
    ctx.textAlign = 'center';
    const label = d.label || '';
    // 짧은 라벨만 표시 (혼잡 방지)
    if (data.length <= 15 || i % Math.ceil(data.length / 15) === 0) {
      ctx.fillText(label.slice(5), x + barWidth / 2, h - padding.bottom + 18);
    }
  });
}

// Severity 분포 도넛 (간이 버전 - 가로 바)
function drawSeverityBars(containerId, counts) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const colors = { Critical: '#FF4444', High: '#FF8800', Medium: '#FFCC00', Low: '#44BB44' };
  const order = ['Critical', 'High', 'Medium', 'Low'];

  let html = '';
  for (const sev of order) {
    const count = counts[sev] || 0;
    const pct = ((count / total) * 100).toFixed(1);
    html += `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
        <span style="width:60px;font-size:12px;color:#8b949e;">${sev}</span>
        <div style="flex:1;height:8px;background:#21262d;border-radius:4px;overflow:hidden;">
          <div style="width:${pct}%;height:100%;background:${colors[sev]};border-radius:4px;"></div>
        </div>
        <span style="width:50px;font-size:12px;color:#e6edf3;text-align:right;">${count}</span>
      </div>`;
  }
  container.innerHTML = html;
}
