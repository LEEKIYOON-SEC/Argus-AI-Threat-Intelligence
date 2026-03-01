/**
 * Argus Blacklist IP Dashboard
 * 검색, 필터, 정렬, 페이지네이션
 */

let allIndicators = [];
let filteredIndicators = [];
let blStatsData = {};
let recoveredIps = [];
let blCurrentPage = 1;
const BL_PAGE_SIZE = 50;
let blSortField = 'score';
let blSortDir = -1;
let blFilters = { risk: new Set(['Critical', 'High', 'Medium', 'Low']), search: '', category: '' };

// ===== 초기화 =====
async function init() {
  showLoading(true);
  try {
    const [blRes, statsRes] = await Promise.all([
      fetch('data/blacklist.json').then(r => r.json()),
      fetch('data/stats.json').then(r => r.json()),
    ]);
    allIndicators = blRes.indicators || [];
    recoveredIps = blRes.recovered || [];
    blStatsData = statsRes;
    renderStats(blRes);
    renderChart();
    buildCategoryFilter();
    applyFilters();
    renderRecoveredIps();
  } catch (e) {
    console.error('Data load failed:', e);
    document.getElementById('bl-table-body').innerHTML =
      '<tr><td colspan="7" class="empty-state"><div class="icon">&#128737;</div><p>데이터를 불러올 수 없습니다.</p></td></tr>';
  }
  showLoading(false);
}

function showLoading(show) {
  const el = document.getElementById('loading');
  if (el) el.style.display = show ? 'block' : 'none';
}

// ===== 통계 =====
function renderStats(blData) {
  const bl = blStatsData.blacklist || {};
  const risk = bl.risk || {};

  setText('stat-total', bl.total || allIndicators.length);
  setText('stat-critical', risk.Critical || 0);
  setText('stat-high', risk.High || 0);
  setText('stat-recovered', bl.recovered_count || (blData.recovered || []).length);

  // 날짜
  if (blData.date) {
    setText('stat-date', blData.date);
  }

  // 업데이트 시간
  if (blStatsData.generated_at) {
    const d = new Date(blStatsData.generated_at);
    setText('updated-time', d.toLocaleString('ko-KR'));
  }

  // 위험도 분포
  if (risk) {
    drawSeverityBars('risk-dist', risk);
  }
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = typeof val === 'number' ? val.toLocaleString() : val;
}

// ===== 차트 =====
function renderChart() {
  const trend = blStatsData.blacklist?.daily_trend || [];
  const chartData = trend.map(d => ({
    label: d.date,
    value: d.total,
    color: '#FF8800',
  }));
  drawBarChart('trend-chart', chartData);
}

// ===== 카테고리 필터 =====
function buildCategoryFilter() {
  const cats = new Map();
  allIndicators.forEach(ind => {
    const c = ind.category || 'unknown';
    cats.set(c, (cats.get(c) || 0) + 1);
  });

  const sorted = [...cats.entries()].sort((a, b) => b[1] - a[1]);
  const select = document.getElementById('category-filter');
  if (!select) return;
  sorted.forEach(([c, count]) => {
    const opt = document.createElement('option');
    opt.value = c;
    opt.textContent = `${c} (${count})`;
    select.appendChild(opt);
  });
}

// ===== 필터링 =====
function applyFilters() {
  const search = blFilters.search.toLowerCase();
  const category = blFilters.category;

  filteredIndicators = allIndicators.filter(ind => {
    if (!blFilters.risk.has(ind.risk || 'Low')) return false;
    if (search && !ind.indicator.includes(search)) return false;
    if (category && ind.category !== category) return false;
    return true;
  });

  filteredIndicators.sort((a, b) => {
    let va, vb;
    switch (blSortField) {
      case 'score': va = a.score || 0; vb = b.score || 0; break;
      case 'indicator': va = a.indicator || ''; vb = b.indicator || ''; break;
      case 'risk': va = riskOrder(a.risk); vb = riskOrder(b.risk); break;
      default: va = a.score || 0; vb = b.score || 0;
    }
    if (va < vb) return blSortDir;
    if (va > vb) return -blSortDir;
    return 0;
  });

  blCurrentPage = 1;
  renderTable();
  renderPagination();
}

function riskOrder(risk) {
  const order = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  return order[risk] || 0;
}

// ===== 테이블 =====
function renderTable() {
  const tbody = document.getElementById('bl-table-body');
  if (!tbody) return;

  const start = (blCurrentPage - 1) * BL_PAGE_SIZE;
  const page = filteredIndicators.slice(start, start + BL_PAGE_SIZE);

  if (page.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><div class="icon">&#128269;</div><p>조건에 맞는 IP가 없습니다.</p></td></tr>';
    return;
  }

  tbody.innerHTML = page.map(ind => {
    const riskClass = `badge-${(ind.risk || 'low').toLowerCase()}`;
    const sources = (ind.sources || []).slice(0, 3).join(', ');
    const abuseConf = ind.abuse_confidence != null ? `${ind.abuse_confidence}%` : '-';
    const abuseReports = ind.abuse_reports != null ? ind.abuse_reports : '-';

    return `<tr data-severity="${ind.risk || 'Low'}">
      <td><code>${escapeHtml(ind.indicator)}</code></td>
      <td class="score-cell">${ind.score || 0}</td>
      <td><span class="badge ${riskClass}">${ind.risk || 'Low'}</span></td>
      <td>${escapeHtml(ind.category || '-')}</td>
      <td style="font-size:12px;color:var(--text-secondary)">${escapeHtml(sources)}</td>
      <td class="score-cell">${abuseConf}</td>
      <td class="score-cell">${abuseReports}</td>
    </tr>`;
  }).join('');
}

// ===== 페이지네이션 =====
function renderPagination() {
  const totalPages = Math.ceil(filteredIndicators.length / BL_PAGE_SIZE);
  const info = document.getElementById('page-info');
  const prevBtn = document.getElementById('prev-btn');
  const nextBtn = document.getElementById('next-btn');

  if (info) info.textContent = `${blCurrentPage} / ${totalPages} (${filteredIndicators.length}건)`;
  if (prevBtn) prevBtn.disabled = blCurrentPage <= 1;
  if (nextBtn) nextBtn.disabled = blCurrentPage >= totalPages;
}

function changePage(delta) {
  const totalPages = Math.ceil(filteredIndicators.length / BL_PAGE_SIZE);
  blCurrentPage = Math.max(1, Math.min(totalPages, blCurrentPage + delta));
  renderTable();
  renderPagination();
  window.scrollTo({ top: document.querySelector('.table-wrapper')?.offsetTop - 80, behavior: 'smooth' });
}

// ===== 정렬 =====
function sortBy(field) {
  if (blSortField === field) {
    blSortDir *= -1;
  } else {
    blSortField = field;
    blSortDir = -1;
  }
  applyFilters();
}

// ===== 평판 회복 IP =====
function renderRecoveredIps() {
  const section = document.getElementById('recovered-section');
  const tbody = document.getElementById('recovered-table-body');
  if (!section || !tbody) return;

  if (!recoveredIps || recoveredIps.length === 0) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';
  tbody.innerHTML = recoveredIps.map(r => {
    const statusBadge = r.status === 'removed'
      ? '<span class="badge" style="background:#28A745;color:#fff;">Removed</span>'
      : '<span class="badge" style="background:#FFC107;color:#000;">Degraded</span>';
    const yesterdayBadge = `<span class="badge badge-${r.yesterday_risk.toLowerCase()}">${r.yesterday_risk}</span> ${r.yesterday_score}`;
    const todayText = r.status === 'removed'
      ? '<span style="color:var(--text-muted)">- (Feed removed)</span>'
      : `<span class="badge badge-${(r.today_risk || 'low').toLowerCase()}">${r.today_risk}</span> ${r.today_score}`;

    return `<tr>
      <td><code>${escapeHtml(r.indicator)}</code></td>
      <td>${statusBadge}</td>
      <td>${yesterdayBadge}</td>
      <td>${todayText}</td>
      <td>${escapeHtml(r.category || '-')}</td>
    </tr>`;
  }).join('');
}

// ===== 유틸 =====
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ===== 이벤트 =====
document.addEventListener('DOMContentLoaded', () => {
  init();

  const searchEl = document.getElementById('search-input');
  if (searchEl) {
    let timer;
    searchEl.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        blFilters.search = searchEl.value;
        applyFilters();
      }, 300);
    });
  }

  const catEl = document.getElementById('category-filter');
  if (catEl) catEl.addEventListener('change', () => {
    blFilters.category = catEl.value;
    applyFilters();
  });

  document.querySelectorAll('.severity-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const risk = btn.dataset.severity;
      if (blFilters.risk.has(risk)) {
        blFilters.risk.delete(risk);
        btn.classList.remove('active');
      } else {
        blFilters.risk.add(risk);
        btn.classList.add('active');
      }
      applyFilters();
    });
  });
});
