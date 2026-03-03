/**
 * Argus IOC Integrated Dashboard
 * CVE + IP + Detection Rule + URL + Hash 통합 IOC 뷰
 * 타입별 lazy-load 아키텍처
 */

// ===== State =====
var iocMeta = {};                  // ioc-meta.json (통계)
var typeCache = {};                // { cve: [...], ip: [...], ... } 로드된 타입 캐시
var typeLoading = {};              // { cve: true, ... } 로딩 중 여부
var filteredIocs = [];
var currentPage = 1;
var PAGE_SIZE = 50;
var sortField = 'date';
var sortDir = -1;
var activeFilters = { risk: new Set(['Critical', 'High', 'Medium', 'Low']), search: '', type: '' };

// ===== Constants =====
var IOC_TYPES = ['cve', 'ip', 'rule', 'url', 'hash'];
var TYPE_ICONS = { cve: '\u{1F6E1}', ip: '\u{1F310}', rule: '\u{1F50D}', url: '\u{1F517}', hash: '\u{1F9EC}' };
var TYPE_LABELS = { cve: 'CVE', ip: 'IP', rule: 'Rule', url: 'URL', hash: 'Hash' };

// ===== Init =====
async function init() {
  showLoading(true);
  try {
    // 1) 메타 로드 (경량 — 통계만)
    iocMeta = await fetch('data/ioc-meta.json').then(function(r) { return r.json(); });
    renderStats();
    renderCharts();
    renderTypeTabCounts();

    // 2) 초기 데이터 로드 — 타입 필터 없으면 소규모 타입(cve, ip, rule)부터
    await loadTypes(['cve', 'ip', 'rule']);
    applyFilters();

    // 3) 대용량 타입(url, hash) 백그라운드 로드
    loadTypes(['url', 'hash']).then(function() {
      // 현재 해당 타입 필터 중이면 새로고침
      if (!activeFilters.type || activeFilters.type === 'url' || activeFilters.type === 'hash') {
        applyFilters();
      }
      renderTypeTabCounts();
    });

  } catch (e) {
    console.error('IOC meta load failed:', e);
    document.getElementById('ioc-table-body').innerHTML =
      '<tr><td colspan="7" class="empty-state"><div class="icon">&#128268;</div><p>IOC 데이터를 불러올 수 없습니다.</p></td></tr>';
  }
  showLoading(false);
}

function showLoading(show) {
  var el = document.getElementById('loading');
  if (el) el.style.display = show ? 'block' : 'none';
}

// ===== Lazy Load =====
function loadTypes(types) {
  var promises = [];
  for (var i = 0; i < types.length; i++) {
    var t = types[i];
    if (typeCache[t] || typeLoading[t]) continue;
    promises.push(loadSingleType(t));
  }
  return Promise.all(promises);
}

function loadSingleType(t) {
  typeLoading[t] = true;
  return fetch('data/ioc-' + t + '.json')
    .then(function(r) {
      if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
      return r.json();
    })
    .then(function(items) {
      typeCache[t] = items;
      typeLoading[t] = false;
      // 탭 카운트 실제 값으로 업데이트
      var el = document.getElementById('tab-count-' + t);
      if (el) el.textContent = items.length.toLocaleString();
    })
    .catch(function(e) {
      console.warn('ioc-' + t + '.json load failed:', e);
      typeCache[t] = [];
      typeLoading[t] = false;
    });
}

function getAllLoadedIocs() {
  var all = [];
  for (var i = 0; i < IOC_TYPES.length; i++) {
    var t = IOC_TYPES[i];
    if (typeCache[t]) {
      all = all.concat(typeCache[t]);
    }
  }
  return all;
}

// ===== Stats =====
function renderStats() {
  setText('stat-total', iocMeta.total || 0);
  var bt = iocMeta.by_type || {};
  setText('stat-cve', bt.cve || 0);
  setText('stat-ip', bt.ip || 0);
  setText('stat-rule', bt.rule || 0);
  setText('stat-url', bt.url || 0);
  setText('stat-hash', bt.hash || 0);

  if (iocMeta.generated_at) {
    var d = new Date(iocMeta.generated_at);
    setText('updated-time', d.toLocaleString('ko-KR'));
  }
}

function setText(id, val) {
  var el = document.getElementById(id);
  if (el) el.textContent = typeof val === 'number' ? val.toLocaleString() : val;
}

// ===== Charts =====
function renderCharts() {
  renderTypeBars();
  if (iocMeta.by_risk) {
    drawSeverityBars('risk-dist', iocMeta.by_risk);
  }
}

function renderTypeBars() {
  var container = document.getElementById('type-dist');
  if (!container) return;

  var types = [
    { key: 'cve', label: 'CVE', color: '#58a6ff', icon: TYPE_ICONS.cve },
    { key: 'ip', label: 'Malicious IP', color: '#FF8800', icon: TYPE_ICONS.ip },
    { key: 'rule', label: 'Detection Rule', color: '#44BB44', icon: TYPE_ICONS.rule },
    { key: 'url', label: 'Malicious URL', color: '#E040FB', icon: TYPE_ICONS.url },
    { key: 'hash', label: 'Malware Hash', color: '#FF5252', icon: TYPE_ICONS.hash },
  ];

  var bt = iocMeta.by_type || {};
  var maxCount = 1;
  types.forEach(function(t) {
    var c = bt[t.key] || 0;
    if (c > maxCount) maxCount = c;
  });

  var html = '';
  types.forEach(function(t) {
    var count = bt[t.key] || 0;
    var pct = ((count / maxCount) * 100).toFixed(1);
    html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
      '<span style="width:24px;font-size:16px;">' + t.icon + '</span>' +
      '<span style="width:90px;font-size:12px;color:#8b949e;">' + t.label + '</span>' +
      '<div style="flex:1;height:8px;background:#21262d;border-radius:4px;overflow:hidden;">' +
        '<div style="width:' + pct + '%;height:100%;background:' + t.color + ';border-radius:4px;"></div>' +
      '</div>' +
      '<span style="width:50px;font-size:12px;color:#e6edf3;text-align:right;">' + count.toLocaleString() + '</span>' +
    '</div>';
  });
  container.innerHTML = html;
}

function renderTagCloud() {
  var container = document.getElementById('tag-cloud');
  if (!container) return;

  var allIocs = getAllLoadedIocs();
  var tagCounts = {};
  allIocs.forEach(function(item) {
    (item.tags || []).forEach(function(tag) {
      tagCounts[tag] = (tagCounts[tag] || 0) + 1;
    });
  });

  var sorted = Object.entries(tagCounts).sort(function(a, b) { return b[1] - a[1]; }).slice(0, 15);

  var tagColors = {
    'KEV': '#FF4444', 'PoC': '#FF8800', 'Critical': '#FF4444',
    'High-EPSS': '#FF8800', 'has-rules': '#44BB44', 'official-rules': '#28A745',
    'multi-source': '#58a6ff', 'high-abuse': '#FF4444',
    'ai-generated': '#8b949e', 'official': '#28A745',
  };

  var html = '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
  sorted.forEach(function(entry) {
    var tag = entry[0], count = entry[1];
    var color = tagColors[tag] || '#58a6ff';
    html += '<span class="ioc-tag" style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '44;">' +
      escapeHtml(tag) + ' <span style="opacity:0.7;">' + count + '</span></span>';
  });
  html += '</div>';
  container.innerHTML = html;
}

// ===== Type Tabs =====
function renderTypeTabCounts() {
  var bt = iocMeta.by_type || {};
  IOC_TYPES.forEach(function(t) {
    var el = document.getElementById('tab-count-' + t);
    if (el) {
      var loaded = typeCache[t];
      el.textContent = (loaded ? loaded.length : (bt[t] || 0)).toLocaleString();
    }
  });
  var totalEl = document.getElementById('tab-count-all');
  if (totalEl) totalEl.textContent = (iocMeta.total || 0).toLocaleString();
}

function selectTypeTab(type) {
  activeFilters.type = type;

  // 탭 active 상태 업데이트
  document.querySelectorAll('.type-tab').forEach(function(el) {
    el.classList.toggle('active', el.dataset.type === type);
  });

  // 선택 타입이 아직 로드 안 됐으면 로드
  if (type && !typeCache[type] && !typeLoading[type]) {
    showLoading(true);
    loadSingleType(type).then(function() {
      showLoading(false);
      applyFilters();
    });
    return;
  }

  applyFilters();
}

// ===== Filtering =====
function applyFilters() {
  var search = activeFilters.search.toLowerCase();
  var typeFilter = activeFilters.type;

  // 소스 데이터 결정
  var source;
  if (typeFilter && typeCache[typeFilter]) {
    source = typeCache[typeFilter];
  } else if (typeFilter && !typeCache[typeFilter]) {
    source = []; // 아직 로드 안됨
  } else {
    source = getAllLoadedIocs();
  }

  filteredIocs = source.filter(function(item) {
    if (!activeFilters.risk.has(item.risk || 'Low')) return false;
    if (search) {
      var haystack = (item.indicator + ' ' + item.title + ' ' + (item.tags || []).join(' ')).toLowerCase();
      if (haystack.indexOf(search) === -1) return false;
    }
    return true;
  });

  filteredIocs.sort(function(a, b) {
    var va, vb;
    switch (sortField) {
      case 'score': va = a.score || 0; vb = b.score || 0; break;
      case 'indicator': va = a.indicator || ''; vb = b.indicator || ''; break;
      case 'risk': va = riskOrder(a.risk); vb = riskOrder(b.risk); break;
      case 'date': va = a.date || ''; vb = b.date || ''; break;
      default: va = a.date || ''; vb = b.date || '';
    }
    if (va < vb) return sortDir;
    if (va > vb) return -sortDir;
    return 0;
  });

  currentPage = 1;
  renderTable();
  renderPagination();
  renderTagCloud();
}

function riskOrder(risk) {
  var order = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  return order[risk] || 0;
}

// ===== Table =====
function renderTable() {
  var tbody = document.getElementById('ioc-table-body');
  if (!tbody) return;

  var start = (currentPage - 1) * PAGE_SIZE;
  var page = filteredIocs.slice(start, start + PAGE_SIZE);

  if (page.length === 0) {
    var isLoading = false;
    for (var k in typeLoading) { if (typeLoading[k]) isLoading = true; }
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><div class="icon">' +
      (isLoading ? '&#9203;' : '&#128269;') + '</div><p>' +
      (isLoading ? '데이터 로딩 중...' : '조건에 맞는 IOC가 없습니다.') + '</p></td></tr>';
    return;
  }

  tbody.innerHTML = page.map(function(item) {
    var riskClass = 'badge-' + (item.risk || 'low').toLowerCase();
    var typeIcon = TYPE_ICONS[item.ioc_type] || '';
    var typeLabel = TYPE_LABELS[item.ioc_type] || item.ioc_type;
    var dateStr = item.date ? new Date(item.date).toLocaleDateString('ko-KR') : '-';

    var tagsHtml = (item.tags || []).slice(0, 3).map(function(t) {
      return '<span class="ioc-tag-sm">' + escapeHtml(t) + '</span>';
    }).join('');

    var scoreDisplay = item.ioc_type === 'ip' ? (item.score || 0) : (item.score || 0).toFixed(1);

    var indicatorDisplay;
    if (item.ioc_type === 'ip') {
      indicatorDisplay = '<code>' + escapeHtml(item.indicator) + '</code>';
    } else if (item.ioc_type === 'url') {
      var shortUrl = item.indicator.length > 60 ? item.indicator.substring(0, 57) + '...' : item.indicator;
      indicatorDisplay = '<code style="font-size:11px;">' + escapeHtml(shortUrl) + '</code>';
    } else if (item.ioc_type === 'hash') {
      indicatorDisplay = '<code style="font-size:11px;">' + escapeHtml(item.indicator.substring(0, 16)) + '...</code>';
    } else {
      indicatorDisplay = '<span class="cve-id">' + escapeHtml(item.indicator) + '</span>';
    }

    return '<tr data-severity="' + (item.risk || 'Low') + '" onclick="showDetail(\'' + escapeAttr(item.indicator) + '\',\'' + (item.ioc_type || '') + '\')">' +
      '<td><span class="ioc-type-badge ioc-type-' + item.ioc_type + '">' + typeIcon + ' ' + typeLabel + '</span></td>' +
      '<td>' + indicatorDisplay + '</td>' +
      '<td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(item.title || '-') + '</td>' +
      '<td><span class="badge ' + riskClass + '">' + (item.risk || '-') + '</span></td>' +
      '<td class="score-cell">' + scoreDisplay + '</td>' +
      '<td>' + tagsHtml + '</td>' +
      '<td>' + dateStr + '</td>' +
    '</tr>';
  }).join('');
}

// ===== Pagination =====
function renderPagination() {
  var totalPages = Math.ceil(filteredIocs.length / PAGE_SIZE);
  var info = document.getElementById('page-info');
  var prevBtn = document.getElementById('prev-btn');
  var nextBtn = document.getElementById('next-btn');

  if (info) info.textContent = currentPage + ' / ' + totalPages + ' (' + filteredIocs.length.toLocaleString() + '건)';
  if (prevBtn) prevBtn.disabled = currentPage <= 1;
  if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
}

function changePage(delta) {
  var totalPages = Math.ceil(filteredIocs.length / PAGE_SIZE);
  currentPage = Math.max(1, Math.min(totalPages, currentPage + delta));
  renderTable();
  renderPagination();
  var tw = document.querySelector('.table-wrapper');
  if (tw) window.scrollTo({ top: tw.offsetTop - 80, behavior: 'smooth' });
}

// ===== Sorting =====
function sortBy(field) {
  if (sortField === field) {
    sortDir *= -1;
  } else {
    sortField = field;
    sortDir = -1;
  }
  applyFilters();
}

// ===== Detail Modal =====
function showDetail(indicator, iocType) {
  // 해당 타입 캐시에서 검색 (성능: 전체 스캔 대신 타입 한정)
  var items = iocType && typeCache[iocType] ? typeCache[iocType] : getAllLoadedIocs();
  var item = null;
  for (var i = 0; i < items.length; i++) {
    if (items[i].indicator === indicator) { item = items[i]; break; }
  }
  if (!item) return;

  document.getElementById('modal-title').textContent = item.indicator;

  var body = document.getElementById('modal-body');
  var riskClass = 'badge-' + (item.risk || 'low').toLowerCase();
  var detail = item.detail || {};
  var html = '';

  // Common info
  html += detailRow('Type', '<span class="ioc-type-badge ioc-type-' + item.ioc_type + '">' +
    (TYPE_ICONS[item.ioc_type] || '') + ' ' + (TYPE_LABELS[item.ioc_type] || item.ioc_type) + '</span>');
  html += detailRow('Risk', '<span class="badge ' + riskClass + '">' + (item.risk || '-') + '</span> Score: ' + (item.score || 0));
  html += detailRow('Date', item.date ? new Date(item.date).toLocaleString('ko-KR') : '-');

  // Tags
  if (item.tags && item.tags.length > 0) {
    var tagHtml = item.tags.map(function(t) {
      return '<span class="ioc-tag-sm">' + escapeHtml(t) + '</span>';
    }).join(' ');
    html += detailRow('Tags', tagHtml);
  }

  // Type-specific detail
  if (item.ioc_type === 'cve') {
    html += '<hr style="border-color:var(--border);margin:16px 0;">';
    html += detailRow('CVSS', (detail.cvss || 0).toFixed(1));
    html += detailRow('EPSS', ((detail.epss || 0) * 100).toFixed(2) + '%');
    html += detailRow('KEV', detail.is_kev ? 'YES' : 'No');
    if (detail.cwe && detail.cwe.length > 0) {
      html += detailRow('CWE', detail.cwe.join(', '));
    }
    if (detail.has_poc) {
      html += detailRow('PoC', 'Available');
    }
    if (detail.affected && detail.affected.length > 0) {
      var affHtml = detail.affected.map(function(a) {
        return escapeHtml(a.vendor || '') + ' / ' + escapeHtml(a.product || '');
      }).join('<br>');
      html += detailRow('Affected', affHtml);
    }
    if (item.related_rules && item.related_rules.length > 0) {
      html += detailRow('Rules', item.related_rules.map(function(r) {
        return '<span class="ioc-tag-sm">' + escapeHtml(r) + '</span>';
      }).join(' '));
    }
    if (isSafeUrl(detail.report_url)) {
      html += '<a href="' + escapeHtml(detail.report_url) + '" target="_blank" rel="noopener noreferrer" class="report-link">AI 상세 분석 리포트 보기</a>';
    }
  } else if (item.ioc_type === 'ip') {
    html += '<hr style="border-color:var(--border);margin:16px 0;">';
    html += detailRow('Category', escapeHtml(detail.category || '-'));
    if (detail.sources && detail.sources.length > 0) {
      html += detailRow('Sources', detail.sources.map(function(s) {
        return '<span class="ioc-tag-sm">' + escapeHtml(s) + '</span>';
      }).join(' '));
    }
    if (detail.abuse_confidence != null) {
      html += detailRow('AbuseIPDB', detail.abuse_confidence + '% confidence');
    }
    if (detail.abuse_reports != null) {
      html += detailRow('Reports', detail.abuse_reports + ' reports');
    }
  } else if (item.ioc_type === 'url') {
    html += '<hr style="border-color:var(--border);margin:16px 0;">';
    html += detailRow('Source', escapeHtml(detail.source || '-'));
    if (detail.threat) {
      html += detailRow('Threat', escapeHtml(detail.threat));
    }
    if (detail.target) {
      html += detailRow('Target', escapeHtml(detail.target));
    }
    if (detail.tags && detail.tags.length > 0) {
      html += detailRow('Feed Tags', detail.tags.map(function(t) {
        return '<span class="ioc-tag-sm">' + escapeHtml(t) + '</span>';
      }).join(' '));
    }
    if (isSafeUrl(item.indicator)) {
      html += '<div style="margin-top:12px;"><span class="detail-label" style="display:block;margin-bottom:8px;">URL</span>' +
        '<pre class="rule-preview">' + escapeHtml(item.indicator) + '</pre></div>';
    }
  } else if (item.ioc_type === 'hash') {
    html += '<hr style="border-color:var(--border);margin:16px 0;">';
    html += detailRow('Source', escapeHtml(detail.source || '-'));
    if (detail.signature) {
      html += detailRow('Signature', escapeHtml(detail.signature));
    }
    if (detail.file_name) {
      html += detailRow('File Name', escapeHtml(detail.file_name));
    }
    if (detail.file_type) {
      html += detailRow('File Type', escapeHtml(detail.file_type));
    }
    html += '<div style="margin-top:12px;"><span class="detail-label" style="display:block;margin-bottom:8px;">SHA256</span>' +
      '<pre class="rule-preview">' + escapeHtml(detail.sha256 || item.indicator) + '</pre></div>';
  } else if (item.ioc_type === 'rule') {
    html += '<hr style="border-color:var(--border);margin:16px 0;">';
    html += detailRow('Engine', escapeHtml(detail.engine || '-').toUpperCase());
    html += detailRow('CVE', '<span class="cve-id">' + escapeHtml(detail.cve_id || '-') + '</span>');
    html += detailRow('Source', detail.is_official ? '<span class="badge" style="background:#28A74533;color:#28A745;">Official</span>' : '<span class="badge" style="background:#8b949e33;color:#8b949e;">AI Generated</span>');
    if (detail.rule_preview) {
      html += '<div style="margin-top:12px;">' +
        '<span class="detail-label" style="display:block;margin-bottom:8px;">RULE PREVIEW</span>' +
        '<pre class="rule-preview">' + escapeHtml(detail.rule_preview) + '</pre>' +
      '</div>';
    }
    if (isSafeUrl(detail.report_url)) {
      html += '<a href="' + escapeHtml(detail.report_url) + '" target="_blank" rel="noopener noreferrer" class="report-link">Full Report</a>';
    }
  }

  body.innerHTML = html;
  document.getElementById('modal-overlay').classList.add('active');
}

function detailRow(label, value) {
  return '<div class="detail-row">' +
    '<span class="detail-label">' + label + '</span>' +
    '<span class="detail-value">' + value + '</span>' +
  '</div>';
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('active');
}

// ===== Export =====
function exportCSV() {
  var headers = ['Type', 'Indicator', 'Title', 'Risk', 'Score', 'Tags', 'Date'];
  var rows = filteredIocs.map(function(item) {
    return [
      item.ioc_type || '',
      item.indicator || '',
      '"' + (item.title || '').replace(/"/g, '""') + '"',
      item.risk || '',
      item.score || 0,
      '"' + (item.tags || []).join(', ') + '"',
      item.date || '',
    ].join(',');
  });

  var csv = headers.join(',') + '\n' + rows.join('\n');
  downloadFile(csv, 'argus-ioc-' + todayStr() + '.csv', 'text/csv');
}

function exportJSON() {
  var data = filteredIocs.map(function(item) {
    return {
      type: item.ioc_type,
      indicator: item.indicator,
      title: item.title,
      risk: item.risk,
      score: item.score,
      tags: item.tags,
      date: item.date,
      detail: item.detail,
    };
  });
  var json = JSON.stringify(data, null, 2);
  downloadFile(json, 'argus-ioc-' + todayStr() + '.json', 'application/json');
}

function downloadFile(content, filename, mimeType) {
  var blob = new Blob([content], { type: mimeType + ';charset=utf-8' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

// ===== Utils =====
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeAttr(str) {
  if (!str) return '';
  return str.replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

function isSafeUrl(url) {
  if (!url) return false;
  try {
    var parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch (e) {
    return false;
  }
}

// ===== Events =====
document.addEventListener('DOMContentLoaded', function() {
  init();

  // Search
  var searchEl = document.getElementById('search-input');
  if (searchEl) {
    var timer;
    searchEl.addEventListener('input', function() {
      clearTimeout(timer);
      timer = setTimeout(function() {
        activeFilters.search = searchEl.value;
        applyFilters();
      }, 300);
    });
  }

  // Type tabs
  document.querySelectorAll('.type-tab').forEach(function(tab) {
    tab.addEventListener('click', function() {
      selectTypeTab(tab.dataset.type);
    });
  });

  // Risk filter buttons
  document.querySelectorAll('.severity-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var risk = btn.dataset.severity;
      if (activeFilters.risk.has(risk)) {
        activeFilters.risk.delete(risk);
        btn.classList.remove('active');
      } else {
        activeFilters.risk.add(risk);
        btn.classList.add('active');
      }
      applyFilters();
    });
  });

  // Export buttons
  var csvBtn = document.getElementById('export-csv-btn');
  if (csvBtn) csvBtn.addEventListener('click', exportCSV);
  var jsonBtn = document.getElementById('export-json-btn');
  if (jsonBtn) jsonBtn.addEventListener('click', exportJSON);

  // Modal close
  var overlay = document.getElementById('modal-overlay');
  if (overlay) overlay.addEventListener('click', function(e) {
    if (e.target === e.currentTarget) closeModal();
  });

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeModal();
  });
});
