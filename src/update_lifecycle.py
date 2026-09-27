#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import re
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple

import requests

from logger import logger

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_ROOT, "data")
PRODUCTS_PATH = os.path.join(DATA_DIR, "lifecycle_products.json")
ALIASES_PATH = os.path.join(DATA_DIR, "lifecycle_aliases.json")
OUT_PATH = os.path.join(DATA_DIR, "lifecycle.json")

API_BASE = "https://endoflife.date/api/v1"
API_MAJOR = "1"
PROVIDER = "endoflife.date"
SCHEMA = 1
LICENSE = {
    "name": "MIT",
    "notice": "Copyright 2020 endoflife.date contributors",
    "url": "https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE",
    "text": (
        "Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\n"
        "The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\n"
        "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."
    ),
}
STATUSES = ("ACTIVE", "SECURITY_SUPPORT", "EXTENDED_SUPPORT", "EOL", "UNKNOWN")
MAX_FAILED_RATIO = 0.2

_TIMEOUT = 30
_RETRIES = 3
_UA = {"User-Agent": "argus-lifecycle", "Accept": "application/json"}
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

RELEASE_FIELDS = (
    "product_slug", "vendor", "product", "cycle", "release_date", "support_end",
    "security_support_end", "extended_support_end", "eol_date", "latest_version",
    "latest_release_date", "lts", "lifecycle_status", "source_provider", "source_url",
    "fetched_at",
    "cycle_label", "codename", "support_ended", "extended_support_ended", "eol_reached",
)
_DATE_FIELDS = ("release_date", "support_end", "security_support_end",
                "extended_support_end", "eol_date", "latest_release_date")
_FLAG_FIELDS = ("lts", "support_ended", "extended_support_ended", "eol_reached")


class LifecycleError(Exception):
    pass


def _text(value) -> Optional[str]:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _url(value) -> Optional[str]:
    v = _text(value)
    return v if v and v.startswith(("https://", "http://")) else None


def _date(value, where: str, problems: List[str]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str) and _DATE_RE.match(value):
        try:
            dt.date.fromisoformat(value)
            return value
        except ValueError:
            pass
    problems.append(f"{where}: 날짜 형식이 아님 ({value!r})")
    return None


def _flag(value, where: str, problems: List[str]) -> Optional[bool]:
    if value is None or isinstance(value, bool):
        return value
    problems.append(f"{where}: 불리언이 아님 ({value!r})")
    return None


def phase_status(label: Optional[str], override: Optional[str] = None) -> str:
    if override in STATUSES:
        return override
    text = (label or "").lower()
    if "security" in text:
        return "SECURITY_SUPPORT"
    if "extended" in text:
        return "EXTENDED_SUPPORT"
    return "UNKNOWN"


def _reached(date: Optional[str], flag: Optional[bool], today: str) -> Optional[bool]:
    if date:
        return date <= today
    if isinstance(flag, bool):
        return flag
    return None


def _override(meta: Dict) -> Optional[str]:
    return (meta.get("phase_status") or {}).get("eol")


def compute_status(rec: Dict, meta: Dict, today: str) -> str:
    labels = meta.get("labels") or {}
    eol = _reached(rec.get("eol_date"), rec.get("eol_reached"), today)
    if eol is None:
        return "UNKNOWN"
    if eol:
        ext = rec.get("extended_support_ended")
        if labels.get("eoes") and isinstance(ext, bool) \
                and _reached(rec.get("extended_support_end"), ext, today) is False:
            return "EXTENDED_SUPPORT"
        return "EOL"
    if labels.get("eoas"):
        eoas = _reached(rec.get("support_end"), rec.get("support_ended"), today)
        if eoas is None:
            return "UNKNOWN"
        if not eoas:
            return "ACTIVE"
        return phase_status(labels.get("eol"), _override(meta))
    return "ACTIVE"


def security_support_end(rec: Dict, meta: Dict) -> Optional[str]:
    labels = meta.get("labels") or {}
    if not labels.get("eoas"):
        return None
    if phase_status(labels.get("eol"), _override(meta)) == "SECURITY_SUPPORT":
        return rec.get("eol_date")
    if "security" in labels["eoas"].lower():
        return rec.get("support_end")
    return None


def normalize_product(cfg: Dict, raw: Dict, last_modified: Optional[str],
                      fetched_at: str, today: str) -> Tuple[Dict, List[Dict], List[str]]:
    slug = cfg["slug"]
    problems: List[str] = []
    if not isinstance(raw, dict):
        return {}, [], [f"{slug}: 제품 응답이 객체가 아님"]

    labels_raw = raw.get("labels") if isinstance(raw.get("labels"), dict) else {}
    labels = {k: _text(labels_raw.get(k)) for k in ("eoas", "eol", "eoes")}
    if not labels["eol"]:
        problems.append(f"{slug}: labels.eol 없음")
    links = raw.get("links") if isinstance(raw.get("links"), dict) else {}
    source_url = _url(links.get("html"))
    if not source_url:
        problems.append(f"{slug}: links.html 없음")

    identifiers = {"cpe": [], "purl": []}
    for ident in raw.get("identifiers") or []:
        if isinstance(ident, dict) and ident.get("type") in identifiers:
            value = _text(ident.get("id"))
            if value and value not in identifiers[ident["type"]]:
                identifiers[ident["type"]].append(value)

    meta = {
        "slug": slug,
        "label": _text(raw.get("label")) or slug,
        "vendor": cfg.get("vendor"),
        "aliases": [a for a in raw.get("aliases") or [] if isinstance(a, str)],
        "labels": labels,
        "identifiers": identifiers,
        "source_url": source_url,
        "original_source_url": _url(links.get("releasePolicy")),
        "source_last_modified": _text(last_modified),
        "fetched_at": fetched_at,
    }
    if cfg.get("phase_status"):
        meta["phase_status"] = cfg["phase_status"]

    releases = raw.get("releases")
    if not isinstance(releases, list) or not releases:
        problems.append(f"{slug}: releases 없음")
        releases = []

    has_eoas, has_eoes = bool(labels["eoas"]), bool(labels["eoes"])
    out: List[Dict] = []
    seen = set()
    for i, rel in enumerate(releases):
        if not isinstance(rel, dict):
            problems.append(f"{slug} releases[{i}]: 객체가 아님")
            continue
        cycle = _text(rel.get("name"))
        if not cycle:
            problems.append(f"{slug} releases[{i}]: name 없음")
            continue
        if cycle in seen:
            problems.append(f"{slug} {cycle}: 사이클 중복")
            continue
        seen.add(cycle)
        where = f"{slug} {cycle}"
        latest = rel.get("latest") if isinstance(rel.get("latest"), dict) else {}
        rec = {
            "product_slug": slug,
            "vendor": cfg.get("vendor"),
            "product": meta["label"],
            "cycle": cycle,
            "release_date": _date(rel.get("releaseDate"), f"{where} releaseDate", problems),
            "support_end": _date(rel.get("eoasFrom"), f"{where} eoasFrom", problems)
                           if has_eoas else None,
            "security_support_end": None,
            "extended_support_end": _date(rel.get("eoesFrom"), f"{where} eoesFrom", problems)
                                    if has_eoes else None,
            "eol_date": _date(rel.get("eolFrom"), f"{where} eolFrom", problems),
            "latest_version": _text(latest.get("name")),
            "latest_release_date": _date(latest.get("date"), f"{where} latest.date", problems),
            "lts": _flag(rel.get("isLts"), f"{where} isLts", problems),
            "lifecycle_status": "UNKNOWN",
            "source_provider": PROVIDER,
            "source_url": source_url,
            "fetched_at": fetched_at,
            "cycle_label": _text(rel.get("label")) or cycle,
            "codename": _text(rel.get("codename")),
            "support_ended": _flag(rel.get("isEoas"), f"{where} isEoas", problems)
                             if has_eoas else None,
            "extended_support_ended": _flag(rel.get("isEoes"), f"{where} isEoes", problems)
                                      if has_eoes else None,
            "eol_reached": _flag(rel.get("isEol"), f"{where} isEol", problems),
        }
        if rec["eol_reached"] is None:
            problems.append(f"{where}: isEol 없음")
        rec["security_support_end"] = security_support_end(rec, meta)
        rec["lifecycle_status"] = compute_status(rec, meta, today)
        out.append(rec)
    return meta, out, problems


def _get_json(session, url: str) -> Dict:
    last = None
    for attempt in range(_RETRIES):
        try:
            resp = session.get(url, timeout=_TIMEOUT, headers=_UA)
            if resp.status_code == 404:
                raise LifecycleError(f"{url}: 404")
            resp.raise_for_status()
            return resp.json()
        except LifecycleError:
            raise
        except (requests.exceptions.RequestException, ValueError) as e:
            last = e
            if attempt < _RETRIES - 1:
                time.sleep(2 * (2 ** attempt))
    raise LifecycleError(f"{url}: {last}")


def _result(payload, url: str):
    if not isinstance(payload, dict):
        raise LifecycleError(f"{url}: 응답이 객체가 아님")
    version = str(payload.get("schema_version") or "")
    if version.split(".")[0] != API_MAJOR:
        raise LifecycleError(f"{url}: API 스키마 {version or '없음'} — v{API_MAJOR}.x 만 읽는다")
    return payload.get("result")


def fetch_catalog(session) -> Dict[str, str]:
    url = f"{API_BASE}/products"
    result = _result(_get_json(session, url), url)
    if not isinstance(result, list) or not result:
        raise LifecycleError(f"{url}: 제품 목록이 비었다")
    names: Dict[str, str] = {}
    for item in result:
        if isinstance(item, dict) and _text(item.get("name")):
            names[item["name"]] = item["name"]
    for item in result:
        if isinstance(item, dict) and _text(item.get("name")):
            for alias in item.get("aliases") or []:
                if isinstance(alias, str):
                    names.setdefault(alias, item["name"])
    return names


def fetch_product(session, slug: str) -> Tuple[Dict, Optional[str]]:
    url = f"{API_BASE}/products/{slug}"
    payload = _get_json(session, url)
    result = _result(payload, url)
    if not isinstance(result, dict):
        raise LifecycleError(f"{url}: result 가 객체가 아님")
    return result, payload.get("last_modified")


def load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_config(path: str = PRODUCTS_PATH) -> List[Dict]:
    config = load_json(path)
    items = config.get("products") if isinstance(config, dict) else None
    if not isinstance(items, list) or not items:
        raise LifecycleError(f"{path}: products 목록이 없다")
    seen = set()
    for item in items:
        slug = item.get("slug") if isinstance(item, dict) else None
        if not _text(slug) or slug != slug.strip().lower():
            raise LifecycleError(f"{path}: slug 가 올바르지 않다 ({item!r})")
        if slug in seen:
            raise LifecycleError(f"{path}: slug 중복 {slug}")
        seen.add(slug)
        override = item.get("phase_status")
        if override is not None:
            if not isinstance(override, dict) or override.get("eol") not in STATUSES \
                    or not _url(override.get("basis")):
                raise LifecycleError(f"{path}: {slug}.phase_status 는 "
                                     f"{{'eol': <상태>, 'basis': <정책 URL>}} 이어야 한다")
    return items


def load_previous(path: str = OUT_PATH) -> Optional[Dict]:
    try:
        data = load_json(path)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        logger.warning(f"직전 lifecycle.json 을 읽지 못함({e}) → 이월 없이 진행")
        return None
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        logger.warning(f"직전 lifecycle.json 스키마 {data.get('schema') if isinstance(data, dict) else '?'}"
                       f" ≠ {SCHEMA} → 이월 없이 진행")
        return None
    return data


def _group(releases: List[Dict]) -> Dict[str, List[Dict]]:
    out: Dict[str, List[Dict]] = {}
    for rec in releases or []:
        out.setdefault(rec.get("product_slug"), []).append(rec)
    return out


def _without_fetched(meta: Dict, recs: List[Dict]):
    return ({k: v for k, v in meta.items() if k != "fetched_at"},
            [{k: v for k, v in r.items() if k != "fetched_at"} for r in recs])


def build(config: List[Dict], previous: Optional[Dict], now: dt.datetime,
          catalog_fn: Callable[[], Dict[str, str]],
          product_fn: Callable[[str], Tuple[Dict, Optional[str]]]) -> Tuple[Dict, Dict]:
    fetched_at = now.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    today = now.astimezone(dt.timezone.utc).date().isoformat()
    catalog = catalog_fn()

    prev_products = (previous or {}).get("products") or {}
    prev_releases = _group((previous or {}).get("releases"))
    products: Dict[str, Dict] = {}
    by_slug: Dict[str, List[Dict]] = {}
    unavailable: List[Dict] = []
    report = {"fetched": [], "failed": {}, "carried": [], "dropped": [], "warnings": []}

    for cfg in config:
        slug = cfg["slug"]
        upstream = catalog.get(slug)
        if upstream is None:
            unavailable.append({
                "slug": slug,
                "name": cfg.get("name") or slug,
                "vendor": cfg.get("vendor"),
                "reason": "endoflife.date 에 없는 제품",
                "identifiers": {"cpe": list(cfg.get("match_cpe") or []), "purl": []},
            })
            continue
        if upstream != slug:
            report["warnings"].append(f"{slug}: upstream 에서는 '{upstream}' 의 별칭이다 — "
                                      f"lifecycle_products.json 의 slug 를 고쳐야 한다")
        try:
            raw, last_modified = product_fn(upstream)
            meta, recs, problems = normalize_product(cfg, raw, last_modified, fetched_at, today)
            if problems:
                raise LifecycleError("; ".join(problems[:5])
                                     + (f" 외 {len(problems) - 5}건" if len(problems) > 5 else ""))
        except LifecycleError as e:
            report["failed"][slug] = str(e)
            if slug in prev_products and prev_releases.get(slug):
                meta = prev_products[slug]
                recs = [dict(r, lifecycle_status=compute_status(r, meta, today))
                        for r in prev_releases[slug]]
                products[slug], by_slug[slug] = meta, recs
                report["carried"].append(slug)
            else:
                report["dropped"].append(slug)
            continue

        if slug in prev_products and \
                _without_fetched(meta, recs) == _without_fetched(prev_products[slug],
                                                                 prev_releases.get(slug, [])):
            kept = prev_products[slug].get("fetched_at") or fetched_at
            meta["fetched_at"] = kept
            recs = [dict(r, fetched_at=kept) for r in recs]
        products[slug], by_slug[slug] = meta, recs
        report["fetched"].append(slug)

    available = len(config) - len(unavailable)
    if available and len(report["failed"]) > available * MAX_FAILED_RATIO:
        raise LifecycleError(f"제품 {len(report['failed'])}/{available}개 수집 실패 — "
                             f"일시 장애나 API 형식 변경으로 보고 기존 데이터를 그대로 둔다")

    order = [c["slug"] for c in config if c["slug"] in products]
    dataset = {
        "schema": SCHEMA,
        "source_provider": PROVIDER,
        "source_api": f"{API_BASE}/",
        "license": LICENSE,
        "generated_at": fetched_at,
        "products": {slug: products[slug] for slug in sorted(order)},
        "unavailable": unavailable,
        "releases": [rec for slug in sorted(order) for rec in by_slug[slug]],
    }
    return dataset, report


def validate(dataset: Dict) -> List[str]:
    problems: List[str] = []
    products = dataset.get("products")
    releases = dataset.get("releases")
    if not isinstance(products, dict) or not products:
        return ["products 가 비었다"]
    if not isinstance(releases, list) or not releases:
        return ["releases 가 비었다"]
    for slug, meta in products.items():
        if not _url(meta.get("source_url")):
            problems.append(f"{slug}: source_url 없음")
        if not _text(meta.get("fetched_at")):
            problems.append(f"{slug}: fetched_at 없음")
    counts: Dict[str, int] = {}
    keys = set()
    for rec in releases:
        where = f"{rec.get('product_slug')} {rec.get('cycle')}"
        missing = [f for f in RELEASE_FIELDS if f not in rec]
        if missing:
            problems.append(f"{where}: 필드 없음 {missing}")
            continue
        if rec["product_slug"] not in products:
            problems.append(f"{where}: products 에 없는 제품")
        if (rec["product_slug"], rec["cycle"]) in keys:
            problems.append(f"{where}: 중복")
        keys.add((rec["product_slug"], rec["cycle"]))
        if rec["lifecycle_status"] not in STATUSES:
            problems.append(f"{where}: 상태 {rec['lifecycle_status']!r}")
        for field in _DATE_FIELDS:
            v = rec[field]
            if v is not None and not (isinstance(v, str) and _DATE_RE.match(v)):
                problems.append(f"{where}: {field}={v!r}")
        for field in _FLAG_FIELDS:
            if rec[field] is not None and not isinstance(rec[field], bool):
                problems.append(f"{where}: {field}={rec[field]!r}")
        if rec["source_provider"] != PROVIDER or not _url(rec["source_url"]) \
                or not _text(rec["fetched_at"]):
            problems.append(f"{where}: 출처·수집시각 없음")
        counts[rec["product_slug"]] = counts.get(rec["product_slug"], 0) + 1
    for slug in products:
        if not counts.get(slug):
            problems.append(f"{slug}: 릴리스 0개")
    return problems


def validate_aliases(aliases, known: set) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    if not isinstance(aliases, dict):
        return ["별칭 파일이 객체가 아님"], warnings

    def need_slug(slug, where):
        if not isinstance(slug, str) or not slug:
            errors.append(f"{where}: 제품 slug 가 없다")
        elif slug not in known:
            warnings.append(f"{where}: lifecycle_products.json 에 없는 제품 '{slug}'")

    for section in ("vendor_aliases", "overrides", "product_vendors", "version_rewrites"):
        if not isinstance(aliases.get(section, {}), dict):
            errors.append(f"{section}: 객체여야 한다")
    for key, value in (aliases.get("vendor_aliases") or {}).items():
        if not isinstance(value, str) or not value:
            errors.append(f"vendor_aliases.{key}: 문자열이어야 한다")
    for key, value in (aliases.get("overrides") or {}).items():
        if key.count(":") not in (1, 2):
            errors.append(f"overrides.{key}: 'vendor:product' 또는 'vendor:product:version' 형식이어야 한다")
        if value is None:
            continue
        if isinstance(value, str):
            need_slug(value, f"overrides.{key}")
        elif isinstance(value, dict):
            need_slug(value.get("product"), f"overrides.{key}")
            if not isinstance(value.get("cycles", []), list):
                errors.append(f"overrides.{key}.cycles: 목록이어야 한다")
        else:
            errors.append(f"overrides.{key}: 문자열·객체·null 만 허용")
    for slug, vendors in (aliases.get("product_vendors") or {}).items():
        need_slug(slug, f"product_vendors.{slug}")
        if not isinstance(vendors, list) or not all(isinstance(v, str) for v in vendors):
            errors.append(f"product_vendors.{slug}: 문자열 목록이어야 한다")
    for i, rule in enumerate(aliases.get("patterns") or []):
        where = f"patterns[{i}]"
        if not isinstance(rule, dict):
            errors.append(f"{where}: 객체여야 한다")
            continue
        need_slug(rule.get("lifecycle"), where)
        if not isinstance(rule.get("vendor"), str) or not isinstance(rule.get("cycle"), str):
            errors.append(f"{where}: vendor·cycle 이 필요하다")
        try:
            re.compile(rule.get("product") or "")
        except re.error as e:
            errors.append(f"{where}.product: 정규식 오류 {e}")
        if not str(rule.get("product") or "").startswith("^") \
                or not str(rule.get("product") or "").endswith("$"):
            errors.append(f"{where}.product: ^…$ 로 전체 일치를 강제해야 한다")
    for slug, rules in (aliases.get("version_rewrites") or {}).items():
        need_slug(slug, f"version_rewrites.{slug}")
        for j, rule in enumerate(rules if isinstance(rules, list) else []):
            try:
                re.compile(rule.get("from") or "")
            except (re.error, AttributeError) as e:
                errors.append(f"version_rewrites.{slug}[{j}]: 정규식 오류 {e}")
    return errors, warnings


def dump(dataset: Dict) -> str:
    def line(value) -> str:
        return json.dumps(value, ensure_ascii=False)

    def block(items: List[str], indent: str = "  ") -> List[str]:
        return [f"{indent}{s}{',' if i < len(items) - 1 else ''}" for i, s in enumerate(items)]

    parts = ["{"]
    for key, value in dataset.items():
        if key not in ("products", "unavailable", "releases"):
            parts.append(f" {line(key)}: {line(value)},")
    parts.append(' "products": {')
    parts += block([f"{line(slug)}: {line(meta)}" for slug, meta in dataset["products"].items()])
    parts.append(" },")
    parts.append(' "unavailable": [')
    parts += block([line(u) for u in dataset["unavailable"]])
    parts.append(" ],")
    parts.append(' "releases": [')
    parts += block([line(r) for r in dataset["releases"]])
    parts.append(" ]")
    parts.append("}")
    text = "\n".join(parts) + "\n"
    if json.loads(text) != dataset:
        raise LifecycleError("직렬화 결과가 원본과 다르다")
    return text


def write_atomic(path: str, text: str) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def _comparable(dataset: Optional[Dict]) -> Optional[Dict]:
    if dataset is None:
        return None
    return {k: v for k, v in dataset.items() if k != "generated_at"}


def diff_lines(previous: Optional[Dict], dataset: Dict) -> List[str]:
    old = _group((previous or {}).get("releases"))
    new = _group(dataset.get("releases"))
    old_meta = (previous or {}).get("products") or {}
    lines = []
    for slug in sorted(set(old) | set(new)):
        a = {r["cycle"]: r for r in old.get(slug, [])}
        b = {r["cycle"]: r for r in new.get(slug, [])}
        added = [c for c in b if c not in a]
        removed = [c for c in a if c not in b]
        changed, moved = [], []
        for cycle in b:
            if cycle not in a:
                continue
            fa = {k: v for k, v in a[cycle].items() if k != "fetched_at"}
            fb = {k: v for k, v in b[cycle].items() if k != "fetched_at"}
            if fa != fb:
                changed.append(f"{cycle}({','.join(sorted(k for k in fb if fa.get(k) != fb.get(k)))})")
                if fa.get("lifecycle_status") != fb.get("lifecycle_status"):
                    moved.append(f"{cycle} {fa.get('lifecycle_status')}→{fb.get('lifecycle_status')}")
        meta_changed = slug in old_meta and slug in dataset["products"] and \
            _without_fetched(old_meta[slug], [])[0] != _without_fetched(dataset["products"][slug], [])[0]
        if not (added or removed or changed or meta_changed):
            continue
        bits = []
        if added:
            bits.append(f"추가 {', '.join(added)}")
        if removed:
            bits.append(f"삭제 {', '.join(removed)}")
        if moved:
            bits.append(f"상태 {'; '.join(moved)}")
        if changed:
            bits.append(f"값 변경 {len(changed)}건: {' '.join(changed[:6])}"
                        + (f" 외 {len(changed) - 6}건" if len(changed) > 6 else ""))
        if meta_changed:
            bits.append("제품 메타데이터 변경")
        lines.append(f"{slug}: " + " · ".join(bits))
    common = sorted(k for k in set(previous or {}) | set(dataset)
                    if k not in ("products", "releases", "generated_at")
                    and (previous or {}).get(k) != dataset.get(k))
    if previous is not None and common:
        lines.append(f"공통 항목 변경: {', '.join(common)}")
    return lines


def _status_counts(dataset: Dict) -> Dict[str, int]:
    counts = {s: 0 for s in STATUSES}
    for rec in dataset.get("releases") or []:
        counts[rec["lifecycle_status"]] = counts.get(rec["lifecycle_status"], 0) + 1
    return counts


def _emit(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")


def _step_summary(lines: List[str]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="endoflife.date → data/lifecycle.json")
    parser.add_argument("--dry-run", action="store_true", help="계산·검증만 하고 쓰지 않는다")
    args = parser.parse_args(argv)

    logger.info("=" * 60)
    logger.info("제품 수명주기 갱신 (endoflife.date API v1)")
    logger.info("=" * 60)
    code, changed = _run(args.dry_run)
    _emit("changed", "true" if changed else "false")
    return code


def _run(dry_run: bool) -> Tuple[int, bool]:
    try:
        config = load_config()
        errors, warnings = validate_aliases(load_json(ALIASES_PATH), {c["slug"] for c in config})
    except (OSError, ValueError, LifecycleError) as e:
        logger.error(f"설정 파일 오류: {e}")
        return 1, False
    for w in warnings:
        logger.warning(f"별칭 규칙: {w}")
    if errors:
        for e in errors:
            logger.error(f"별칭 규칙: {e}")
        return 1, False

    previous = load_previous()
    session = requests.Session()
    try:
        dataset, report = build(config, previous, dt.datetime.now(dt.timezone.utc),
                                lambda: fetch_catalog(session),
                                lambda slug: fetch_product(session, slug))
    except LifecycleError as e:
        logger.error(f"⛔ {e} — data/lifecycle.json 을 건드리지 않는다")
        _step_summary(["### 제품 수명주기 갱신 실패", f"- {e}", "- 기존 데이터를 그대로 유지했다"])
        return 1, False

    for slug, err in report["failed"].items():
        how = "직전 데이터 유지" if slug in report["carried"] else "직전 데이터 없음 → 제외"
        logger.warning(f"⚠️ {slug} 수집 실패({how}): {err}")
    for w in report["warnings"]:
        logger.warning(f"⚠️ {w}")

    problems = validate(dataset)
    if problems:
        for p in problems[:30]:
            logger.error(f"검증 실패: {p}")
        logger.error("⛔ 검증을 통과하지 못해 data/lifecycle.json 을 건드리지 않는다")
        return 1, False

    counts = _status_counts(dataset)
    changed = _comparable(previous) != _comparable(dataset)
    changes = diff_lines(previous, dataset) if changed else []
    unavailable = [u["slug"] for u in dataset["unavailable"]]

    logger.info(f"제품 {len(dataset['products'])}개 · 릴리스 {len(dataset['releases'])}개 · "
                + " · ".join(f"{k} {v}" for k, v in counts.items()))
    if unavailable:
        logger.info(f"endoflife.date 에 없는 제품(UNKNOWN): {', '.join(unavailable)}")
    if not changed:
        logger.info("변경 없음 — 파일을 쓰지 않는다")
    else:
        logger.info(f"변경 {len(changes)}건" + (" (최초 생성)" if previous is None else ""))
        for line in changes:
            logger.info(f"  {line}")

    summary = ["### 제품 수명주기 갱신",
               f"- 제품 {len(dataset['products'])}개 · 릴리스 {len(dataset['releases'])}개",
               "- 상태: " + " · ".join(f"{k} {v}" for k, v in counts.items()),
               f"- 변경: {'없음' if not changed else f'{len(changes)}건'}"]
    summary += [f"  - {line}" for line in changes]
    if report["failed"]:
        summary.append(f"- 수집 실패: {', '.join(report['failed'])} (이월: {', '.join(report['carried']) or '없음'})")
    if unavailable:
        summary.append(f"- endoflife.date 미제공: {', '.join(unavailable)}")
    _step_summary(summary)

    if not changed or dry_run:
        return 0, False
    write_atomic(OUT_PATH, dump(dataset))
    logger.info(f"저장: {OUT_PATH}")
    return 0, True


if __name__ == "__main__":
    sys.exit(main())
