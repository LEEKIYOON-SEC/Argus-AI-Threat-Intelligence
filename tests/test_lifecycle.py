import copy
import datetime as dt
import json
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import update_lifecycle as ul  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures")
AVAILABLE = ["debian", "kubernetes", "mysql", "nginx", "nodejs", "redis", "windows-server"]
NOW = dt.datetime(2026, 9, 27, 12, 0, tzinfo=dt.timezone.utc)
TODAY = "2026-09-27"
FETCHED = "2026-09-27T12:00:00Z"


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


def raw(slug):
    return load(os.path.join("endoflife_v1", f"{slug}.json"))


def normalize(slug, vendor="V", **cfg):
    return ul.normalize_product(dict(slug=slug, vendor=vendor, **cfg), raw(slug)["result"], FETCHED, TODAY)


def full_payload(slugs, edit=None):
    """/products/full 응답 — 제품별 v1 응답(fixture)의 result 를 모은다. edit(slug, result) 로 한 제품만 망가뜨린다."""
    items = []
    for slug in slugs:
        result = copy.deepcopy(raw(slug)["result"])
        if edit:
            edit(slug, result)
        items.append(result)
    return {"schema_version": "1.2.1", "generated_at": "2026-09-27T11:00:00+00:00", "total": len(items), "result": items}


def by_cycle(recs):
    return {r["cycle"]: r for r in recs}


class ParseTests(unittest.TestCase):
    """1. 정상 lifecycle JSON parsing"""

    def test_nginx_release_matches_normalized_schema(self):
        meta, recs, problems = normalize("nginx", vendor="F5")
        self.assertEqual(problems, [])
        rec = by_cycle(recs)["1.25"]
        self.assertEqual(list(rec)[:16], [
            "product_slug", "vendor", "product", "cycle", "release_date", "support_end",
            "security_support_end", "extended_support_end", "eol_date", "latest_version",
            "latest_release_date", "lts", "lifecycle_status", "source_provider", "source_url",
            "fetched_at"])
        self.assertEqual(rec, {
            "product_slug": "nginx", "vendor": "F5", "product": "nginx", "cycle": "1.25",
            "release_date": "2023-05-23", "support_end": None, "security_support_end": None,
            "extended_support_end": None, "eol_date": "2024-05-29", "latest_version": "1.25.5",
            "latest_release_date": "2024-04-16", "lts": False, "lifecycle_status": "EOL",
            "source_provider": "endoflife.date", "source_url": "https://endoflife.date/nginx",
            "fetched_at": FETCHED, "cycle_label": "1.25", "codename": None,
            "support_ended": None, "extended_support_ended": None, "eol_reached": True,
        })

    def test_product_meta_keeps_source_and_identifiers_but_not_icons(self):
        meta, _, _ = normalize("nginx", vendor="F5")
        self.assertEqual(meta["source_url"], "https://endoflife.date/nginx")
        self.assertTrue(meta["original_source_url"].startswith("https://www.nginx.com/"))
        self.assertEqual(meta["identifiers"]["cpe"], ["cpe:2.3:a:f5:nginx"])
        self.assertIn("pkg:deb/debian/nginx", meta["identifiers"]["purl"])
        self.assertEqual(meta["labels"], {"eoas": None, "eol": "Security Support", "eoes": None})
        self.assertNotIn("icon", json.dumps(meta))
        self.assertNotIn("source_last_modified", meta, "전체 응답에는 제품별 수정 시각이 없다 — 지어내지 않는다")

    def test_one_request_for_everything(self):
        session = FakeSession({"/products/full": full_payload(AVAILABLE)})
        items = ul.fetch_full(session)
        self.assertEqual(session.calls, 1)
        self.assertEqual([i["name"] for i in items], AVAILABLE)

    def test_names_include_aliases_but_names_win(self):
        items = full_payload(AVAILABLE)["result"]
        items[0]["aliases"] = ["kubernetes"]  # 다른 제품의 이름과 같은 별칭
        names = ul.upstream_names(items)
        self.assertEqual(names["k8s"], "kubernetes")
        self.assertEqual(names["windowsserver"], "windows-server")
        self.assertEqual(names["kubernetes"], "kubernetes")
        self.assertNotIn("openssh", names)

    def test_unknown_api_major_is_rejected(self):
        payload = full_payload(AVAILABLE)
        payload["schema_version"] = "2.0.0"
        with self.assertRaises(ul.LifecycleError):
            ul.fetch_full(FakeSession({"/products/full": payload}))

    def test_truncated_or_malformed_response_is_rejected(self):
        payload = full_payload(AVAILABLE)
        payload["total"] = len(AVAILABLE) + 5
        with self.assertRaisesRegex(ul.LifecycleError, "잘린 응답"):
            ul.fetch_full(FakeSession({"/products/full": payload}))
        payload = full_payload(AVAILABLE)
        del payload["result"][0]["name"]
        with self.assertRaisesRegex(ul.LifecycleError, "이름 없는 제품"):
            ul.fetch_full(FakeSession({"/products/full": payload}))
        with self.assertRaises(ul.LifecycleError):
            ul.fetch_full(FakeSession({"/products/full": dict(full_payload(AVAILABLE), result=[], total=0)}))

    @mock.patch("update_lifecycle.time.sleep")
    def test_transient_error_is_retried(self, _sleep):
        session = FakeSession({"/products/full": full_payload(AVAILABLE)}, fail_first=2)
        self.assertEqual(len(ul.fetch_full(session)), len(AVAILABLE))
        self.assertEqual(session.calls, 3)

    @mock.patch("update_lifecycle.time.sleep")
    def test_persistent_error_raises(self, _sleep):
        with self.assertRaises(ul.LifecycleError):
            ul.fetch_full(FakeSession({}, fail_first=99))


class NullTests(unittest.TestCase):
    """2. null field 처리 — 값이 없으면 추정하지 않고 null"""

    def test_open_ended_cycle_has_no_invented_dates(self):
        _, recs, _ = normalize("nginx")
        rec = by_cycle(recs)["1.31"]
        self.assertIsNone(rec["eol_date"])
        self.assertIs(rec["eol_reached"], False)
        self.assertIsNone(rec["support_end"])
        self.assertIsNone(rec["security_support_end"])
        self.assertIsNone(rec["extended_support_end"])
        self.assertEqual(rec["lifecycle_status"], "ACTIVE")

    def test_flag_without_date_stays_null_date(self):
        _, recs, _ = normalize("nodejs")
        rec = by_cycle(recs)["1"]
        self.assertIsNone(rec["support_end"])
        self.assertIs(rec["support_ended"], True)
        self.assertIsNone(rec["eol_date"])
        self.assertIs(rec["eol_reached"], True)
        self.assertEqual(rec["lifecycle_status"], "EOL")

    def test_active_support_end_unknown_but_not_over(self):
        _, recs, _ = normalize("redis")
        rec = by_cycle(recs)["8.10"]
        self.assertIsNone(rec["support_end"])
        self.assertIs(rec["support_ended"], False)
        self.assertEqual(rec["lifecycle_status"], "ACTIVE")

    def test_missing_optional_fields_become_null(self):
        payload = copy.deepcopy(raw("nginx")["result"])
        rel = payload["releases"][0]
        for key in ("latest", "codename", "releaseDate", "label"):
            rel.pop(key, None)
        _, recs, problems = ul.normalize_product({"slug": "nginx", "vendor": "F5"}, payload, FETCHED, TODAY)
        self.assertEqual(problems, [])
        rec = recs[0]
        self.assertIsNone(rec["latest_version"])
        self.assertIsNone(rec["latest_release_date"])
        self.assertIsNone(rec["release_date"])
        self.assertIsNone(rec["codename"])
        self.assertEqual(rec["cycle_label"], rec["cycle"])

    def test_missing_is_eol_is_a_problem_not_active(self):
        payload = copy.deepcopy(raw("nginx")["result"])
        del payload["releases"][0]["isEol"]
        _, recs, problems = ul.normalize_product({"slug": "nginx"}, payload, FETCHED, TODAY)
        self.assertTrue(any("isEol" in p for p in problems))
        self.assertEqual(recs[0]["lifecycle_status"], "UNKNOWN")

    def test_malformed_date_is_reported(self):
        payload = copy.deepcopy(raw("nginx")["result"])
        payload["releases"][2]["eolFrom"] = "2024/05/29"
        _, _, problems = ul.normalize_product({"slug": "nginx"}, payload, FETCHED, TODAY)
        self.assertTrue(any("eolFrom" in p for p in problems))


class StatusTests(unittest.TestCase):
    """3. EOL status 계산 — docs/js/lifecycle.js 와 같은 표"""

    def test_shared_status_table(self):
        table = load("lifecycle_status_cases.json")
        for case in table["cases"]:
            meta = {"labels": table["labels"][case["labels"]]}
            if case.get("phase_status"):
                meta["phase_status"] = case["phase_status"]
            with self.subTest(case["name"]):
                self.assertEqual(ul.compute_status(case["release"], meta, table["today"]), case["expect"])

    def test_statuses_from_real_responses(self):
        expected = {
            ("windows-server", "2019"): "SECURITY_SUPPORT",
            ("windows-server", "2016"): "SECURITY_SUPPORT",
            ("windows-server", "2012-r2"): "EXTENDED_SUPPORT",
            ("windows-server", "2008-r2-sp1"): "EOL",
            ("debian", "13"): "ACTIVE",
            ("debian", "12"): "UNKNOWN",
            ("debian", "11"): "EXTENDED_SUPPORT",
            ("mysql", "8.4"): "ACTIVE",
            ("mysql", "8.0"): "EOL",
            ("kubernetes", "1.37"): "ACTIVE",
            ("kubernetes", "1.34"): "UNKNOWN",
            ("kubernetes", "1.33"): "EOL",
            ("redis", "8.8"): "SECURITY_SUPPORT",
            ("nodejs", "22"): "SECURITY_SUPPORT",
            ("nodejs", "20"): "EXTENDED_SUPPORT",
        }
        for (slug, cycle), status in expected.items():
            with self.subTest(f"{slug} {cycle}"):
                _, recs, problems = normalize(slug)
                self.assertEqual(problems, [])
                self.assertEqual(by_cycle(recs)[cycle]["lifecycle_status"], status)

    def test_status_is_date_based_not_policy_guess(self):
        _, recs, _ = normalize("windows-server")
        rec = by_cycle(recs)["2016"]
        meta, _, _ = normalize("windows-server")
        self.assertEqual(ul.compute_status(rec, meta, "2027-01-11"), "SECURITY_SUPPORT")
        self.assertEqual(ul.compute_status(rec, meta, "2027-01-12"), "EXTENDED_SUPPORT")
        self.assertEqual(ul.compute_status(rec, meta, "2030-01-12"), "EOL")


class DateFieldTests(unittest.TestCase):
    """4. support / security support / extended support / EOL 날짜 구분"""

    def test_security_support_only_when_upstream_says_security(self):
        cases = {
            ("windows-server", "2019"): ("2024-01-09", "2029-01-09", "2029-01-09"),
            ("debian", "12"): ("2026-07-11", "2026-07-11", "2028-06-30"),
            ("mysql", "8.0"): ("2025-04-30", None, "2026-04-30"),
            ("kubernetes", "1.34"): ("2026-08-27", None, "2026-10-27"),
            ("nginx", "1.25"): (None, None, "2024-05-29"),
        }
        for (slug, cycle), (support, security, eol) in cases.items():
            with self.subTest(f"{slug} {cycle}"):
                _, recs, _ = normalize(slug)
                rec = by_cycle(recs)[cycle]
                self.assertEqual(rec["support_end"], support)
                self.assertEqual(rec["security_support_end"], security)
                self.assertEqual(rec["eol_date"], eol)

    def test_extended_support_fields(self):
        _, recs, _ = normalize("windows-server")
        rec = by_cycle(recs)
        self.assertEqual(rec["2012-r2"]["extended_support_end"], "2026-10-13")
        self.assertIs(rec["2012-r2"]["extended_support_ended"], False)
        self.assertEqual(rec["2008-r2-sp1"]["extended_support_end"], "2023-01-10")
        self.assertIs(rec["2008-r2-sp1"]["extended_support_ended"], True)
        self.assertIsNone(rec["2019"]["extended_support_end"])
        self.assertIsNone(rec["2019"]["extended_support_ended"])

    def test_products_without_extended_phase_never_get_extended_fields(self):
        _, recs, _ = normalize("mysql")
        for rec in recs:
            self.assertIsNone(rec["extended_support_end"])
            self.assertIsNone(rec["extended_support_ended"])

    def test_reviewed_phase_mapping_is_applied_only_when_configured(self):
        _, recs, _ = normalize("kubernetes")
        self.assertEqual(by_cycle(recs)["1.34"]["lifecycle_status"], "UNKNOWN")
        cfg = {"phase_status": {"eol": "SECURITY_SUPPORT", "basis": "https://example.org/k8s-policy"}}
        _, recs, _ = normalize("kubernetes", **cfg)
        rec = by_cycle(recs)["1.34"]
        self.assertEqual(rec["lifecycle_status"], "SECURITY_SUPPORT")
        self.assertEqual(rec["security_support_end"], "2026-10-27")


def broken(*slugs):
    """이 제품들의 첫 릴리스에서 isEol 을 지운다 — 정규화 문제로 '읽기 실패'가 된다."""
    def edit(slug, result):
        if slug in slugs:
            del result["releases"][0]["isEol"]
    return edit


def items_of(slugs=None, fail=()):
    return full_payload(slugs or AVAILABLE, broken(*fail))["result"]


CONFIG = [
    {"slug": "nginx", "vendor": "F5"},
    {"slug": "windows-server", "vendor": "Microsoft"},
    {"slug": "debian", "vendor": "Debian"},
    {"slug": "mysql", "vendor": "Oracle"},
    {"slug": "redis", "vendor": "Redis"},
    {"slug": "openssh", "vendor": "OpenBSD", "name": "OpenSSH", "match_cpe": ["cpe:2.3:a:openbsd:openssh"]},
]
class BuildTests(unittest.TestCase):
    def build(self, previous=None, fail=(), config=CONFIG, now=NOW):
        return ul.build(config, previous, now, items_of(fail=fail))

    def test_unavailable_product_is_not_invented(self):
        dataset, _ = self.build()
        self.assertNotIn("openssh", dataset["products"])
        self.assertFalse(any(r["product_slug"] == "openssh" for r in dataset["releases"]))
        self.assertEqual(dataset["unavailable"][0]["slug"], "openssh")
        self.assertEqual(dataset["unavailable"][0]["identifiers"]["cpe"], ["cpe:2.3:a:openbsd:openssh"])

    def test_dataset_passes_validation_and_round_trips(self):
        dataset, report = self.build()
        self.assertEqual(ul.validate(dataset), [])
        self.assertEqual(json.loads(ul.dump(dataset)), dataset)
        self.assertEqual(report["failed"], {})
        self.assertEqual(dataset["license"]["name"], "MIT")
        self.assertIn("Permission is hereby granted", dataset["license"]["text"])
        for rec in dataset["releases"]:
            self.assertEqual(rec["source_provider"], "endoflife.date")
            self.assertTrue(rec["fetched_at"])

    def test_failed_product_keeps_previous_data(self):
        previous, _ = self.build()
        later = NOW + dt.timedelta(days=1)
        dataset, report = self.build(previous=previous, fail=("mysql",), now=later)
        self.assertIn("mysql", report["carried"])
        prev_mysql = [r for r in previous["releases"] if r["product_slug"] == "mysql"]
        now_mysql = [r for r in dataset["releases"] if r["product_slug"] == "mysql"]
        self.assertEqual([r["cycle"] for r in now_mysql], [r["cycle"] for r in prev_mysql])
        self.assertEqual({r["fetched_at"] for r in now_mysql}, {FETCHED})

    def test_failed_product_without_previous_is_dropped_not_guessed(self):
        dataset, report = self.build(fail=("mysql",))
        self.assertIn("mysql", report["dropped"])
        self.assertNotIn("mysql", dataset["products"])

    def test_too_many_failures_abort_without_data(self):
        with self.assertRaises(ul.LifecycleError):
            self.build(fail=("mysql", "redis"))

    def test_unchanged_product_keeps_its_fetch_time(self):
        previous, _ = self.build()
        later = NOW + dt.timedelta(hours=6)
        dataset, _ = self.build(previous=previous, now=later)
        self.assertEqual(dataset["products"]["nginx"]["fetched_at"], FETCHED)
        self.assertEqual({k: v for k, v in dataset.items() if k != "generated_at"},
                         {k: v for k, v in previous.items() if k != "generated_at"})

    def test_status_change_over_time_is_a_change(self):
        previous, _ = self.build()
        later = dt.datetime(2027, 1, 12, 1, 0, tzinfo=dt.timezone.utc)
        dataset, _ = self.build(previous=previous, now=later)
        ws2016 = next(r for r in dataset["releases"] if r["product_slug"] == "windows-server" and r["cycle"] == "2016")
        self.assertEqual(ws2016["lifecycle_status"], "EXTENDED_SUPPORT")
        lines = ul.diff_lines(previous, dataset)
        self.assertTrue(any("windows-server" in line and "SECURITY_SUPPORT→EXTENDED_SUPPORT" in line for line in lines))

    def test_config_slug_that_is_an_upstream_alias_is_flagged(self):
        config = [{"slug": "k8s", "vendor": "CNCF"}]
        dataset, report = ul.build(config, None, NOW, items_of())
        self.assertTrue(report["warnings"])
        self.assertIn("k8s", dataset["products"])


class ValidateTests(unittest.TestCase):
    def setUp(self):
        self.dataset, _ = ul.build(CONFIG, None, NOW, items_of())

    def test_missing_field(self):
        bad = copy.deepcopy(self.dataset)
        del bad["releases"][0]["eol_date"]
        self.assertTrue(any("필드 없음" in p for p in ul.validate(bad)))

    def test_duplicate_cycle(self):
        bad = copy.deepcopy(self.dataset)
        bad["releases"].append(copy.deepcopy(bad["releases"][0]))
        self.assertTrue(any("중복" in p for p in ul.validate(bad)))

    def test_bad_status_and_date(self):
        bad = copy.deepcopy(self.dataset)
        bad["releases"][0]["lifecycle_status"] = "SUPPORTED"
        bad["releases"][1]["eol_date"] = "soon"
        problems = ul.validate(bad)
        self.assertTrue(any("상태" in p for p in problems))
        self.assertTrue(any("eol_date" in p for p in problems))

    def test_missing_source(self):
        bad = copy.deepcopy(self.dataset)
        bad["releases"][0]["source_url"] = None
        self.assertTrue(any("출처" in p for p in ul.validate(bad)))


CATALOG_FIXTURE = os.path.join(FIX, "lifecycle_catalog_sample.json")


def make_catalog_fixture():
    """tests/fixtures/lifecycle_catalog_sample.json — 화면 테스트(JS)가 쓰는 전체 목록. 만드는 규칙이 바뀌면
    python -c 'import tests.test_lifecycle as t; t.make_catalog_fixture()' 로 다시 만든다."""
    catalog, _ = ul.build_catalog(CONFIG, None, NOW, items_of())
    ul.write_atomic(CATALOG_FIXTURE, ul.dump(catalog))


class CatalogTests(unittest.TestCase):
    """전체 목록 data/lifecycle_catalog.json — 제품 수명주기 화면용. 같은 응답으로 만든다."""

    def build(self, previous=None, fail=(), config=CONFIG, now=NOW, slugs=None):
        return ul.build_catalog(config, previous, now, items_of(slugs, fail))

    def test_every_upstream_product_with_compact_releases(self):
        catalog, report = self.build()
        self.assertEqual(sorted(catalog["products"]), sorted(AVAILABLE))
        self.assertEqual(report["failed"], {})
        self.assertEqual(ul.validate_catalog(catalog), [])
        self.assertEqual(json.loads(ul.dump(catalog)), catalog)
        self.assertEqual(catalog["license"], ul.LICENSE)
        self.assertEqual(catalog["source_api"], "https://endoflife.date/api/v1/products/full")
        self.assertNotIn("unavailable", catalog, "추적 제품이 아닌 목록에는 '없는 제품' 개념이 없다")
        for rec in catalog["releases"]:
            self.assertNotIn(None, rec.values(), "빈 값은 싣지 않는다")
            for gone in ("security_support_end", "vendor", "fetched_at", "lifecycle_status", "source_url"):
                self.assertNotIn(gone, rec)
        rec = next(r for r in catalog["releases"] if r["product_slug"] == "nginx" and r["cycle"] == "1.25")
        self.assertEqual(rec, {"product_slug": "nginx", "cycle": "1.25", "release_date": "2023-05-23",
                               "eol_date": "2024-05-29", "eol_reached": True, "latest_version": "1.25.5",
                               "latest_release_date": "2024-04-16"})
        k8s = catalog["products"]["kubernetes"]
        self.assertEqual((k8s["category"], k8s["aliases"]), ("server-app", ["k8s"]))
        self.assertEqual(k8s["labels"], {"eoas": "Active Support", "eol": "Maintenance Support", "eoes": None})
        self.assertEqual(k8s["source_url"], "https://endoflife.date/kubernetes")
        self.assertNotIn("icon", json.dumps(catalog))

    def test_same_dates_as_the_tracked_file(self):
        catalog, _ = self.build()
        dataset, _ = ul.build(CONFIG, None, NOW, items_of())
        tracked = ul._group(dataset["releases"])
        listed = ul._group(catalog["releases"])
        self.assertTrue(tracked)
        for slug, recs in tracked.items():
            with self.subTest(slug):
                self.assertEqual([r["cycle"] for r in listed[slug]], [r["cycle"] for r in recs])
                for a, b in zip(recs, listed[slug]):
                    for key in b:
                        self.assertEqual(b[key], a[key], f"{slug} {a['cycle']} {key}")
                    for key in ("eol_date", "eol_reached", "support_end", "extended_support_end", "release_date"):
                        self.assertEqual(b.get(key), a[key], f"{slug} {a['cycle']} {key}")

    def test_reviewed_phase_mapping_applies_to_the_list_too(self):
        config = [{"slug": "kubernetes", "phase_status": {"eol": "SECURITY_SUPPORT", "basis": "https://example.org/k8s"}}]
        catalog, _ = self.build(config=config)
        self.assertEqual(catalog["products"]["kubernetes"]["phase_status"]["eol"], "SECURITY_SUPPORT")
        self.assertNotIn("phase_status", catalog["products"]["nginx"])

    def test_unchanged_product_keeps_its_fetch_time(self):
        previous, _ = self.build()
        later = NOW + dt.timedelta(days=1)
        catalog, _ = self.build(previous=previous, now=later)
        self.assertEqual(catalog["products"]["nginx"]["fetched_at"], FETCHED)
        self.assertEqual(ul._comparable(catalog), ul._comparable(previous))

    def test_broken_product_keeps_previous_entry_or_is_left_out(self):
        previous, _ = self.build()
        catalog, report = self.build(previous=previous, fail=("mysql",), now=NOW + dt.timedelta(days=1))
        self.assertEqual(report["carried"], ["mysql"])
        self.assertEqual(ul._group(catalog["releases"])["mysql"], ul._group(previous["releases"])["mysql"])
        catalog, report = self.build(fail=("mysql",))
        self.assertEqual(report["dropped"], ["mysql"])
        self.assertNotIn("mysql", catalog["products"])
        self.assertFalse(any(r["product_slug"] == "mysql" for r in catalog["releases"]))

    def test_mass_failure_or_a_shrunken_list_is_not_written(self):
        with self.assertRaisesRegex(ul.LifecycleError, "읽지 못함"):
            self.build(fail=("mysql", "redis"))
        previous, _ = self.build()
        with self.assertRaisesRegex(ul.LifecycleError, "줄었다"):
            self.build(previous=previous, slugs=AVAILABLE[:5])

    def test_validate_catches_mistakes(self):
        catalog, _ = self.build()
        bad = copy.deepcopy(catalog)
        bad["releases"].append(copy.deepcopy(bad["releases"][0]))
        bad["releases"][1]["eol_date"] = "soon"
        bad["releases"][2]["vendor"] = "x"
        bad["products"]["nginx"]["source_url"] = None
        problems = ul.validate_catalog(bad)
        for word in ("중복", "eol_date", "모르는 필드", "출처"):
            self.assertTrue(any(word in p for p in problems), word)

    def test_screen_fixture_is_builder_output(self):
        catalog, _ = self.build()
        self.assertEqual(ul.load_json(CATALOG_FIXTURE), catalog,
                         "tests/fixtures/lifecycle_catalog_sample.json 을 make_catalog_fixture() 로 다시 만든다")


class RunTests(unittest.TestCase):
    """_run 전체 — 요청 한 번으로 두 파일, 바뀐 날만 쓰기, 실패하면 둘 다 그대로"""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.paths = {k: os.path.join(self.tmp, n) for k, n in
                      (("OUT_PATH", "lifecycle.json"), ("CATALOG_PATH", "lifecycle_catalog.json"),
                       ("PRODUCTS_PATH", "lifecycle_products.json"))}
        with open(self.paths["PRODUCTS_PATH"], "w", encoding="utf-8") as f:
            json.dump({"products": CONFIG}, f)
        self.patches = [mock.patch.object(ul, k, v) for k, v in self.paths.items()]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        import shutil
        shutil.rmtree(self.tmp)

    def run_with(self, session, dry_run=False):
        with mock.patch.object(ul.requests, "Session", lambda: session), \
                mock.patch("update_lifecycle.time.sleep"), \
                mock.patch.object(ul, "validate_aliases", lambda *a: ([], [])):
            return ul._run(dry_run)

    def read(self):
        out = {}
        for key in ("OUT_PATH", "CATALOG_PATH"):
            path = self.paths[key]
            out[key] = None
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    out[key] = f.read()
        return out

    def test_one_request_writes_both_files_and_only_when_changed(self):
        session = FakeSession({"/products/full": full_payload(AVAILABLE)})
        self.assertEqual(self.run_with(session, dry_run=True), (0, False))
        self.assertEqual(self.read(), {"OUT_PATH": None, "CATALOG_PATH": None}, "dry-run 은 쓰지 않는다")
        self.assertEqual(self.run_with(session), (0, True))
        self.assertEqual(session.calls, 2, "실행마다 요청은 한 번")
        first = self.read()
        self.assertEqual(ul.validate(json.loads(first["OUT_PATH"])), [])
        self.assertEqual(ul.validate_catalog(json.loads(first["CATALOG_PATH"])), [])
        self.assertEqual(self.run_with(FakeSession({"/products/full": full_payload(AVAILABLE)})), (0, False))
        self.assertEqual(self.read(), first, "바뀐 게 없으면 두 파일 모두 그대로")

    def test_failed_request_leaves_both_files(self):
        self.run_with(FakeSession({"/products/full": full_payload(AVAILABLE)}))
        before = self.read()
        self.assertEqual(self.run_with(FakeSession({}, fail_first=99)), (1, False))
        self.assertEqual(self.read(), before)
        truncated = full_payload(AVAILABLE)
        truncated["total"] = 99
        self.assertEqual(self.run_with(FakeSession({"/products/full": truncated})), (1, False))
        self.assertEqual(self.read(), before)


class CommittedFilesTests(unittest.TestCase):
    """저장소에 커밋된 설정·데이터가 스스로의 규칙을 지키는지"""

    def test_products_config_loads(self):
        config = ul.load_config()
        slugs = [c["slug"] for c in config]
        for slug in ("linux", "ubuntu", "debian", "rocky-linux", "almalinux", "windows", "windows-server",
                     "apache-http-server", "nginx", "openssh", "openssl", "postgresql", "mysql", "mariadb",
                     "redis", "nodejs", "python", "oracle-jdk", "php", "kubernetes", "docker-engine"):
            self.assertIn(slug, slugs)

    def test_aliases_file_is_valid(self):
        config = ul.load_config()
        errors, warnings = ul.validate_aliases(ul.load_json(ul.ALIASES_PATH), {c["slug"] for c in config})
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_aliases_validator_catches_mistakes(self):
        errors, warnings = ul.validate_aliases({
            "overrides": {"nocolon": "nginx", "a:b": "nope", "c:d": 3},
            "patterns": [{"vendor": "x", "product": "windows_(", "lifecycle": "windows", "cycle": "$1"},
                         {"vendor": "x", "product": "unanchored", "lifecycle": "windows", "cycle": "1"}],
        }, {"nginx", "windows"})
        self.assertTrue(any("nocolon" in e for e in errors))
        self.assertTrue(any("c:d" in e for e in errors))
        self.assertTrue(any("정규식" in e for e in errors))
        self.assertTrue(any("^…$" in e for e in errors))
        self.assertTrue(any("nope" in w for w in warnings))

    def test_phase_status_requires_policy_basis(self):
        path = os.path.join(os.path.dirname(ul.PRODUCTS_PATH), "_tmp_products.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"products": [{"slug": "kubernetes", "phase_status": {"eol": "SECURITY_SUPPORT"}}]}, f)
            with self.assertRaises(ul.LifecycleError):
                ul.load_config(path)
        finally:
            os.remove(path)

    def test_committed_lifecycle_data_is_valid(self):
        data = ul.load_json(ul.OUT_PATH)
        self.assertEqual(data["schema"], ul.SCHEMA)
        self.assertEqual(ul.validate(data), [])
        self.assertEqual(data["license"], ul.LICENSE)
        as_of = data["generated_at"][:10]
        for rec in data["releases"]:
            meta = data["products"][rec["product_slug"]]
            self.assertEqual(ul.compute_status(rec, meta, as_of), rec["lifecycle_status"],
                             f"{rec['product_slug']} {rec['cycle']}")
        self.assertIn("openssh", [u["slug"] for u in data["unavailable"]])

    def test_committed_catalog_is_valid_and_agrees_with_the_tracked_file(self):
        catalog = ul.load_json(ul.CATALOG_PATH)
        self.assertEqual(catalog["schema"], ul.CATALOG_SCHEMA)
        self.assertEqual(ul.validate_catalog(catalog), [])
        self.assertEqual(catalog["license"], ul.LICENSE)
        self.assertGreater(len(catalog["products"]), 400)
        tracked = ul.load_json(ul.OUT_PATH)
        listed = ul._group(catalog["releases"])
        for slug, recs in ul._group(tracked["releases"]).items():
            with self.subTest(slug):
                self.assertIn(slug, catalog["products"])
                self.assertEqual([r["cycle"] for r in listed[slug]], [r["cycle"] for r in recs])


class FakeResponse:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise ul.requests.exceptions.HTTPError(f"{self.status_code}")

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, routes, fail_first=0):
        self.routes = routes
        self.fail_first = fail_first
        self.calls = 0

    def get(self, url, timeout=None, headers=None):
        self.calls += 1
        if self.calls <= self.fail_first:
            raise ul.requests.exceptions.ConnectionError("reset")
        path = url.replace(ul.API_BASE, "")
        if path not in self.routes:
            return FakeResponse(404, None)
        return FakeResponse(200, self.routes[path])


if __name__ == "__main__":
    unittest.main()
