import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import update_cwe as uc  # noqa: E402

# MITRE 가 내려 주는 모양 그대로(네임스페이스 · 속성 · 하위 요소) 줄인 목록.
CATALOG = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog Name="CWE" Version="4.20" Date="2026-04-30" xmlns="http://cwe.mitre.org/cwe-7"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Weaknesses>
    <Weakness ID="89" Name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
      Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>The product constructs all or part of an SQL command ...</Description>
    </Weakness>
    <Weakness ID="1321" Name="Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')"
      Abstraction="Variant" Structure="Simple" Status="Incomplete"/>
    <Weakness ID="200" Name="Exposure of Sensitive Information to an Unauthorized Actor" Abstraction="Class"
      Structure="Simple" Status="Draft"/>
    <Weakness ID="284" Name="Improper Access Control" Abstraction="Pillar" Structure="Simple" Status="Incomplete"/>
    <Weakness ID="352" Name="Cross-Site Request Forgery (CSRF)" Abstraction="Compound" Structure="Composite"
      Status="Stable"/>
    <Weakness ID="1187" Name="DEPRECATED: Use of Uninitialized Resource" Abstraction="Base" Structure="Simple"
      Status="Deprecated"/>
    <Weakness ID="10" Name="  Spaces Around  " Abstraction="Base" Structure="Simple" Status="Draft"/>
  </Weaknesses>
  <Categories>
    <Category ID="399" Name="Resource Management Errors" Status="Obsolete"><Summary>...</Summary></Category>
    <Category ID="16" Name="Configuration" Status="Obsolete"/>
  </Categories>
  <Views><View ID="1000" Name="Research Concepts" Type="Graph" Status="Draft"/></Views>
  <External_References><External_Reference Reference_ID="REF-1"><Title>x</Title></External_Reference></External_References>
</Weakness_Catalog>
""".encode("utf-8")


def zipped(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def payload_of(js):
    """render_js 가 쓴 JS 에서 데이터 JSON 만 꺼낸다."""
    m = re.search(r"const data = (\{.*\});\n", js)
    return json.loads(m.group(1))


class ParseTests(unittest.TestCase):
    def test_reads_version_abstraction_and_names(self):
        cat = uc.parse_catalog(CATALOG)
        self.assertEqual((cat["version"], cat["date"]), ("4.20", "2026-04-30"))
        self.assertEqual(cat["weaknesses"], {
            "89": ("B", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"),
            "1321": ("V", "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')"),
            "200": ("C", "Exposure of Sensitive Information to an Unauthorized Actor"),
            "284": ("P", "Improper Access Control"),
            "352": ("M", "Cross-Site Request Forgery (CSRF)"),
            "1187": ("D", "DEPRECATED: Use of Uninitialized Resource"),
            "10": ("B", "Spaces Around"),
        })
        self.assertEqual(cat["categories"], {"399": "Resource Management Errors", "16": "Configuration"})

    def test_zip_with_one_xml_equals_plain_xml(self):
        self.assertEqual(uc.parse_catalog(zipped({"cwec_v4.20.xml": CATALOG})), uc.parse_catalog(CATALOG))

    def test_zip_with_other_than_one_xml_is_refused(self):
        with self.assertRaises(uc.CweError):
            uc.parse_catalog(zipped({"a.xml": CATALOG, "b.xml": CATALOG}))
        with self.assertRaises(uc.CweError):
            uc.parse_catalog(zipped({"readme.txt": b"x"}))

    def test_unknown_abstraction_is_refused_not_guessed(self):
        bad = CATALOG.replace(b'Abstraction="Pillar"', b'Abstraction="Mystery"')
        with self.assertRaises(uc.CweError):
            uc.parse_catalog(bad)

    def test_missing_version_is_refused(self):
        with self.assertRaises(uc.CweError):
            uc.parse_catalog(CATALOG.replace(b'Version="4.20"', b'Version=""'))


class ValidateTests(unittest.TestCase):
    def test_too_few_live_weaknesses_is_refused_deprecated_not_counted(self):
        cat = uc.parse_catalog(CATALOG)  # 살아 있는 약점 6개 · 폐기 1개
        with mock.patch.object(uc, "MIN_WEAKNESSES", 6):
            uc.validate(cat)
        with mock.patch.object(uc, "MIN_WEAKNESSES", 7):
            with self.assertRaises(uc.CweError):
                uc.validate(cat)


class RenderTests(unittest.TestCase):
    def test_payload_sorted_by_number_with_codes(self):
        js = uc.render_js(uc.parse_catalog(CATALOG), 2026)
        data = payload_of(js)
        self.assertEqual(list(data), ["version", "date", "w", "c"])
        self.assertEqual(list(data["w"]), ["10", "89", "200", "284", "352", "1187", "1321"])
        self.assertEqual(data["w"]["89"], "B|Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')")
        self.assertEqual(data["w"]["1187"], "D|DEPRECATED: Use of Uninitialized Resource")
        self.assertEqual(list(data["c"]), ["16", "399"])
        self.assertIn("root.ArgusCWEData = data;", js)
        self.assertIn("module.exports = data", js)

    def test_copyright_and_terms_of_use_travel_with_the_copy(self):
        """CWE 이용 약관: 사본마다 MITRE 저작권 표기와 약관 문구를 함께 싣는다."""
        js = uc.render_js(uc.parse_catalog(CATALOG), 2026)
        head = js.split("(function (root)")[0]
        self.assertIn("Copyright © 2006–2026, The MITRE Corporation.", head)
        self.assertIn(uc.TERMS_TEXT, head)
        self.assertIn(uc.TERMS_URL, head)
        self.assertIn("CWE 4.20 (2026-04-30)", head)
        self.assertNotIn("*/", uc.TERMS_TEXT, "약관 문구가 주석을 닫으면 안 된다")

    def test_same_input_renders_same_text(self):
        cat = uc.parse_catalog(CATALOG)
        self.assertEqual(uc.render_js(cat, 2026), uc.render_js(uc.parse_catalog(zipped({"c.xml": CATALOG})), 2026))


class MainTests(unittest.TestCase):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(uc, "MIN_WEAKNESSES", 3), \
                mock.patch.object(uc, "_download", side_effect=AssertionError("네트워크를 쓰면 안 된다")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = uc.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_writes_then_leaves_unchanged_file_alone(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = os.path.join(d, "c.zip"), os.path.join(d, "cwe-data.js")
            with open(src, "wb") as f:
                f.write(zipped({"cwec_v4.20.xml": CATALOG}))
            code, out, _ = self.run_main("--source", src, "--out", dst)
            self.assertEqual(code, 0)
            self.assertIn("CWE 4.20 (2026-04-30) · 약점 7개 · 분류 2개", out)
            with open(dst, encoding="utf-8") as f:
                first = f.read()
            self.assertEqual(payload_of(first)["version"], "4.20")
            code, out, _ = self.run_main("--source", src, "--out", dst)
            self.assertEqual(code, 0)
            self.assertIn("바뀐 것 없음", out)

    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = os.path.join(d, "c.xml"), os.path.join(d, "cwe-data.js")
            with open(src, "wb") as f:
                f.write(CATALOG)
            code, _, _ = self.run_main("--source", src, "--out", dst, "--dry-run")
            self.assertEqual(code, 0)
            self.assertFalse(os.path.exists(dst))

    def test_broken_source_keeps_existing_file(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = os.path.join(d, "c.xml"), os.path.join(d, "cwe-data.js")
            with open(src, "wb") as f:
                f.write(CATALOG[:400])  # 잘린 XML
            with open(dst, "w", encoding="utf-8") as f:
                f.write("기존")
            code, _, err = self.run_main("--source", src, "--out", dst)
            self.assertEqual(code, 1)
            self.assertIn("CWE 목록을 만들지 못함", err)
            with open(dst, encoding="utf-8") as f:
                self.assertEqual(f.read(), "기존")


class CommittedDataTests(unittest.TestCase):
    """저장소에 넣은 docs/js/cwe-data.js — 화면이 읽는 그 파일."""

    @classmethod
    def setUpClass(cls):
        with open(uc.OUT_PATH, encoding="utf-8") as f:
            cls.js = f.read()
        cls.data = payload_of(cls.js)

    def test_carries_copyright_and_terms(self):
        head = self.js.split("(function (root)")[0]
        self.assertRegex(head, r"Copyright © 2006–\d{4}, The MITRE Corporation\.")
        self.assertIn(uc.TERMS_TEXT, head)
        self.assertIn(f"CWE {self.data['version']} ({self.data['date']})", head)

    def test_is_a_whole_catalog(self):
        codes = [v.split("|", 1)[0] for v in self.data["w"].values()]
        self.assertGreaterEqual(sum(1 for c in codes if c != "D"), uc.MIN_WEAKNESSES)
        self.assertLessEqual(set(codes), set(uc.ABSTRACTION.values()) | {"D"})
        self.assertEqual(list(self.data["w"]), sorted(self.data["w"], key=int))
        self.assertIn("Resource Management Errors", self.data["c"].values())


if __name__ == "__main__":
    unittest.main()
