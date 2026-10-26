import hashlib
from pathlib import Path
from unittest import mock

from reviewer.contracts.redaction import redact
from reviewer.contracts.snapshot import read_verified
from reviewer.pipeline.snaps import head_lines
from reviewer.repoimport import import_repository, verify_import
from reviewer.repoimport import materialize as mat
from reviewer.repoimport.redactcheck import line_count, probe

from .helpers import Tmp

# Test-only secrets, assembled at runtime so no literal credential sits in the source.
GH = "gh" + "p_" + "A1b2C3d4" * 5
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
CANARY = "RVWCANARY_" + "x9Yz" * 6
KEY = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIabc\nDEFghi\n-----END RSA " + "PRIVATE KEY-----\n"
SAMPLE = (f"line1\ntoken = '{GH}'\naws {AWS}\n{KEY}after key\nc = {CANARY}\n"
          "password = \"hunter2hunter2\"\nurl = https://user:p4ssw0rd@example.invalid/x\nlast line no newline")


class Redaction(Tmp):
    def test_raw_bytes_are_pinned_and_tool_redaction_keeps_lines(self):
        w, sha = self.fixture({"secrets.env": SAMPLE, "plain.txt": "a\nb\n", "crlf.txt": "k = '" + GH + "'\r\nz\r\n"})
        imp = import_repository(self.remote(w), sha, self.store)
        raw = (Path(imp.root) / "secrets.env").read_bytes()
        self.assertEqual(raw, SAMPLE.encode())                                  # raw bytes stored
        e = {x["path"]: x for x in imp.manifest["entries"]}["secrets.env"]
        self.assertEqual(e["sha256"], hashlib.sha256(SAMPLE.encode()).hexdigest())
        red, counts = redact(SAMPLE)
        for secret in (GH, AWS, CANARY, "hunter2hunter2", "p4ssw0rd", "MIIabc"):
            self.assertNotIn(secret, red)
        self.assertEqual(red.count("\n"), SAMPLE.count("\n"))
        self.assertEqual(len(head_lines(imp.root, imp.manifest, "secrets.env")), line_count(SAMPLE))
        self.assertGreaterEqual(sum(counts.values()), 6)
        anchors = __import__("json").loads((imp.dir / "line-anchors.json").read_bytes())
        self.assertEqual(anchors["secrets.env"], SAMPLE.count("\n") + 1)
        self.assertEqual(anchors["crlf.txt"], 2)
        r = imp.record["redaction"]
        self.assertEqual((r["filesScanned"], r["filesWithRedactions"], r["lineMismatches"]), (3, 2, 0))
        self.assertEqual(r["counts"]["github-token"], 2)
        self.assertEqual(verify_import(imp.dir), [])
        # the tools-visible line N is the same line N in raw bytes
        raw_lines, red_lines = SAMPLE.split("\n"), head_lines(imp.root, imp.manifest, "secrets.env")
        self.assertTrue(red_lines[0] == raw_lines[0] and red_lines[-1] == raw_lines[-1])

    def test_every_pattern_family_preserves_line_count_on_multiline_input(self):
        for text in (SAMPLE, KEY * 3, "-----BEGIN PRIVATE KEY-----\nunterminated\n\n\nend\n", GH + "\n" + GH, ""):
            with self.subTest(text=text[:20]):
                n = line_count(text)
                self.assertEqual(probe(text)[0], n)
                self.assertEqual(line_count(redact(text)[0]), n)

    def test_a_redaction_that_would_shift_lines_omits_the_file(self):
        w, sha = self.fixture({"good.txt": "a\nb\n", "bad.txt": "BAD\nline\n"})
        real = mat.probe

        def fake(text):
            return None if text.startswith("BAD") else real(text)
        with mock.patch.object(mat, "probe", fake):
            imp = import_repository(self.remote(w), sha, self.store)
        self.assertEqual([(i["path"], i["kind"]) for i in imp.record["omissions"]["items"]], [("bad.txt", "redaction")])
        self.assertEqual(imp.record["redaction"]["lineMismatches"], 1)
        self.assertEqual({e["path"] for e in imp.manifest["entries"]}, {"good.txt"})
        self.assertEqual(verify_import(imp.dir), [])
        self.assertFalse(imp.coverage["fullRepositoryCoverage"])

    def test_known_redact3_limit_unterminated_key_block_at_eof_without_final_newline(self):
        """redact@3 keeps the newline COUNT but an unterminated key block that swallows an unterminated last line turns
        it into a terminated one, so head_lines sees one line fewer. The importer must not hide that: it omits the file."""
        text = "-----BEGIN PRIVATE KEY-----\nunterminated\n\n\nend"
        self.assertEqual(redact(text)[0].count("\n"), text.count("\n"))
        self.assertIsNone(probe(text))
        w, sha = self.fixture({"ok.txt": "a\n", "k.pem": text})
        imp = import_repository(self.remote(w), sha, self.store)
        self.assertEqual([(i["path"], i["kind"]) for i in imp.record["omissions"]["items"]], [("k.pem", "redaction")])
        self.assertEqual(imp.record["redaction"]["lineMismatches"], 1)
        self.assertEqual(verify_import(imp.dir), [])
