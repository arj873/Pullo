import itertools
import unittest

from reviewer.scoring import ScoringError, match_comments
from .helpers import make_comment


def bug(i, path, a, b):
    return {"id": f"b{i}", "path": path, "lines": [a, b], "category": "bug", "severity": "P1"}


class Overlap(unittest.TestCase):
    def test_overlap_and_tolerance_boundaries(self):
        b = [bug(0, "x.py", 10, 12)]
        cases = [((10, 12), True), ((12, 20), True), ((1, 10), True),      # overlap
                 ((15, 20), True), ((1, 7), True),                          # nearest lines differ by exactly 3
                 ((16, 20), False), ((1, 6), False)]                        # differ by 4
        for (s, e), ok in cases:
            with self.subTest(s=s, e=e):
                r = match_comments([make_comment("x.py", s, e)], b, 3)
                self.assertEqual(r.true_positives, 1 if ok else 0)
                self.assertEqual(len(r.false_positives), 0 if ok else 1)
                self.assertEqual(len(r.false_negatives), 0 if ok else 1)

    def test_tolerance_zero_requires_real_overlap(self):
        b = [bug(0, "x.py", 10, 12)]
        self.assertEqual(match_comments([make_comment("x.py", 13, 13)], b, 0).true_positives, 0)  # adjacent line: distance 1
        self.assertEqual(match_comments([make_comment("x.py", 12, 13)], b, 0).true_positives, 1)

    def test_path_must_be_exact(self):
        b = [bug(0, "src/a.py", 10, 12)]
        for p in ("src/A.py", "a.py", "src/a.pyc", "other/src/a.py"):
            with self.subTest(p):
                self.assertEqual(match_comments([make_comment(p, 10, 12)], b, 3).true_positives, 0)

    def test_tolerance_validated(self):
        for t in (-1, 21, 1.5, True, None, "3"):
            with self.subTest(t), self.assertRaises(ScoringError):
                match_comments([], [], t)


class Assignment(unittest.TestCase):
    def test_one_comment_matches_at_most_one_bug(self):
        r = match_comments([make_comment("x.py", 10, 30)], [bug(0, "x.py", 10, 11), bug(1, "x.py", 25, 26)], 3)
        self.assertEqual((r.true_positives, len(r.false_negatives), len(r.false_positives)), (1, 1, 0))

    def test_maximum_cardinality_beats_greedy(self):
        # c1 (visited first) overlaps both bugs and prefers b0; c2 overlaps only b0.
        # Greedy c1->b0 strands c2 and loses a true positive; augmenting paths re-route c1 to b1.
        c1, c2 = make_comment("x.py", 10, 20, n=1), make_comment("x.py", 11, 12, n=2)
        r = match_comments([c1, c2], [bug(0, "x.py", 10, 11), bug(1, "x.py", 18, 19)], 0)
        self.assertEqual(r.true_positives, 2)
        self.assertEqual((r.false_positives, r.false_negatives), ((), ()))

    def test_duplicates_are_false_positives_and_counted_separately(self):
        a, dup, far = (make_comment("x.py", 10, 12, n=1), make_comment("x.py", 11, 12, n=2),
                       make_comment("x.py", 90, 91, n=3))
        r = match_comments([a, dup, far], [bug(0, "x.py", 10, 12)], 3)
        self.assertEqual(r.true_positives, 1)
        self.assertEqual(len(r.false_positives), 2)
        self.assertEqual(len(r.duplicates), 1)              # `far` is a plain FP, not a duplicate
        self.assertTrue(set(r.duplicates) <= set(r.false_positives))
        self.assertNotIn(far["id"], r.duplicates)

    def test_two_comments_on_unlabelled_code_are_fps_not_duplicates(self):
        r = match_comments([make_comment("x.py", 5, 6, n=1), make_comment("x.py", 5, 6, n=2)], [], 3)
        self.assertEqual((len(r.false_positives), len(r.duplicates)), (2, 0))

    def test_unmatched_bug_is_false_negative(self):
        r = match_comments([], [bug(0, "x.py", 1, 2), bug(1, "y.py", 1, 2)], 3)
        self.assertEqual(r.false_negatives, ("b0", "b1"))

    def test_input_order_never_matters(self):
        cs = [make_comment("x.py", 10, 12, n=1), make_comment("x.py", 11, 13, n=2),
              make_comment("x.py", 40, 41, n=3), make_comment("y.py", 1, 2, n=4)]
        bs = [bug(0, "x.py", 10, 12), bug(1, "x.py", 39, 40), bug(2, "z.py", 1, 1)]
        want = match_comments(cs, bs, 3)
        for perm in itertools.permutations(cs):
            for bperm in (bs, bs[::-1]):
                self.assertEqual(match_comments(list(perm), list(bperm), 3), want)

    def test_non_scored_states_are_ignored_not_scored(self):
        cs = [make_comment("x.py", 10, 12, n=1), make_comment("x.py", 10, 12, n=2, state="retracted"),
              make_comment("x.py", 10, 12, n=3, state="superseded")]
        r = match_comments(cs, [bug(0, "x.py", 10, 12)], 3)
        self.assertEqual((r.true_positives, len(r.false_positives), len(r.ignored)), (1, 0, 2))

    def test_duplicate_ids_rejected(self):
        c = make_comment()
        with self.assertRaises(ScoringError):
            match_comments([c, dict(c)], [], 3)
        with self.assertRaises(ScoringError):
            match_comments([], [bug(0, "x.py", 1, 2), bug(0, "x.py", 3, 4)], 3)


if __name__ == "__main__":
    unittest.main()
