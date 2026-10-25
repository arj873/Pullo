import unittest

from reviewer.contracts import validate
from reviewer.scoring import f1_value, ratio
from reviewer.scoring.metrics import percentile


class Ratios(unittest.TestCase):
    def test_zero_denominator_is_undefined_never_zero_or_one(self):
        r = ratio(0, 0, "no comments")
        self.assertEqual(r, {"value": None, "numerator": 0, "denominator": 0, "undefinedReason": "no comments"})
        self.assertEqual(validate("Ratio", r), [])

    def test_defined_ratio_validates(self):
        for n, d in ((0, 5), (3, 4), (5, 5)):
            r = ratio(n, d, "x")
            self.assertEqual(r["value"], n / d)
            self.assertIsNone(r["undefinedReason"])
            self.assertEqual(validate("Ratio", r), [])

    def test_zero_numerator_with_positive_denominator_is_a_real_zero(self):
        self.assertEqual(ratio(0, 3, "x")["value"], 0.0)

    def test_impossible_ratios_refused(self):
        for n, d in ((2, 1), (-1, 3), (0, -1)):
            with self.assertRaises(ValueError):
                ratio(n, d, "x")

    def test_f1_cases(self):
        p, r = ratio(1, 2, "x"), ratio(1, 4, "x")
        self.assertAlmostEqual(f1_value(p, r)["value"], 2 * 0.5 * 0.25 / 0.75)
        self.assertEqual(f1_value(ratio(0, 3, "x"), ratio(0, 2, "x"))["value"], 0.0)   # P+R == 0
        u = f1_value(ratio(0, 0, "no comments"), ratio(1, 2, "x"))
        self.assertIsNone(u["value"])
        self.assertIn("precision undefined", u["undefinedReason"])
        both = f1_value(ratio(0, 0, "a"), ratio(0, 0, "b"))
        self.assertIsNone(both["value"])
        self.assertIn("recall undefined", both["undefinedReason"])
        for d in (u, both):
            self.assertIsNone(d["value"])
            self.assertTrue(d["undefinedReason"])

    def test_percentile_nearest_rank(self):
        self.assertIsNone(percentile([], 0.5))
        self.assertEqual(percentile([5], 0.95), 5)
        self.assertEqual(percentile([1, 2, 3, 4], 0.5), 2)
        self.assertEqual(percentile([4, 1, 3, 2], 0.95), 4)


if __name__ == "__main__":
    unittest.main()
