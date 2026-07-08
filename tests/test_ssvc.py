"""Parity tests guarding the transcribed SSVC decision tables.

Run with: python -m unittest discover -s tests
Independent restatements of the two published tables assert that the lookup
tables in patrowl_intel_mcp.ssvc were transcribed correctly.
"""
import unittest

from patrowl_intel_mcp import ssvc


# CISA BOD 26-04 "Table of Values" — 16 rows.
# https://certcc.github.io/SSVC/howto/cisa_response/#table-of-values
# (is_kev, publicly_exposed, automatable, tech_impact) -> code
BOD_26_04_TABLE = [
    (False, False, "no",  "partial", "FSU"),
    (False, False, "no",  "total",   "FSU"),
    (False, False, "yes", "partial", "60D"),
    (False, False, "yes", "total",   "60D"),
    (False, True,  "no",  "partial", "60D"),
    (False, True,  "no",  "total",   "14D"),
    (False, True,  "yes", "partial", "14D"),
    (False, True,  "yes", "total",   "3D"),
    (True,  False, "no",  "partial", "14D"),
    (True,  False, "no",  "total",   "14D"),
    (True,  False, "yes", "partial", "14D"),
    (True,  False, "yes", "total",   "3DF"),
    (True,  True,  "no",  "partial", "14D"),
    (True,  True,  "no",  "total",   "3DF"),
    (True,  True,  "yes", "partial", "3D"),
    (True,  True,  "yes", "total",   "3DF"),
]

# CISA Coordinator SSVC — 36 rows.
# (exploitation, automatable, tech_impact, mission_wellbeing) -> action key
CISA_TABLE = [
    ("none", "no", "partial", "low", "track"), ("none", "no", "partial", "medium", "track"), ("none", "no", "partial", "high", "track_star"),
    ("none", "no", "total", "low", "track"), ("none", "no", "total", "medium", "track"), ("none", "no", "total", "high", "track_star"),
    ("none", "yes", "partial", "low", "track"), ("none", "yes", "partial", "medium", "track"), ("none", "yes", "partial", "high", "attend"),
    ("none", "yes", "total", "low", "track"), ("none", "yes", "total", "medium", "track"), ("none", "yes", "total", "high", "attend"),
    ("poc", "no", "partial", "low", "track"), ("poc", "no", "partial", "medium", "track"), ("poc", "no", "partial", "high", "track_star"),
    ("poc", "no", "total", "low", "track"), ("poc", "no", "total", "medium", "track_star"), ("poc", "no", "total", "high", "attend"),
    ("poc", "yes", "partial", "low", "track"), ("poc", "yes", "partial", "medium", "track"), ("poc", "yes", "partial", "high", "attend"),
    ("poc", "yes", "total", "low", "track"), ("poc", "yes", "total", "medium", "track_star"), ("poc", "yes", "total", "high", "attend"),
    ("active", "no", "partial", "low", "track"), ("active", "no", "partial", "medium", "track"), ("active", "no", "partial", "high", "attend"),
    ("active", "no", "total", "low", "track"), ("active", "no", "total", "medium", "attend"), ("active", "no", "total", "high", "act"),
    ("active", "yes", "partial", "low", "attend"), ("active", "yes", "partial", "medium", "attend"), ("active", "yes", "partial", "high", "act"),
    ("active", "yes", "total", "low", "attend"), ("active", "yes", "total", "medium", "act"), ("active", "yes", "total", "high", "act"),
]


class BodDecisionTest(unittest.TestCase):
    def test_all_sixteen_rows(self):
        self.assertEqual(len(BOD_26_04_TABLE), 16)
        for is_kev, exposed, auto, impact, expected in BOD_26_04_TABLE:
            with self.subTest(is_kev=is_kev, exposed=exposed, auto=auto, impact=impact):
                self.assertEqual(ssvc.bod_decision(is_kev, exposed, auto, impact), expected)

    def test_defaults_are_lowest_urgency(self):
        self.assertEqual(ssvc.bod_decision(), "FSU")

    def test_tolerates_bool_and_casing(self):
        self.assertEqual(ssvc.bod_decision(True, True, True, "Total"), "3DF")
        self.assertEqual(ssvc.bod_decision(automatable=" YES ", tech_impact="partial"), "60D")

    def test_invalid_values_raise(self):
        with self.assertRaises(ValueError):
            ssvc.bod_decision(automatable="maybe")
        with self.assertRaises(ValueError):
            ssvc.bod_decision(tech_impact="catastrophic")


class CisaDecisionTest(unittest.TestCase):
    def test_all_thirtysix_rows(self):
        self.assertEqual(len(CISA_TABLE), 36)
        for exp, auto, impact, mission, expected in CISA_TABLE:
            with self.subTest(exp=exp, auto=auto, impact=impact, mission=mission):
                self.assertEqual(ssvc.cisa_decision(exp, auto, impact, mission), expected)

    def test_invalid_values_raise(self):
        with self.assertRaises(ValueError):
            ssvc.cisa_decision(exploitation="rumored")
        with self.assertRaises(ValueError):
            ssvc.cisa_decision(mission_wellbeing="extreme")


class VectorTest(unittest.TestCase):
    def test_bod_vector(self):
        self.assertEqual(ssvc.bod_vector(True, True, "yes", "total"), "KEV:Y / PE:Y / A:Y / T:T")
        self.assertEqual(ssvc.bod_vector(False, False, "no", "partial"), "KEV:N / PE:N / A:N / T:P")

    def test_cisa_vector(self):
        self.assertEqual(ssvc.cisa_vector("active", "yes", "total", "high"), "E:A / A:Y / T:T / M:H")
        self.assertEqual(ssvc.cisa_vector("none", "no", "partial", "low"), "E:N / A:N / T:P / M:L")


if __name__ == "__main__":
    unittest.main()
