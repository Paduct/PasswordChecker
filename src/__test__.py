# coding: utf-8
# Copyright 2017

"""Testing password analysis module."""

from unittest import TestCase, TestLoader, TestSuite

from checker import Checker


class TestChecker(TestCase):

    """Verify password properties testing."""

    def test_password_properties_form(self):
        """Form filling and printing testing."""
        Checker.password = "Password 4 You ;)"
        self.assertEqual(Checker().password_properties_form(), (
            "\tThe password should be easily remembered ;)\n"
            "—————————————————————————————————————————————————————\n"
            " Status |            Description            | Amount\n"
            "—————————————————————————————————————————————————————\n"
            "   O    | ASCII uppercase letter            |   2\n"
            "   O    | ASCII lowercase letter            |   9\n"
            "   O    | ASCII numeral                     |   1\n"
            "   O    | ASCII special character           |   2\n"
            "   X    | Non-ASCII uppercase letter        |   0\n"
            "   X    | Non-ASCII lowercase letter        |   0\n"
            "   O    | Free space                        |   3\n"
            "   X    | Unicode character                 |   0\n"
            "   O    | Normal length                     |   17\n"
            "—————————————————————————————————————————————————————\n"
            "   X    | No consecutive repetition symbols |   1\n"
            "   X    | No substantially dominant symbols |   1\n"
            "   O    | No matching symbol sets           |   0\n"
            "—————————————————————————————————————————————————————\n"
            "  Bit   ++++++++++++++++++++++++++++++++-----   111\n"
        ))


def suite() -> TestSuite:
    """Return a test suite for execution."""
    tests: TestSuite = TestSuite()
    loader: TestLoader = TestLoader()
    tests.addTest(loader.loadTestsFromTestCase(TestChecker))
    return tests
