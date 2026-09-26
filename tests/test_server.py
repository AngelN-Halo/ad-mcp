import datetime as dt
import os
import unittest
from unittest.mock import patch

import server


class SafetyHelpersTest(unittest.TestCase):
    def test_filter_escaping(self):
        self.assertEqual(server.escape_filter_value("a*(b)\\\x00"), r"a\2a\28b\29\5c\00")

    def test_limit_clamping(self):
        self.assertEqual(server.clamp_limit(None, 50, 500), 50)
        self.assertEqual(server.clamp_limit(0, 50, 500), 1)
        self.assertEqual(server.clamp_limit(900, 50, 500), 500)

    def test_enabled_account_is_active(self):
        state = server.account_state({"userAccountControl": 512, "accountExpires": 0})
        self.assertTrue(state["enabled"])
        self.assertTrue(state["active"])
        self.assertEqual(state["status"], "active")

    def test_disabled_account_is_not_active(self):
        state = server.account_state({"userAccountControl": 514, "accountExpires": 0})
        self.assertFalse(state["enabled"])
        self.assertFalse(state["active"])
        self.assertEqual(state["status"], "disabled")

    def test_expired_account_is_not_active(self):
        epoch = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
        expired = int(((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)) - epoch).total_seconds() * 10_000_000)
        state = server.account_state({"userAccountControl": 512, "accountExpires": expired})
        self.assertFalse(state["active"])
        self.assertEqual(state["status"], "expired")

    def test_people_bases_are_generic(self):
        with patch.dict(os.environ, {
            "AD_PRIMARY_PEOPLE_BASE": "OU=People,DC=example,DC=org",
            "AD_SECONDARY_PEOPLE_BASE": "OU=PeopleSecondary,DC=example,DC=org",
        }, clear=False):
            cfg = server.config()
        self.assertEqual(cfg["people_bases"], [
            "OU=People,DC=example,DC=org",
            "OU=PeopleSecondary,DC=example,DC=org",
        ])

    def test_human_name_detection_preserves_dn_with_spaces(self):
        domain = "DC=example,DC=org"
        self.assertTrue(server._looks_like_human_name("Example Person", domain))
        self.assertFalse(server._looks_like_human_name("Example_Person", domain))
        self.assertFalse(server._looks_like_human_name("Example_Person@example.org", domain))
        self.assertFalse(server._looks_like_human_name(
            "CN=Example Person,OU=People,DC=example,DC=org", domain
        ))

    def test_group_dn_parser_handles_escaped_comma(self):
        group = server._group_from_dn(
            r"CN=Example\, Special Group,OU=Groups,DC=example,DC=org"
        )
        self.assertEqual(group["name"], "Example, Special Group")
        self.assertEqual(
            group["dn"],
            r"CN=Example\, Special Group,OU=Groups,DC=example,DC=org",
        )

    def test_unparsable_group_dn_is_retained(self):
        group = server._group_from_dn("not a distinguished name")
        self.assertIsNone(group["name"])
        self.assertEqual(group["dn"], "not a distinguished name")

    def test_memberships_not_requested_is_explicit(self):
        result = server._memberships_not_requested()
        self.assertFalse(result["memberships_included"])
        self.assertIsNone(result["direct_memberships"])
        self.assertFalse(result["primary_group_included"])

    def test_report_filename_is_safe(self):
        self.assertEqual(
            server._safe_report_filename("Duo SSO/FTE: Report"),
            "Duo-SSO-FTE-Report",
        )
        self.assertEqual(server._safe_report_filename("***"), "ad-group")

    def test_csv_formula_prefixes_are_neutralized(self):
        self.assertEqual(server._csv_safe("=HYPERLINK('bad')"), "'=HYPERLINK('bad')")
        self.assertEqual(server._csv_safe("+SUM(A1:A2)"), "'+SUM(A1:A2)")
        self.assertEqual(server._csv_safe("Normal Group"), "Normal Group")


if __name__ == "__main__":
    unittest.main()
