"""P0 public social identity release guard; historical VDP/IOC data untouched."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent


class PublicSocialIdentityTests(unittest.TestCase):
    def test_published_ecosystem_has_no_unverified_facebook_or_orcid(self):
        html = (ROOT / "ecosystem" / "ecosystem.html").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"https?://(?:www\\.)?(?:facebook\\.com|orcid\\.org)(?:[/:?#]|$)", html, re.I))

    def test_preserves_approved_linkedin_instagram(self):
        html = (ROOT / "ecosystem" / "ecosystem.html").read_text(encoding="utf-8")
        self.assertIn("https://www.linkedin.com/company/cyberdudebivash/", html)
        self.assertIn("https://www.instagram.com/cyberdudebivash_official/", html)


if __name__ == "__main__":
    unittest.main()
