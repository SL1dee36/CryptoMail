# Integration test for Layout switching and persistence (Classic vs Gmail)
import os
import unittest
from cryptomail.app import set_layout_api, render, TEMPLATES_DIR, STYLE_DIR
from cryptomail.database import init_db, SessionLocal
from cryptomail.models.user import User


class TestLayoutSwitching(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_layout_api_endpoint(self):
        """Test set_layout_api sets cookie and redirects properly."""
        # Switch to gmail
        res = set_layout_api(layout="gmail")
        self.assertEqual(res.status_code, 302)
        cookie_header = res.headers.get("set-cookie", "")
        self.assertIn("cryptomail_layout=gmail", cookie_header)

        # Switch to classic
        res = set_layout_api(layout="classic")
        self.assertEqual(res.status_code, 302)
        cookie_header = res.headers.get("set-cookie", "")
        self.assertIn("cryptomail_layout=classic", cookie_header)

    def test_static_files_exist(self):
        """Test that gmail.css and layout.js exist in style directory."""
        gmail_css = os.path.join(STYLE_DIR, "gmail.css")
        layout_js = os.path.join(STYLE_DIR, "layout.js")

        self.assertTrue(os.path.exists(gmail_css))
        self.assertTrue(os.path.exists(layout_js))

        with open(gmail_css, "r", encoding="utf-8") as f:
            css_content = f.read()
            self.assertIn("gm-workspace", css_content)
            self.assertIn("data-layout=\"gmail\"", css_content)

        with open(layout_js, "r", encoding="utf-8") as f:
            js_content = f.read()
            self.assertIn("toggleLayout", js_content)
            self.assertIn("switchGmailTab", js_content)

    def test_templates_contain_gmail_components(self):
        """Test that base.html and index.html include Gmail markup and switcher."""
        base_html = os.path.join(TEMPLATES_DIR, "base.html")
        index_html = os.path.join(TEMPLATES_DIR, "index.html")

        with open(base_html, "r", encoding="utf-8") as f:
            base_content = f.read()
            self.assertIn("gmail.css", base_content)
            self.assertIn("layout.js", base_content)
            self.assertIn("gm-header", base_content)
            self.assertIn("layout-toggle-label", base_content)

        with open(index_html, "r", encoding="utf-8") as f:
            index_content = f.read()
            self.assertIn("cm-classic-only", index_content)
            self.assertIn("cm-gmail-only", index_content)
            self.assertIn("gm-sidebar", index_content)
            self.assertIn("gm-docked-compose", index_content)
