"""The web API must refuse cross-site requests (CSRF) and DNS rebinding.  python -m unittest discover tests"""
import http.client
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ied_inspector import app  # noqa: E402


class SecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def req(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def test_page_contains_token_and_api_needs_it(self):
        st, page = self.req("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn(app.SESSION_TOKEN.encode(), page)
        self.assertEqual(self.req("GET", "/api/settings")[0], 403)
        self.assertEqual(self.req("GET", "/api/settings", {"X-IED-Token": app.SESSION_TOKEN})[0], 200)

    def test_csrf_post_without_token_is_refused(self):
        st, _ = self.req("POST", "/api/sim/stop", {"Content-Type": "text/plain"}, b'{"key":"all"}')
        self.assertEqual(st, 403)

    def test_foreign_origin_is_refused_even_with_token(self):
        st, _ = self.req("POST", "/api/capture/stop", {"Origin": "https://evil.example",
                                                       "X-IED-Token": app.SESSION_TOKEN}, b"{}")
        self.assertEqual(st, 403)

    def test_dns_rebinding_host_is_refused(self):
        self.assertEqual(self.req("GET", "/", {"Host": f"evil.example:{self.port}"})[0], 421)

    def test_report_download_needs_token_in_query(self):
        self.assertEqual(self.req("GET", "/report/comparison?format=json")[0], 403)
        st, _ = self.req("GET", f"/report/comparison?format=json&t={app.SESSION_TOKEN}")
        self.assertEqual(st, 200)


if __name__ == "__main__":
    unittest.main()
