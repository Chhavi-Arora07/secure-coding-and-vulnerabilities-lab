#!/usr/bin/env python3
"""
vaultapp - small file-based application (intentionally vulnerable, for static-analysis lab).
Do NOT deploy. Uses only the Python standard library.
"""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "meta.db")
ADMIN_TOKEN = "vault-admin-2024-secret"          # hard-coded credential


def init():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("CREATE TABLE IF NOT EXISTS files(name TEXT, owner TEXT, note TEXT)")
    con.commit()
    con.close()


def etag_for(data):
    # used only as a cache validator for the browser, not for security
    return hashlib.md5(data).hexdigest()


def make_share_token():
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(12))   # predictable PRNG


def backup_uploads(dest):
    # fixed argument list, no shell, no user input
    subprocess.run(["tar", "-czf", dest, "-C", UPLOAD_DIR, "."], check=True)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/download":
            name = q.get("file", [""])[0]
            path = os.path.join(UPLOAD_DIR, name)               # no normalisation
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError:
                return self._send(404, "not found")
            return self._send(200, data, "application/octet-stream")
        if url.path == "/info":
            name = q.get("file", [""])[0]
            out = os.popen("ls -l " + UPLOAD_DIR + "/" + name).read()   # shell
            return self._send(200, out)
        if url.path == "/search":
            term = q.get("q", [""])[0]
            con = sqlite3.connect(DB_PATH)
            sql = "SELECT name, owner FROM files WHERE note LIKE '%" + term + "%'"
            try:
                rows = con.execute(sql).fetchall()
            except sqlite3.Error as e:
                return self._send(500, "db error: " + str(e))
            return self._send(200, repr(rows))
        if url.path == "/share":
            return self._send(200, make_share_token())
        if url.path == "/health":
            return self._send(200, "ok")
        return self._send(404, "unknown route")

    def do_POST(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if url.path == "/upload":
            name = q.get("name", ["unnamed"])[0]
            path = os.path.join(UPLOAD_DIR, name)               # no extension/path check
            with open(path, "wb") as f:
                f.write(body)
            con = sqlite3.connect(DB_PATH)
            con.execute("INSERT INTO files VALUES (?,?,?)", (name, "anon", q.get("note", [""])[0]))
            con.commit()
            self.send_response(201)
            self.send_header("ETag", etag_for(body))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if url.path == "/import":
            if self.headers.get("X-Admin-Token") != ADMIN_TOKEN:
                return self._send(403, "forbidden")
            state = pickle.loads(body)                          # untrusted bytes
            return self._send(200, "imported " + str(type(state)))
        return self._send(404, "unknown route")


def main():
    init()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
