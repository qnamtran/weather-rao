"""
Remote Northern Airports weather board — backend.

- Polls the NOAA Aviation Weather Center API for METARs at the 29 airports
- Keeps every report (hourly METARs + SPECIs) in SQLite (wx.db)
- Serves a JSON API and the dashboard in ./static

Python 3.9+ standard library only. Run:  python server.py   then open http://localhost:8080
"""
import json, os, sys, math, sqlite3, ssl, subprocess, tempfile, threading, time, urllib.request, urllib.error, urllib.parse, csv, io, gzip
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

# --- Settings (override with environment variables) ----------------------------------
PORT = int(os.environ.get("PORT", 8080))
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", 300))   # AWC asks for >= 1 min between calls
KEEP_DAYS = int(os.environ.get("KEEP_DAYS", 0))           # 0 = keep all history forever
BACKFILL_DELAY = float(os.environ.get("BACKFILL_DELAY", 0.7))  # seconds between history requests (API allows 100/min)
HISTORY_DAYS = max(1, min(int(os.environ.get("HISTORY_DAYS", 30)), 30))  # NOAA serves at most the past 30 days
HISTORY_H = HISTORY_DAYS * 24
API_MAX_RESULTS = 400                                     # AWC returns at most this many reports per request
GROUP_BUDGET = 300                                        # expected reports per shared request, kept well under the limit
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "wx.db"))
HERE = os.path.dirname(os.path.abspath(__file__))
# The page can live in ./static/index.html (recommended) or right next to server.py.
STATIC = next((d for d in (os.path.join(HERE, "static"), HERE)
               if os.path.isfile(os.path.join(d, "index.html"))), os.path.join(HERE, "static"))
AWC = "https://aviationweather.gov/api/data"
UA = {"User-Agent": "RemoteAirportsWx/1.0 (internal dashboard)", "Accept-Encoding": "gzip"}

# Verify this list against MTO's official remote northern airports dataset.
# Positions are approximate fallbacks so every airport appears on the map; precise
# positions from the Aviation Weather Center replace them when it has the airport.
AIRPORT_INFO = {
    "CYYW": ("Armstrong", 50.29, -88.91), "CYAT": ("Attawapiskat", 52.93, -82.43),
    "CNE3": ("Bearskin Lake", 53.97, -91.03), "CYTL": ("Big Trout Lake", 53.82, -89.90),
    "CYAC": ("Cat Lake", 51.73, -91.82), "CYVZ": ("Deer Lake", 52.66, -94.06),
    "CYFA": ("Fort Albany", 52.20, -81.70), "CYFH": ("Fort Hope", 51.56, -87.91),
    "CYER": ("Fort Severn", 56.02, -87.68), "CYAQ": ("Kasabonika", 53.52, -88.64),
    "CZKE": ("Kashechewan", 52.28, -81.68), "CPV8": ("Keewaywin", 53.00, -92.84),
    "CNM5": ("Kingfisher Lake", 53.01, -89.86), "CYLH": ("Lansdowne House", 52.20, -87.93),
    "CZMD": ("Muskrat Dam", 53.44, -91.76),
    "CKQ3": ("North Spirit Lake", 52.49, -92.97), "CYKP": ("Ogoki Post", 51.66, -85.90),
    "CYPO": ("Peawanuck", 54.99, -85.44), "CYPL": ("Pickle Lake", 51.45, -90.21),
    "CYPM": ("Pikangikum", 51.82, -93.97), "CPV7": ("Poplar Hill", 52.11, -94.26),
    "CZRJ": ("Round Lake", 52.94, -91.31), "CZPB": ("Sachigo Lake", 53.89, -92.20),
    "CZSJ": ("Sandy Lake", 53.06, -93.34), "CKD9": ("Slate Falls", 51.1300, -91.6656),
    "CJV7": ("Summer Beaver", 52.71, -88.54),
    "CKB6": ("Wapekeka", 53.85, -89.58), "CYWP": ("Webequie", 52.96, -87.37),
    "CKL3": ("Wunnummin Lake", 52.89, -89.29),
}
AIRPORTS = {k: v[0] for k, v in AIRPORT_INFO.items()}
IDS = ",".join(AIRPORTS)

# --- Database --------------------------------------------------------------------------
def db():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS obs (
            icao TEXT, obs_time INTEGER, raw TEXT, temp REAL, dewp REAL,
            wdir TEXT, wspd REAL, wgst REAL, visib REAL, ceiling INTEGER,
            altim REAL, flt_cat TEXT, is_auto INTEGER,
            PRIMARY KEY (icao, obs_time));
        CREATE INDEX IF NOT EXISTS obs_time_idx ON obs(obs_time);
        CREATE TABLE IF NOT EXISTS airports (icao TEXT PRIMARY KEY, name TEXT, lat REAL, lon REAL);
        CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
        """)
        keep = list(AIRPORT_INFO)
        c.execute(f"DELETE FROM airports WHERE icao NOT IN ({','.join('?' * len(keep))})", keep)
        for icao, (name, lat, lon) in AIRPORT_INFO.items():
            c.execute("INSERT OR IGNORE INTO airports(icao, name, lat, lon) VALUES (?, ?, ?, ?)", (icao, name, lat, lon))
            c.execute("UPDATE airports SET lat=?, lon=? WHERE icao=? AND (lat IS NULL OR lon IS NULL)", (lat, lon, icao))

def set_meta(k, v):
    with db() as c:
        c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (k, str(v)))

def get_meta(k):
    with db() as c:
        r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r["v"] if r else None

# --- Fetching & parsing ----------------------------------------------------------------
# --- HTTPS trust ----------------------------------------------------------------------
# Some Python installs on macOS (e.g. the Command Line Tools Python) ship an old or empty
# certificate list, and work networks may inspect HTTPS with their own root certificate.
# Browsers trust what macOS trusts; Python only trusts its own list unless told. We add:
# macOS's built-in root certificates, certificates installed in the System and login
# keychains, and any CA_BUNDLE (.pem) file. Verification always stays on.
CA_BUNDLE = os.environ.get("CA_BUNDLE", "")
CERT_HELP = ("HTTPS certificate not trusted by Python. Either Python's certificate list is out of date, or the "
             "network inspects HTTPS with its own certificate. See 'Certificate errors' in README.md.")

def make_ssl_context():
    ctx = ssl.create_default_context()
    added = []
    if sys.platform == "darwin" and not os.environ.get("NO_KEYCHAIN"):
        for label, kc in (("macOS built-in root certificates", "/System/Library/Keychains/SystemRootCertificates.keychain"),
                          ("macOS System keychain", "/Library/Keychains/System.keychain"),
                          ("macOS login keychain", os.path.expanduser("~/Library/Keychains/login.keychain-db"))):
            if not os.path.exists(kc):
                continue
            try:
                pem = subprocess.run(["security", "find-certificate", "-a", "-p", kc],
                                     capture_output=True, text=True, timeout=20).stdout
                n = pem.count("BEGIN CERTIFICATE")
                if n:
                    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                        f.write(pem)
                    ctx.load_verify_locations(cafile=f.name); os.unlink(f.name)
                    added.append(f"{label} ({n})")
            except Exception as e:
                print(f"[https] couldn't read the {label}: {e}")
    if CA_BUNDLE:
        try:
            ctx.load_verify_locations(cafile=os.path.expanduser(CA_BUNDLE)); added.append(CA_BUNDLE)
        except Exception as e:
            print(f"[https] couldn't load CA_BUNDLE {CA_BUNDLE}: {e}")
    if added:
        print(f"[https] also trusting certificates from: {', '.join(added)}")
    return ctx

SSL_CTX = None

_chain_shown = False
def show_chain_once():
    """Print who issued the certificate the network presents for aviationweather.gov."""
    global _chain_shown
    if _chain_shown:
        return
    _chain_shown = True
    try:
        import socket
        raw = ssl.create_default_context(); raw.check_hostname = False; raw.verify_mode = ssl.CERT_NONE
        u = urllib.parse.urlparse(AWC); host, port = u.hostname, u.port or 443
        with socket.create_connection((host, port), timeout=10) as sock:
            with raw.wrap_socket(sock, server_hostname=host) as t:
                der = t.getpeercert(binary_form=True)       # only read for diagnosis; never used to send data
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
        info = ssl._ssl._test_decode_cert(f.name); os.unlink(f.name)
        issuer = ", ".join(f"{k}={v}" for part in info.get("issuer", ()) for k, v in part)
        print(f"[https] the certificate this network presents for aviationweather.gov is issued by: {issuer}")
        public = any(n in issuer for n in ("DigiCert", "GeoTrust", "Let's Encrypt", "Sectigo", "GlobalSign", "Amazon", "Entrust", "Google Trust"))
        if public:
            print("[https] that is a public certificate authority, so the network isn't intercepting: this Python's own "
                  "certificate list is missing its root. See 'Certificate errors' in README.md.")
        else:
            print("[https] that looks like a network or security product's certificate: find it (or its root) in "
                  "Keychain Access, export it as .pem, and start with CA_BUNDLE=/path/to/it.pem")
    except Exception as e:
        print(f"[https] couldn't inspect the certificate chain: {e}")

def is_cert_error(e):
    r = getattr(e, "reason", e)
    bad = isinstance(r, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(e)
    if bad:
        show_chain_once()
    return bad

def fetch_json(path, **params):
    url = f"{AWC}/{path}?{urllib.parse.urlencode(params)}"
    global SSL_CTX
    if SSL_CTX is None:
        SSL_CTX = make_ssl_context()
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=45, context=SSL_CTX) as r:
        body = r.read()
        if r.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
    return json.loads(body) if body.strip() else []

def num(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip().rstrip("+")
    try:
        if " " in s:                              # "1 1/2"
            w, f = s.split(" ", 1); a, b = f.split("/")
            return float(w) + float(a) / float(b)
        if "/" in s:
            a, b = s.split("/"); return float(a) / float(b)
        return float(s)
    except ValueError:
        return None

def ceiling_ft(clouds):
    bases = [c.get("base") for c in (clouds or [])
             if c.get("cover") in ("BKN", "OVC", "OVX", "VV") and c.get("base") is not None]
    return int(min(bases)) if bases else None

def flight_category(ceil, vis):
    # Standard ceiling/visibility categories (statute miles, feet AGL)
    if ceil is None and vis is None:
        return None
    c = ceil if ceil is not None else 99999
    v = vis if vis is not None else 99
    if c < 500 or v < 1: return "LIFR"
    if c < 1000 or v < 3: return "IFR"
    if c <= 3000 or v <= 5: return "MVFR"
    return "VFR"

def store_metars(items):
    rows = []
    for m in items or []:
        icao, t = m.get("icaoId"), m.get("obsTime")
        if icao not in AIRPORTS or not t:
            continue
        vis, ceil = num(m.get("visib")), ceiling_ft(m.get("clouds"))
        raw = m.get("rawOb") or ""
        rows.append((icao, int(t), raw, num(m.get("temp")), num(m.get("dewp")),
                     None if m.get("wdir") is None else str(m.get("wdir")),
                     num(m.get("wspd")), num(m.get("wgst")), vis, ceil, num(m.get("altim")),
                     flight_category(ceil, vis), 1 if " AUTO " in f" {raw} " else 0))
        if m.get("lat") is not None and m.get("lon") is not None:
            with db() as c:
                c.execute("UPDATE airports SET lat=?, lon=? WHERE icao=?",
                          (m["lat"], m["lon"], icao))
    with db() as c:
        c.executemany("INSERT OR REPLACE INTO obs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return len(rows)

def load_airport_coords():
    try:
        for a in fetch_json("airport", ids=IDS, format="json") or []:
            if a.get("icaoId") in AIRPORTS and a.get("lat") is not None:
                with db() as c:
                    c.execute("UPDATE airports SET lat=?, lon=? WHERE icao=?",
                              (float(a["lat"]), float(a["lon"]), a["icaoId"]))
    except Exception as e:
        print("[coords] airport lookup failed:", e)

def poll_once(hours):
    items = fetch_json("metar", ids=IDS, format="json", hours=hours)
    if len(items) >= API_MAX_RESULTS:
        print(f"[poll] warning: hit the {API_MAX_RESULTS}-report limit; some reports may be missing")
    n = store_metars(items)
    if KEEP_DAYS > 0:
        with db() as c:
            c.execute("DELETE FROM obs WHERE obs_time < ?", (int(time.time()) - KEEP_DAYS * 86400,))
    set_meta("last_poll", int(time.time())); set_meta("last_error", "")
    print(f"[poll] {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())} stored {n} reports (hours={hours})")

def fetch_history(icao, hours):
    """One airport's reports for the last `hours`. If the answer is cut off at the
    API's 400-report limit (busy weather, many SPECIs), ask again for the older part
    using the API's date parameter, until the whole period is covered."""
    want_from = time.time() - hours * 3600
    items = fetch_json("metar", ids=icao, format="json", hours=hours) or []
    got = list(items)
    for _ in range(40):                         # a busy airport can need ~8 pages for 30 days
        if len(items) < API_MAX_RESULTS:
            break
        oldest = min(m["obsTime"] for m in items if m.get("obsTime"))
        if oldest <= want_from:
            break
        remaining = math.ceil((oldest - want_from) / 3600) + 1
        date = time.strftime("%Y%m%d_%H%M", time.gmtime(oldest - 60))
        print(f"[backfill] {icao}: 400-report limit reached; fetching older reports before {date}Z")
        time.sleep(BACKFILL_DELAY)
        try:
            items = fetch_json("metar", ids=icao, format="json", hours=remaining, date=date) or []
        except urllib.error.HTTPError as e:
            print(f"[backfill] {icao}: couldn't fetch older reports ({e}); some of the period may be missing")
            break
        if not items or min(m["obsTime"] for m in items if m.get("obsTime")) >= oldest:
            break                               # no progress; stop rather than loop
        got += items
    return got

def report_rates():
    """Reports per hour for each airport over the stored last 7 days (None if nothing stored yet)."""
    now = int(time.time()); since = now - 7 * 86400
    with db() as c:
        rows = {r["icao"]: (r["n"], r["first"]) for r in c.execute(
            "SELECT icao, COUNT(*) n, MIN(obs_time) first FROM obs WHERE obs_time>=? GROUP BY icao", (since,))}
    done = set(json.loads(get_meta("backfilled_ids") or "[]"))
    rates = {}
    for icao in AIRPORTS:
        if icao in rows and now - rows[icao][1] >= 12 * 3600:   # need at least 12 h stored to judge
            n, first = rows[icao]
            rates[icao] = n / ((now - first) / 3600)
        elif icao in done and icao not in rows:
            rates[icao] = 0.05            # loaded before and had nothing: a non-reporting airport
        else:
            rates[icao] = None            # unknown
    return rates

def plan_groups(ids, hours):
    """Pack airports into shared requests that should stay under the report limit."""
    rates = report_rates()
    est = {i: (rates[i] if rates[i] is not None else 2.5) * hours * 1.3 + 2 for i in ids}
    groups, cur, load = [], [], 0.0
    for icao in sorted(ids, key=lambda i: -est[i]):
        if est[icao] >= GROUP_BUDGET:
            groups.append([icao]); continue        # busy airport: its own request, with paging
        if cur and load + est[icao] > GROUP_BUDGET:
            groups.append(cur); cur, load = [], 0.0
        cur.append(icao); load += est[icao]
    if cur:
        groups.append(cur)
    return groups

def backfill(hours, ids=None):
    """Load history using as few requests as possible. Airports are grouped into shared
    requests sized to stay under the API's 400-report limit; a busy airport gets its own
    request with paging, and a shared request that comes back full is redone one by one."""
    ids = list(ids or AIRPORTS)
    groups = plan_groups(ids, hours)
    total, failed, done_n, last_exc = 0, [], 0, None
    t0 = time.time()
    print(f"[backfill] loading the last {hours} h for {len(ids)} airport(s) in {len(groups)} request(s)…")
    for g in groups:
        if failed and is_cert_error(last_exc):
            print(f"[backfill] stopped: {CERT_HELP}")
            failed += [i for grp in groups[groups.index(g):] for i in grp]; break
        set_meta("backfill", f"{done_n}/{len(ids)}")
        try:
            if len(g) == 1:
                total += store_metars(fetch_history(g[0], hours))
            else:
                items = fetch_json("metar", ids=",".join(g), format="json", hours=hours) or []
                if len(items) >= API_MAX_RESULTS:
                    print(f"[backfill] shared request for {len(g)} airports was full; loading them one by one")
                    for icao in g:
                        time.sleep(BACKFILL_DELAY)
                        try:
                            total += store_metars(fetch_history(icao, hours))
                        except Exception as e:
                            failed.append(icao); last_exc = e; print(f"[backfill] {icao}: {e}")
                else:
                    total += store_metars(items)
        except Exception as e:
            failed += g; last_exc = e; print(f"[backfill] {','.join(g)}: {e}")
        done_n += len(g)
        time.sleep(BACKFILL_DELAY)
    set_meta("backfill", "")
    set_meta("last_poll", int(time.time()))
    print(f"[backfill] done in {time.time() - t0:.0f} s: {total} reports stored" + (f"; failed: {', '.join(failed)}" if failed else ""))
    done = set(json.loads(get_meta("backfilled_ids") or "[]")) | (set(ids) - set(failed))
    set_meta("backfilled_ids", json.dumps(sorted(done)))
    return not failed

def poller():
    # Current conditions first, so the board is useful within seconds of starting.
    gap_h = (time.time() - int(get_meta("last_poll") or 0)) / 3600   # how long the server was off
    try:
        poll_once(3)
    except Exception as e:
        set_meta("last_error", CERT_HELP if is_cert_error(e) else f"{type(e).__name__}: {e}"); print("[poll] error:", e)
    load_airport_coords()
    # Fill the full history window on first start, and once more after upgrading to a
    # longer window (e.g. from 7 to 30 days). Then fill any gap left while the server was off.
    if int(get_meta("history_loaded_h") or 0) < HISTORY_H:
        if backfill(HISTORY_H):
            set_meta("history_loaded_h", HISTORY_H)
            set_meta("backfill_v3", 1); set_meta("backfill_v2", 1)
    else:
        if get_meta("backfilled_ids") is None:   # databases from before airports could be added
            with db() as c:
                had = [r["icao"] for r in c.execute("SELECT DISTINCT icao FROM obs")]
            set_meta("backfilled_ids", json.dumps(sorted(had)))
        new = [k for k in AIRPORTS if k not in set(json.loads(get_meta("backfilled_ids")))]
        if new:
            backfill(HISTORY_H, new)             # airports added to the list since the last run
        if gap_h > 2:
            backfill(min(HISTORY_H, int(gap_h) + 2))
    while True:
        time.sleep(POLL_SECONDS)          # the first poll already ran at start-up
        try:
            poll_once(3)
        except Exception as e:
            set_meta("last_error", CERT_HELP if is_cert_error(e) else f"{type(e).__name__}: {e}")
            print("[poll] error:", e)

# --- API -------------------------------------------------------------------------------
def api_latest():
    out = []
    with db() as c:
        for a in c.execute("SELECT * FROM airports ORDER BY name"):
            o = c.execute("SELECT * FROM obs WHERE icao=? ORDER BY obs_time DESC LIMIT 1",
                          (a["icao"],)).fetchone()
            n24 = c.execute("SELECT COUNT(*) n, SUM(is_auto) a FROM obs WHERE icao=? AND obs_time>?",
                            (a["icao"], int(time.time()) - 86400)).fetchone()
            out.append({**dict(a), "latest": dict(o) if o else None,
                        "reports24h": n24["n"], "auto24h": n24["a"] or 0})
    return {"airports": out, "now": int(time.time()), "backfill": get_meta("backfill") or "", "historyDays": HISTORY_DAYS,
            "lastPoll": int(get_meta("last_poll") or 0), "lastError": get_meta("last_error") or ""}

RANK = {"VFR": 1, "MVFR": 2, "IFR": 3, "LIFR": 4}

def api_matrix(days):
    step = 3600 if days <= 7 else 3 * 3600      # 3-hour cells for the 30-day view keep the board readable
    end = (int(time.time()) // step + 1) * step
    start = end - days * 86400
    cells = days * 86400 // step
    grid = {k: [None] * cells for k in AIRPORTS}
    with db() as c:
        for r in c.execute("SELECT icao, obs_time, flt_cat FROM obs WHERE obs_time>=? AND obs_time<?",
                           (start, end)):
            i = (r["obs_time"] - start) // step
            cur = grid[r["icao"]][i]
            if r["flt_cat"] and (cur is None or RANK[r["flt_cat"]] > RANK.get(cur, 0)):
                grid[r["icao"]][i] = r["flt_cat"]      # worst category within the cell
            elif cur is None:
                grid[r["icao"]][i] = "NA"              # a report existed but had no cat
    return {"start": start, "step": step, "hours": cells, "rows": grid}

def api_history(icao, days):
    since = int(time.time()) - days * 86400
    with db() as c:
        rows = c.execute("SELECT * FROM obs WHERE icao=? AND obs_time>=? ORDER BY obs_time",
                         (icao, since)).fetchall()
    return {"icao": icao, "name": AIRPORTS.get(icao), "obs": [dict(r) for r in rows]}

def csv_export(icao, days):
    data = api_history(icao, days)["obs"]
    buf = io.StringIO(); w = csv.writer(buf)
    cols = ["icao", "obs_time", "temp", "dewp", "wdir", "wspd", "wgst", "visib",
            "ceiling", "altim", "flt_cat", "is_auto", "raw"]
    w.writerow(["obs_time_utc"] + cols)
    for r in data:
        w.writerow([time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["obs_time"]))] + [r[k] for k in cols])
    return buf.getvalue()

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=STATIC, **kw)

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        days = max(1, min(int(q.get("days", 7) or 7), 3650))
        icao = (q.get("icao") or "").upper()
        try:
            if u.path == "/api/latest":
                return self.send_json(api_latest())
            if u.path == "/api/matrix":
                return self.send_json(api_matrix(min(days, 31)))
            if u.path == "/api/history":
                if icao not in AIRPORTS:
                    return self.send_json({"error": "Unknown airport code"}, 404)
                return self.send_json(api_history(icao, days))
            if u.path == "/api/export.csv":
                if icao not in AIRPORTS:
                    return self.send_json({"error": "Unknown airport code"}, 404)
                body = csv_export(icao, days).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition", f'attachment; filename="{icao}_{days}d.csv"')
                self.end_headers(); return self.wfile.write(body)
        except Exception as e:
            return self.send_json({"error": str(e)}, 500)
        if u.path in ("/", "/index.html") and not os.path.isfile(os.path.join(STATIC, "index.html")):
            body = (f"<h1>Page file not found</h1><p>The server is running, but index.html is missing. "
                    f"Put index.html in <code>{os.path.join(HERE, 'static')}</code> "
                    f"(or next to server.py), then reload this page.</p>").encode()
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers(); return self.wfile.write(body)
        return super().do_GET()

    def log_message(self, *a):
        pass

def check(ids, days=HISTORY_DAYS):
    """Print what is stored for each airport: report count, first and last report, and gaps over 3 hours."""
    since = int(time.time()) - days * 86400
    fmt = lambda t: time.strftime("%a %d %b %H%MZ", time.gmtime(t))
    with db() as c:
        for icao in ids:
            ts = [r[0] for r in c.execute("SELECT obs_time FROM obs WHERE icao=? AND obs_time>=? ORDER BY obs_time", (icao, since))]
            name = AIRPORTS.get(icao, "?")
            if not ts:
                print(f"{icao} {name}: no reports stored in the last {days} days"); continue
            gaps = [(a, b) for a, b in zip(ts, ts[1:]) if b - a > 3 * 3600]
            lead = ts[0] - since
            print(f"{icao} {name}: {len(ts)} reports, first {fmt(ts[0])}, last {fmt(ts[-1])}")
            if lead > 3 * 3600:
                print(f"   nothing stored for the first {lead // 3600} h of the period (before {fmt(ts[0])})")
            for a, b in gaps:
                print(f"   gap of {(b - a) // 3600} h: {fmt(a)} to {fmt(b)}")

if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] in ("check", "refetch"):
    # python3 server.py check [ICAO ...]          show stored coverage (all airports if none given)
    # python3 server.py refetch ICAO [ICAO ...]   reload the full history window for those airports, then show coverage
    init_db()
    ids = [a.upper() for a in sys.argv[2:]] or list(AIRPORTS)
    unknown = [a for a in ids if a not in AIRPORTS]
    if unknown:
        sys.exit(f"Not on the airport list: {', '.join(unknown)}")
    if sys.argv[1] == "refetch":
        backfill(HISTORY_H, ids)
    check(ids)
    sys.exit(0)

if __name__ == "__main__":
    init_db()
    try:
        httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)   # claim the port before fetching anything
    except OSError as e:
        if e.errno in (48, 98, 10048):                             # address in use: macOS, Linux, Windows
            sys.exit(f"Port {PORT} is already in use, most likely by a copy of this server that is still running.\n"
                     f"  Stop it with Ctrl+C in its window, or find it with:  lsof -i :{PORT}   then:  kill <PID>\n"
                     f"  Or start this copy on another port:  PORT={PORT + 1} python3 server.py")
        raise
    page = os.path.join(STATIC, "index.html")
    if os.path.isfile(page):
        print(f"Serving page: {page}")
    else:
        print(f"WARNING: index.html not found. Put it in {os.path.join(HERE, 'static')} or next to server.py.")
    print(f"Open http://localhost:{PORT}  (polling every {POLL_SECONDS}s, db: {DB_PATH})")
    threading.Thread(target=poller, daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
