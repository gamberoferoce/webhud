"""Ponte locale tra la pagina HUD e le Nanoleaf della stanza.

Il token resta in bridge/config.json e non va nel repository.

  python bridge/server.py pair 192.168.1.20
  python bridge/server.py
  python bridge/server.py --tunnel
"""

import hmac
import json
import secrets
import socket
import struct
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CONFIG_PATH = Path(__file__).with_name("config.json")
NANOLEAF_PORT = 16021


def load_config():
    if not CONFIG_PATH.exists():
        config = {
            "host": "",
            "port": NANOLEAF_PORT,
            "token": "",
            "secret": secrets.token_urlsafe(18),
            "listenHost": "127.0.0.1",
            "listenPort": 8787,
        }
        save_config(config)
        print("Creato", CONFIG_PATH)
        print("Parola segreta:", config["secret"])
        return config
    with CONFIG_PATH.open(encoding="utf-8") as handle:
        config = json.load(handle)
    if not config.get("secret"):
        config["secret"] = secrets.token_urlsafe(18)
        save_config(config)
        print("Parola segreta:", config["secret"])
    return config


def save_config(config):
    CONFIG_PATH.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def encode_name(name):
    parts = name.rstrip(".").split(".")
    out = b""
    for part in parts:
        raw = part.encode("ascii")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def decode_name(packet, offset):
    labels = []
    jumped = False
    start = offset
    guard = 0
    while guard < 40:
        guard += 1
        if offset >= len(packet):
            break
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack(">H", packet[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                start = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(packet[offset:offset + length].decode("ascii", "replace"))
        offset += length
    consumed = start if jumped else offset
    return ".".join(labels), consumed


def discover_hosts(timeout=3):
    query = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    query += encode_name("_nanoleafapi._tcp.local")
    query += struct.pack(">HH", 12, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", 5353))
    except OSError:
        pass
    try:
        group = socket.inet_aton("224.0.0.251") + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group)
    except OSError:
        pass
    sock.settimeout(0.4)
    try:
        sock.sendto(query, ("224.0.0.251", 5353))
    except OSError as err:
        print("Ricerca in rete non riuscita:", err)
        sock.close()
        return []
    found = {}
    waited = 0
    while waited < timeout:
        try:
            packet, _addr = sock.recvfrom(4096)
        except socket.timeout:
            waited += 0.4
            continue
        for host, port in hosts_from_mdns(packet):
            found[(host, port)] = True
    sock.close()
    if found:
        return list(found.keys())
    return scan_port()


def hosts_from_mdns(packet):
    if len(packet) < 12:
        return []
    _qid, _flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", packet[:12])
    offset = 12
    for _ in range(qdcount):
        _name, offset = decode_name(packet, offset)
        offset += 4
    addresses = {}
    services = []
    for _ in range(ancount + nscount + arcount):
        if offset + 10 > len(packet):
            break
        name, offset = decode_name(packet, offset)
        if offset + 10 > len(packet):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", packet[offset:offset + 10])
        rdata_at = offset + 10
        offset = rdata_at + rdlength
        if offset > len(packet):
            break
        rdata = packet[rdata_at:offset]
        lowered = (name or "").lower()
        if rtype == 33 and len(rdata) >= 6 and "nanoleaf" in lowered:
            _priority, _weight, port = struct.unpack(">HHH", rdata[:6])
            target, _end = decode_name(packet, rdata_at + 6)
            services.append((target.rstrip(".").lower(), port or NANOLEAF_PORT))
        elif rtype == 1 and len(rdata) == 4 and name and "nanoleaf" in lowered:
            addresses[name.rstrip(".").lower()] = socket.inet_ntoa(rdata)
    results = []
    for target, port in services:
        ip = addresses.get(target)
        results.append((ip or target, port))
    if results:
        return results
    for name, ip in addresses.items():
        if "nanoleaf" in name:
            results.append((ip, NANOLEAF_PORT))
    return results


def local_prefixes():
    prefixes = []
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        infos = []
    for info in infos:
        ip = info[4][0]
        if ip.startswith("127.") or ip.startswith("100."):
            continue
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
            prefix = ip.rsplit(".", 1)[0]
            if prefix not in prefixes:
                prefixes.append(prefix)
    return prefixes


def scan_port():
    open_hosts = []
    lock = threading.Lock()

    def check(host):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        try:
            if sock.connect_ex((host, NANOLEAF_PORT)) == 0:
                with lock:
                    open_hosts.append((host, NANOLEAF_PORT))
        except OSError:
            pass
        finally:
            sock.close()

    for prefix in local_prefixes():
        threads = []
        for last in range(1, 255):
            thread = threading.Thread(target=check, args=("%s.%s" % (prefix, last),))
            thread.start()
            threads.append(thread)
            if len(threads) >= 40:
                for item in threads:
                    item.join()
                threads = []
        for item in threads:
            item.join()
    return open_hosts


def http_json(method, url, payload=None, timeout=5):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            return response.status, body
    except urllib.error.HTTPError as err:
        return err.code, err.read()
    except urllib.error.URLError as err:
        return 0, str(err.reason).encode("utf-8", "replace")


def pair(host):
    config = load_config()
    url = "http://%s:%s/api/v1/new" % (host, config.get("port") or NANOLEAF_PORT)
    print("Chiedo il token a", url)
    print("Il controller deve star lampeggiando.")
    status, body = http_json("POST", url, timeout=8)
    if status != 200:
        if status == 403:
            config["host"] = host
            save_config(config)
            print("Il controller ha risposto, ma non e' in pairing.")
            print("Tieni premuto il pulsante 5-7 secondi, finche' lampeggia, e rilancia il comando.")
        else:
            print("Accoppiamento non riuscito:", status, body.decode("utf-8", "replace"))
        return 1
    token = json.loads(body.decode("utf-8")).get("auth_token")
    if not token:
        print("Risposta senza token.")
        return 1
    config["host"] = host
    config["token"] = token
    save_config(config)
    print("Token salvato in", CONFIG_PATH)
    print("Parola segreta:", config["secret"])
    return 0


def nanoleaf_on(config):
    url = "http://%s:%s/api/v1/%s/state/on" % (config["host"], config.get("port") or NANOLEAF_PORT, config["token"])
    status, body = http_json("GET", url)
    if status != 200:
        raise RuntimeError("lettura %s" % status)
    return bool(json.loads(body.decode("utf-8")).get("value"))


def nanoleaf_set(config, acceso):
    url = "http://%s:%s/api/v1/%s/state" % (config["host"], config.get("port") or NANOLEAF_PORT, config["token"])
    status, _body = http_json("PUT", url, {"on": {"value": bool(acceso)}})
    if status not in (200, 204):
        raise RuntimeError("scrittura %s" % status)
    return bool(acceso)


def chiave_valida(config, data, query):
    attesa = config.get("secret") or ""
    ricevuta = ""
    if isinstance(data, dict) and data.get("k"):
        ricevuta = str(data.get("k"))
    elif query:
        ricevuta = query
    if not attesa or not ricevuta:
        return False
    return hmac.compare_digest(attesa, ricevuta)


def make_handler(config):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            print("%s - %s" % (self.address_string(), fmt % args))

        def cors(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

        def send_json(self, code, payload):
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def read_body(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))

        def do_OPTIONS(self):
            self.send_response(204)
            self.cors()
            self.end_headers()

        def do_GET(self):
            path, _, query = self.path.partition("?")
            if path != "/state":
                self.send_json(404, {"error": "non trovato"})
                return
            chiave = ""
            for piece in query.split("&"):
                if piece.startswith("k="):
                    from urllib.parse import unquote
                    chiave = unquote(piece[2:])
            if not chiave_valida(config, {}, chiave):
                self.send_json(401, {"error": "chiave"})
                return
            if not config.get("token") or not config.get("host"):
                self.send_json(503, {"error": "non accoppiato"})
                return
            try:
                self.send_json(200, {"on": nanoleaf_on(config)})
            except Exception as err:
                self.send_json(502, {"error": str(err)})

        def do_POST(self):
            if self.path.split("?", 1)[0] != "/toggle":
                self.send_json(404, {"error": "non trovato"})
                return
            try:
                data = self.read_body()
            except json.JSONDecodeError:
                self.send_json(400, {"error": "json"})
                return
            if not chiave_valida(config, data, ""):
                self.send_json(401, {"error": "chiave"})
                return
            if not config.get("token") or not config.get("host"):
                self.send_json(503, {"error": "non accoppiato"})
                return
            if "on" not in data:
                self.send_json(400, {"error": "manca on"})
                return
            try:
                acceso = nanoleaf_set(config, data["on"])
            except Exception as err:
                self.send_json(502, {"error": str(err)})
                return
            self.send_json(200, {"on": acceso})

    return Handler


def avvia_tunnel(port):
    try:
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", "http://127.0.0.1:%s" % port],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        print("cloudflared non e' installato. Il ponte resta su http://127.0.0.1:%s" % port)
        return

    def leggi():
        for line in proc.stdout:
            text = line.strip()
            if text:
                print(text)
            if "https://" in text and "trycloudflare.com" in text:
                inizio = text.find("https://")
                print("Indirizzo per gli occhiali:", text[inizio:].split()[0])

    threading.Thread(target=leggi, daemon=True).start()


def serve(tunnel):
    config = load_config()
    host = config.get("listenHost") or "127.0.0.1"
    port = int(config.get("listenPort") or 8787)
    server = ThreadingHTTPServer((host, port), make_handler(config))
    print("Ponte su http://%s:%s" % (host, port))
    print("Parola segreta:", config["secret"])
    if not config.get("token"):
        print("Manca il token. Accoppia con: python bridge/server.py pair INDIRIZZO")
    if tunnel:
        avvia_tunnel(port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Ponte chiuso.")


def main(argv):
    if len(argv) >= 2 and argv[1] == "pair":
        host = argv[2] if len(argv) >= 3 else ""
        if not host:
            trovati = discover_hosts()
            if not trovati:
                print("Nessuna Nanoleaf trovata. Passa l'indirizzo: python bridge/server.py pair 192.168.x.x")
                return 1
            for candidato, _port in trovati:
                print("Trovata", candidato)
                if pair(candidato) == 0:
                    return 0
            return 1
        return pair(host)
    tunnel = "--tunnel" in argv
    serve(tunnel)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
