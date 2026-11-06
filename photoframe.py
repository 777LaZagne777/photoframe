# PhotoFrame : cadre photo connecte pour Raspberry Pi
# Signe LaZagne
import os, time, imaplib, email, threading, subprocess, signal, socket, shutil, secrets, re
import json, urllib.request, urllib.parse, io, hashlib
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path
from functools import wraps
from datetime import timedelta

from flask import Flask, request, jsonify, send_from_directory, Response, redirect, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageOps, ImageFilter, ImageEnhance

EMAIL = os.getenv("GMAIL_USER")
PASSWORD = os.getenv("GMAIL_PASS")
IMAP_SERVER = "imap.gmail.com"

ENV_PATH = Path(__file__).parent / ".env"
PHOTO_DIR = Path(os.getenv("PHOTO_DIR", str(Path.home() / "photos")))
THUMB_DIR = PHOTO_DIR / ".thumbs"
DISPLAY_DIR = PHOTO_DIR / ".display"                       # versions a la taille de l'ecran (lues par feh)
META_PATH = PHOTO_DIR / ".meta.json"                       # source, expediteur et legende de chaque photo
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "60"))
SLIDE_DELAY = os.getenv("SLIDE_DELAY", "8")
SLIDE_ORDER = os.getenv("SLIDE_ORDER", "recent")          # "recent" ou "random"
MAIL_ENABLED = os.getenv("MAIL_ENABLED", "1") != "0"
THUMB_SIZE = int(os.getenv("THUMB_SIZE", "320"))
DISPLAY_MODES = ("mixte", "flou", "recadre", "bandes")
DISPLAY_MODE = os.getenv("DISPLAY_MODE", "mixte")
if DISPLAY_MODE not in DISPLAY_MODES:
    DISPLAY_MODE = "mixte"
DISPLAY_SIZE = os.getenv("DISPLAY_SIZE", "")              # "1920x1080" ; vide = detection xrandr
CROP_MAX_LOSS = 0.20                                      # mixte : recadre si on coupe moins de 20 %
EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".gif"}

# --- Telegram (reception directe des photos) ---
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "").strip()
TELEGRAM_CODE = os.getenv("TELEGRAM_CODE", "").strip()
TELEGRAM_ENABLED = os.getenv("TELEGRAM_ENABLED", "0") != "0"
TELEGRAM_ALLOW_PATH = Path(__file__).parent / "telegram_allowed.json"
# Gestionnaires : recoivent les nouvelles photos avec un bouton Supprimer et gerent le
# cadre a distance. Inscription par un code personnel a usage unique (exemple :
# /admin MONCODE) : il est desactive des qu'il a servi, pour qu'une personne qui le
# devine ensuite ne puisse pas s'en servir. Sinon : /ajouter, ou le site.
TELEGRAM_ADMIN_CODES = [c.strip() for c in os.getenv("TELEGRAM_ADMIN_CODES", "").split(",") if c.strip()]
TELEGRAM_ADMINS_PATH = Path(__file__).parent / "telegram_admins.json"
# Responsable du cadre : gestionnaire permanent, que personne ne peut retirer. Son code
# (/admin TELEGRAM_OWNER_NAME) est reutilisable mais ne marche que depuis son compte.
TELEGRAM_OWNER_ID = os.getenv("TELEGRAM_OWNER_ID", "").strip()
TELEGRAM_OWNER_NAME = os.getenv("TELEGRAM_OWNER_NAME", "").strip() or "Responsable"
# Envoi automatique de chaque nouvelle photo aux gestionnaires. Desactive par defaut :
# ils consultent les photos quand ils le souhaitent avec /photos.
ADMIN_NOTIFY = os.getenv("ADMIN_NOTIFY", "0") != "0"

WEB_PORT = int(os.getenv("WEB_PORT", "8080"))
WEB_USER = os.getenv("WEB_USER", "admin")
WEB_AUTH = os.getenv("WEB_AUTH", "1") != "0"             # "0" = pas de page de login

PHOTO_DIR.mkdir(parents=True, exist_ok=True)
THUMB_DIR.mkdir(parents=True, exist_ok=True)
DISPLAY_DIR.mkdir(parents=True, exist_ok=True)

viewer_proc = None
lock = threading.Lock()
env_lock = threading.Lock()


def update_env(updates):
    """Met a jour (ou ajoute) des cles KEY=val dans le fichier .env, en place.
    Une cle dont la valeur est None est supprimee du fichier."""
    updates = {k: (None if v is None else str(v).replace("\r", " ").replace("\n", " "))
               for k, v in updates.items()}
    with env_lock:
        lines, seen = [], set()
        if ENV_PATH.exists():
            for line in ENV_PATH.read_text().splitlines():
                m = re.match(r"\s*([A-Z_][A-Z0-9_]*)\s*=", line)
                if m and m.group(1) in updates:
                    k = m.group(1)
                    seen.add(k)
                    if updates[k] is None:
                        continue                      # suppression
                    lines.append(f"{k}={updates[k]}")
                else:
                    lines.append(line)
        for k, v in updates.items():
            if k not in seen and v is not None:
                lines.append(f"{k}={v}")
        ENV_PATH.write_text("\n".join(lines) + "\n")
        try:
            os.chmod(ENV_PATH, 0o600)                 # secrets non lisibles par les autres comptes
        except Exception:
            pass


# --- Auth par session : migration du mot de passe en clair vers un hash ---
SECRET_KEY = os.getenv("SECRET_KEY", "")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    update_env({"SECRET_KEY": SECRET_KEY})

WEB_PASS_HASH = os.getenv("WEB_PASS_HASH", "")
_legacy_pass = os.getenv("WEB_PASS", "")
if not WEB_PASS_HASH:
    if _legacy_pass:
        WEB_PASS_HASH = generate_password_hash(_legacy_pass)
    else:
        _gen = secrets.token_urlsafe(9)
        WEB_PASS_HASH = generate_password_hash(_gen)
        print(f"[AUTH] WEB_PASS non defini, mot de passe genere: {_gen}", flush=True)
    # on stocke le hash et on efface toute trace du mot de passe en clair
    update_env({"WEB_PASS_HASH": WEB_PASS_HASH, "WEB_PASS": None})

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=True,          # servi derriere HTTPS (Caddy)
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)


def _client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else (request.remote_addr or "?")


def _check_login(user, pw):
    try:
        return secrets.compare_digest(user, WEB_USER) and check_password_hash(WEB_PASS_HASH, pw)
    except Exception:
        return False


def requires_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not WEB_AUTH and not session.get("auth"):
            # Login desactive : session ouverte d'office (garde le jeton CSRF)
            session["auth"] = True
            session["csrf"] = secrets.token_urlsafe(32)
            session.permanent = True
        if not session.get("auth"):
            p = request.path
            if p.startswith("/api") or p.startswith("/photos") or p.startswith("/thumbnails"):
                return jsonify({"error": "non authentifie"}), 401
            return redirect("/login")
        return f(*a, **kw)
    return wrapper


@app.before_request
def csrf_guard():
    # Toute requete qui modifie l'etat doit porter l'en-tete X-CSRF egale au
    # jeton de session (le login en est exempte : il precede la session, et le
    # cookie SameSite=Strict le protege deja).
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if request.path == "/login":
            return
        token = session.get("csrf")
        if not token or request.headers.get("X-CSRF") != token:
            return jsonify({"error": "requete refusee (protection CSRF)"}), 403


def fetch_photos():
    try:
        m = imaplib.IMAP4_SSL(IMAP_SERVER)
        m.login(EMAIL, PASSWORD)
        m.select("inbox")
        _, data = m.search(None, "UNSEEN")
        new = False
        for num in data[0].split():
            _, d = m.fetch(num, "(RFC822)")
            msg = email.message_from_bytes(d[0][1])
            from_name, from_addr = parseaddr(msg.get("From", ""))
            sender = _decode_name(from_name) or from_addr
            for part in msg.walk():
                if part.get_content_maintype() == "multipart": continue
                fn = part.get_filename()
                if not fn: continue
                dh = decode_header(fn)[0]
                if isinstance(dh[0], bytes): fn = dh[0].decode(dh[1] or "utf-8")
                fn = secure_filename(fn)
                if not fn or Path(fn).suffix.lower() not in EXTS: continue
                ts = int(time.time() * 1000)
                path = PHOTO_DIR / f"{ts}_{fn}"
                with open(path, "wb") as f: f.write(part.get_payload(decode=True))
                generate_thumbnail(path)
                meta_update(path.name, {"source": "mail", "sender": sender, "received": int(time.time())})
                notify_admins(path)
                new = True
            m.store(num, "+FLAGS", "\\Seen")
        m.logout()
        return new
    except Exception as e:
        print(f"IMAP error: {e}")
        return False


def _decode_name(raw):
    try:
        parts = decode_header(raw)
        return "".join(
            (p.decode(enc or "utf-8", "replace") if isinstance(p, bytes) else p) for p, enc in parts
        ).strip()
    except Exception:
        return raw.strip()


_senders_cache = {"ts": 0.0, "data": None}


def get_senders(limit=300):
    """Liste les adresses mail presentes dans la boite (inbox), avec compte et dernier envoi.
    Resultat mis en cache 120s (IMAP est lent)."""
    if not (EMAIL and PASSWORD):
        return {"available": False, "error": "mail non configure", "senders": []}
    now = time.time()
    if _senders_cache["data"] and now - _senders_cache["ts"] < 120:
        return _senders_cache["data"]
    try:
        m = imaplib.IMAP4_SSL(IMAP_SERVER, timeout=20)
        m.login(EMAIL, PASSWORD)
        m.select("inbox", readonly=True)
        _, data = m.search(None, "ALL")
        ids = data[0].split()
        total = len(ids)
        ids = ids[-limit:]
        agg = {}
        if ids:
            _, resp = m.fetch(b",".join(ids), "(BODY.PEEK[HEADER.FIELDS (FROM DATE)])")
            for item in resp:
                if not isinstance(item, tuple):
                    continue
                hdr = email.message_from_bytes(item[1])
                name, addr = parseaddr(hdr.get("From", ""))
                if not addr:
                    continue
                addr = addr.lower()
                name = _decode_name(name)
                ts = 0
                try:
                    ts = int(parsedate_to_datetime(hdr.get("Date")).timestamp())
                except Exception:
                    pass
                e = agg.get(addr)
                if not e:
                    agg[addr] = {"email": addr, "name": name, "count": 1, "last": ts}
                else:
                    e["count"] += 1
                    if ts > e["last"]:
                        e["last"] = ts
                    if not e["name"] and name:
                        e["name"] = name
        m.logout()
        senders = sorted(agg.values(), key=lambda x: (x["count"], x["last"]), reverse=True)
        result = {"available": True, "senders": senders, "total": total, "analyzed": len(ids)}
        _senders_cache.update(ts=now, data=result)
        return result
    except Exception as e:
        return {"available": False, "error": str(e), "senders": []}


def get_photos_sorted():
    return sorted([p for p in PHOTO_DIR.iterdir() if p.is_file() and p.suffix.lower() in EXTS],
                  key=lambda p: p.stat().st_mtime, reverse=True)


# --- Infos par photo (.meta.json) : qui l'a envoyee, par quel canal, quand, avec
# quelle legende. Ecrit a la reception (Telegram, mail, site). ---
meta_lock = threading.Lock()


def meta_load():
    try:
        return json.loads(META_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def meta_update(name, info):
    """Enregistre les infos d'une photo (info=None : les efface)."""
    with meta_lock:
        meta = meta_load()
        if info is None:
            meta.pop(name, None)
        else:
            meta[name] = info
        tmp = META_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, META_PATH)


def photo_info(p, meta):
    """Infos d'une photo. Pour les photos recues avant .meta.json, on les deduit du
    nom : {ms}_tg_{Nom}.jpg pour Telegram, {ms}_{fichier} pour le mail ou le site."""
    info = dict(meta.get(p.name) or {})
    ts, _, rest = p.stem.partition("_")
    if "received" not in info:
        info["received"] = int(ts) // 1000 if ts.isdigit() else int(p.stat().st_mtime)
    if "source" not in info:
        if rest.startswith("tg_"):
            info["source"] = "telegram"
            info.setdefault("sender", rest[3:].replace("_", " "))
        else:
            info["source"] = "inconnue"
    return info


def delete_photo(path):
    """Supprime une photo et tout ce qui en derive (miniature, version ecran, infos)."""
    path.unlink(missing_ok=True)
    (THUMB_DIR / f"{path.stem}.jpg").unlink(missing_ok=True)
    (DISPLAY_DIR / f"{path.stem}.jpg").unlink(missing_ok=True)
    meta_update(path.name, None)


def generate_thumbnail(path):
    thumb_path = THUMB_DIR / f"{path.stem}.jpg"
    try:
        with Image.open(path) as img:
            img = ImageOps.exif_transpose(img).convert("RGB")
            img.thumbnail((THUMB_SIZE, THUMB_SIZE))
            img.save(thumb_path, "JPEG", quality=80)
    except Exception as e:
        print(f"Thumbnail error {path.name}: {e}", flush=True)


# --- Versions "ecran" : chaque photo est preparee UNE fois a la taille exacte de
# l'ecran, avec un redimensionnement de qualite. feh les affiche telles quelles :
# plus de bandes noires, et le Pi 2 n'a plus a decoder des photos de 12 Mpx a
# chaque transition. Les originaux restent intacts (site, telechargement). ---
_display_lock = threading.Lock()


def screen_size():
    """Taille de l'ecran : DISPLAY_SIZE (.env), sinon detectee par xrandr puis
    memorisee dans .env. 1920x1080 par defaut si X n'est pas encore pret."""
    global DISPLAY_SIZE
    m = re.fullmatch(r"(\d+)x(\d+)", DISPLAY_SIZE)
    if m:
        return int(m.group(1)), int(m.group(2))
    try:
        out = subprocess.run(["xrandr"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"current (\d+) x (\d+)", out)
        if m:
            DISPLAY_SIZE = f"{m.group(1)}x{m.group(2)}"
            update_env({"DISPLAY_SIZE": DISPLAY_SIZE})
            return int(m.group(1)), int(m.group(2))
    except Exception as e:
        print(f"[DISPLAY] detection de l'ecran impossible : {e}", flush=True)
    return 1920, 1080


def generate_display(path, size):
    """Version ecran de la photo selon DISPLAY_MODE : recadre (remplit l'ecran),
    flou (photo entiere sur fond flou), bandes (noir), ou mixte (recadre si on
    coupe moins de CROP_MAX_LOSS de l'image, sinon fond flou)."""
    W, H = size
    out = DISPLAY_DIR / f"{path.stem}.jpg"
    try:
        with Image.open(path) as img:
            img.draft("RGB", (W, H))                  # decodage JPEG reduit : bien plus rapide sur Pi 2
            img = ImageOps.exif_transpose(img).convert("RGB")
        r_img, r_scr = img.width / img.height, W / H
        mode = DISPLAY_MODE
        if mode == "mixte":
            loss = 1 - min(r_img, r_scr) / max(r_img, r_scr)
            mode = "recadre" if loss <= CROP_MAX_LOSS else "flou"
        if mode == "recadre":
            # coupe un peu plus en bas qu'en haut : epargne les tetes
            frame = ImageOps.fit(img, (W, H), Image.LANCZOS, centering=(0.5, 0.4))
        else:
            s = min(W / img.width, H / img.height)
            fg = img.resize((max(1, round(img.width * s)), max(1, round(img.height * s))), Image.LANCZOS)
            if mode == "flou":
                frame = ImageOps.fit(img, (W // 8, H // 8), Image.BILINEAR).filter(ImageFilter.GaussianBlur(3))
                frame = ImageEnhance.Brightness(frame.resize((W, H), Image.BICUBIC)).enhance(0.55)
            else:
                frame = Image.new("RGB", (W, H))
            frame.paste(fg, ((W - fg.width) // 2, (H - fg.height) // 2))
        tmp = out.with_suffix(".tmp")
        frame.save(tmp, "JPEG", quality=92)
        os.replace(tmp, out)                          # feh ne voit jamais un fichier a moitie ecrit
    except Exception as e:
        print(f"Display error {path.name}: {e}", flush=True)


def sync_displays():
    """Prepare les versions ecran manquantes (toutes si le mode ou l'ecran a change)
    et supprime celles des photos effacees. Appele avant chaque relance de feh."""
    with _display_lock:
        size = screen_size()
        sig = f"v1 {DISPLAY_MODE} {size[0]}x{size[1]}"
        marker = DISPLAY_DIR / ".mode"
        stale = not marker.exists() or marker.read_text().strip() != sig
        photos = get_photos_sorted()
        todo = [p for p in photos if stale or not (DISPLAY_DIR / f"{p.stem}.jpg").exists()]
        if todo:
            print(f"[DISPLAY] preparation de {len(todo)} photo(s) ({sig})", flush=True)
        for p in todo:
            generate_display(p, size)
        keep = {p.stem for p in photos}
        for d in DISPLAY_DIR.glob("*.jpg"):
            if d.stem not in keep:
                d.unlink(missing_ok=True)
        marker.write_text(sig)


def display_file(photo):
    """Version ecran de la photo si elle est prete, sinon l'originale."""
    d = DISPLAY_DIR / f"{photo.stem}.jpg"
    return d if d.exists() else photo


def safe_path(base, filename):
    filename = secure_filename(filename)
    if not filename:
        return None
    candidate = base / filename
    try:
        candidate = candidate.resolve()
        base_r = base.resolve()
    except Exception:
        return None
    if candidate.parent != base_r or not candidate.exists():
        return None
    return candidate


def start_viewer(photos):
    global viewer_proc
    if viewer_proc:
        try: viewer_proc.terminate(); viewer_proc.wait(timeout=3)
        except Exception:
            try: viewer_proc.kill(); viewer_proc.wait(timeout=2)
            except Exception: pass
        # Laisse labwc/Xwayland detruire l'ancienne fenetre avant d'en mapper une
        # nouvelle. Sans ce delai, le compositeur emet des BadWindow
        # (voir ~/.xsession-errors) et la nouvelle feh peut ne jamais s'afficher.
        time.sleep(0.5)
    if not photos:
        viewer_proc = None
        return
    cmd = ["feh", "--fullscreen", "--hide-pointer", "--auto-zoom",
           "--slideshow-delay", str(SLIDE_DELAY), "--no-fehbg"]
    if SLIDE_ORDER == "random":
        cmd.append("--randomize")
    cmd += [str(display_file(p)) for p in photos]
    try:
        viewer_proc = subprocess.Popen(cmd)
    except Exception as e:
        # viewer_proc reste None : le watchdog reessaiera au lieu de laisser
        # le cadre eteint jusqu'a une intervention manuelle.
        viewer_proc = None
        print(f"[VIEWER] echec du lancement de feh : {e}", flush=True)


def refresh_viewer():
    sync_displays()          # hors du verrou : ~2 s par nouvelle photo, le watchdog reste libre
    with lock:
        start_viewer(get_photos_sorted())


# --- Rafraichissement debounce : une rafale de photos (album Telegram, import
# multiple, mail) ne relance feh QU'UNE fois, apres un court silence. Evite le
# thrashing qui empechait feh de se relancer sur les gros envois.
# REFRESH_QUIET a 2.5 s etait trop court : sur le WiFi du Pi, deux photos d'un
# meme album peuvent etre espacees de 4-5 s, ce qui produisait ~5 relances de feh
# pour une rafale de 12 photos. Chaque relance est une occasion de rater le
# demarrage ; on veut donc une seule relance par rafale. ---
REFRESH_QUIET = 8.0
_refresh_ts = 0.0
_refresh_evt = threading.Event()


def request_refresh():
    global _refresh_ts
    _refresh_ts = time.monotonic()
    _refresh_evt.set()


def refresh_worker():
    while True:
        _refresh_evt.wait()
        while time.monotonic() - _refresh_ts < REFRESH_QUIET:
            time.sleep(0.4)
        _refresh_evt.clear()
        try:
            refresh_viewer()
        except Exception as e:
            print(f"refresh error: {e}", flush=True)


# --- Surveillance de feh -----------------------------------------------------
# Jusqu'ici feh n'etait (re)lance QUE par un refresh explicite. S'il mourait
# entre deux refresh (crash, Xwayland pas encore pret au demarrage, plantage a la
# relance pendant une rafale), plus rien ne le relancait : le cadre restait
# eteint jusqu'a un clic manuel sur "Relancer le diaporama". C'est la cause du
# symptome "le diaporama ne se rallume pas tout seul apres un envoi Telegram".
VIEWER_CHECK = 5.0


def viewer_watchdog():
    fails = 0
    while True:
        time.sleep(VIEWER_CHECK)
        try:
            with lock:
                photos = get_photos_sorted()
                if not photos:
                    continue
                if viewer_proc is not None and viewer_proc.poll() is None:
                    fails = 0
                    continue
                fails += 1
                print(f"[VIEWER] feh absent, relance automatique (essai {fails})",
                      flush=True)
                start_viewer(photos)
            # Si feh remeurt aussitot (X indisponible), on espace les tentatives
            # au lieu de boucler : 5 s, puis jusqu'a 60 s.
            if fails > 3:
                time.sleep(min(60, VIEWER_CHECK * fails))
        except Exception as e:
            print(f"[VIEWER] erreur watchdog : {e}", flush=True)


def mail_loop():
    while True:
        if MAIL_ENABLED and EMAIL and PASSWORD:
            if fetch_photos():
                request_refresh()
        time.sleep(max(10, CHECK_INTERVAL))


# ------------------------- Telegram -------------------------
tg_lock = threading.Lock()
_tg_offset = 0


def tg_api(method, params=None, timeout=35):
    if not TELEGRAM_TOKEN:
        return {"ok": False, "error": "token absent"}
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/{method}"
    data = urllib.parse.urlencode(params or {}).encode() if params else None
    req = urllib.request.Request(url, data=data)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def tg_call(method, params):
    """tg_api sans exception : les erreurs sont seulement journalisees."""
    try:
        return tg_api(method, params, timeout=15)
    except Exception as e:
        print(f"Telegram {method} error: {e}", flush=True)
        return {}


def tg_send(chat_id, text, buttons=None, markup=None):
    """buttons : boutons sous le message ; markup : clavier brut (ex. remove_keyboard)."""
    params = {"chat_id": chat_id, "text": text}
    if buttons:
        markup = {"inline_keyboard": buttons}
    if markup:
        params["reply_markup"] = json.dumps(markup)
    tg_call("sendMessage", params)


def tg_send_photo(chat_id, jpeg, caption="", buttons=None):
    """sendPhoto en envoyant le fichier (multipart) : le Pi n'est pas joignable depuis
    Internet, Telegram ne peut donc pas venir chercher l'image par URL."""
    boundary = secrets.token_hex(16)
    fields = {"chat_id": str(chat_id), "caption": caption}
    if buttons:
        fields["reply_markup"] = json.dumps({"inline_keyboard": buttons})
    body = b"".join(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
                    for k, v in fields.items())
    body += (f'--{boundary}\r\nContent-Disposition: form-data; name="photo"; filename="photo.jpg"\r\n'
             f'Content-Type: image/jpeg\r\n\r\n').encode() + jpeg + f'\r\n--{boundary}--\r\n'.encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendPhoto", data=body,
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def tg_load_allowed():
    try:
        return json.loads(TELEGRAM_ALLOW_PATH.read_text())
    except Exception:
        return {}


def tg_save_allowed(d):
    with tg_lock:
        TELEGRAM_ALLOW_PATH.write_text(json.dumps(d, ensure_ascii=False, indent=2))


def tg_load_admins():
    try:
        admins = json.loads(TELEGRAM_ADMINS_PATH.read_text())
    except Exception:
        admins = {}
    if TELEGRAM_OWNER_ID:                          # toujours gestionnaire, quoi que contienne le fichier
        owner = admins.setdefault(TELEGRAM_OWNER_ID, {"name": TELEGRAM_OWNER_NAME, "since": 0})
        owner["owner"] = True
    return admins


def tg_save_admins(d):
    with tg_lock:
        TELEGRAM_ADMINS_PATH.write_text(json.dumps(d, ensure_ascii=False, indent=2))


def tg_download(file_id, prefix):
    info = tg_api("getFile", {"file_id": file_id}, timeout=20)
    if not info.get("ok"):
        return None
    fpath = info["result"]["file_path"]
    ext = Path(fpath).suffix.lower()
    if ext not in EXTS:
        ext = ".jpg"
    url = f"https://api.telegram.org/file/bot{TELEGRAM_TOKEN}/{fpath}"
    out = PHOTO_DIR / f"{int(time.time()*1000)}_tg_{prefix}{ext}"
    # Telechargement dans un .part, puis decodage complet avant de le garder : une
    # connexion coupee laissait sinon une photo tronquee (moitie grise) sur le cadre.
    tmp = PHOTO_DIR / f"{out.name}.part"
    try:
        with urllib.request.urlopen(url, timeout=30) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
        with Image.open(tmp) as im:
            im.draft("RGB", (THUMB_SIZE, THUMB_SIZE))
            im.load()                                  # leve une erreur si l'image est tronquee
        os.replace(tmp, out)
    finally:
        tmp.unlink(missing_ok=True)
    return out


# ------------------------- Telegram : gestionnaires -------------------------
MOIS = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."]
SOURCE_ICONS = {"telegram": "📱", "mail": "✉️", "site": "💻"}
PHOTOS_PAGE = 10
ADMIN_MAX_FAILS = 5                       # essais de code gestionnaire par heure et par compte
_admin_fails = {}                         # chat_id -> (nb d'echecs, debut de la fenetre)
ADMIN_HELP = ("🛠 Commandes gestionnaire :\n"
              "/photos – les 10 dernières photos, avec un bouton Supprimer\n"
              "/statut – état du cadre\n"
              "/diaporama – relancer l'affichage\n"
              "/ajouter – donner les droits gestionnaire à quelqu'un\n"
              "/retirer – retirer les droits d'un gestionnaire\n\n"
              "Tu peux toujours envoyer des photos au cadre, comme d'habitude.\n"
              "Les photos ne te sont pas envoyées automatiquement : envoie /photos quand tu veux les consulter.")


def photo_label(info):
    """« 📱 Expediteur · 1 janv. 2026 », plus la legende eventuelle."""
    t = time.localtime(info["received"])
    who = info.get("sender") or ("Ajout depuis le site" if info["source"] == "site" else "Mail ou site")
    label = f"{SOURCE_ICONS.get(info['source'], '📷')} {who} · {t.tm_mday} {MOIS[t.tm_mon - 1]} {t.tm_year}"
    if info.get("caption"):
        label += f"\n« {info['caption']} »"
    return label


def photo_key(name):
    """Identifiant court d'une photo pour les boutons (callback_data : 64 octets max)."""
    return hashlib.sha1(name.encode()).hexdigest()[:12]


def find_photo(key):
    return next((p for p in get_photos_sorted() if photo_key(p.name) == key), None)


def tg_preview(path, size=960):
    """Apercu JPEG leger d'une photo pour Telegram (le Wi-Fi du Pi 2 est lent)."""
    with Image.open(path) as img:
        img.draft("RGB", (size, size))
        img = ImageOps.exif_transpose(img).convert("RGB")
    img.thumbnail((size, size))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=82)
    return buf.getvalue()


def del_button(key):
    return [[{"text": "🗑 Supprimer du cadre", "callback_data": f"d:{key}"}]]


def notify_admins(path, exclude=None):
    """Envoie une photo qui vient d'arriver a chaque gestionnaire, avec un bouton Supprimer.
    En arriere-plan : l'envoi ne doit pas retarder la reception des photos suivantes."""
    admins = [cid for cid in tg_load_admins() if cid != exclude]
    if not (ADMIN_NOTIFY and admins and TELEGRAM_ENABLED and TELEGRAM_TOKEN):
        return

    def run():
        try:
            jpeg = tg_preview(path)
            caption = "🆕 Nouvelle photo sur le cadre\n" + photo_label(photo_info(path, meta_load()))
        except Exception as e:
            print(f"[ADMIN] apercu impossible pour {path.name} : {e}", flush=True)
            return
        for cid in admins:
            try:
                tg_send_photo(cid, jpeg, caption, del_button(photo_key(path.name)))
            except Exception as e:
                print(f"[ADMIN] notification a {cid} impossible : {e}", flush=True)
    threading.Thread(target=run, daemon=True).start()


def use_admin_code(code):
    """Desactive un code gestionnaire qui vient de servir (usage unique)."""
    global TELEGRAM_ADMIN_CODES
    TELEGRAM_ADMIN_CODES = [c for c in TELEGRAM_ADMIN_CODES if c != code]
    update_env({"TELEGRAM_ADMIN_CODES": ",".join(TELEGRAM_ADMIN_CODES)})


def tg_admin_register(chat_id, name, code):
    now = time.time()
    fails, since = _admin_fails.get(chat_id, (0, now))
    if now - since > 3600:
        fails, since = 0, now
    if fails >= ADMIN_MAX_FAILS:
        tg_send(chat_id, "⛔ Trop d'essais. Réessaie dans une heure.")
        return
    if not code:
        tg_send(chat_id, "Envoie /admin suivi de ton code gestionnaire, par exemple :\n/admin MONCODE")
        return
    admins = tg_load_admins()
    if chat_id == TELEGRAM_OWNER_ID:
        tg_send(chat_id, f"✅ {TELEGRAM_OWNER_NAME}, tu es le responsable du cadre : tes droits gestionnaire "
                         "sont permanents.\n\n" + ADMIN_HELP)
        return
    if chat_id in admins:
        tg_send(chat_id, "Tu es déjà gestionnaire.\n\n" + ADMIN_HELP)
        return
    match = next((c for c in TELEGRAM_ADMIN_CODES if c.lower() == code.lower()), None)
    if match:
        _admin_fails.pop(chat_id, None)
        admins[chat_id] = {"name": match, "telegram_name": name, "since": int(now), "added_by": "code personnel"}
        tg_save_admins(admins)
        use_admin_code(match)
        print(f"[ADMIN] {match} ({name}, {chat_id}) enregistre(e) comme gestionnaire ; code desactive", flush=True)
        tg_send(chat_id, f"✅ Bienvenue {match}, tu es enregistré(e) comme gestionnaire.\n\n" + ADMIN_HELP)
    else:
        _admin_fails[chat_id] = (fails + 1, since)
        print(f"[ADMIN] code gestionnaire refuse pour {name} ({chat_id})", flush=True)
        tg_send(chat_id, "🔒 Code gestionnaire incorrect.")


def tg_add_admin(cid, name, by):
    """Donne les droits gestionnaire a cid et le previent (possible seulement s'il a deja
    ecrit au bot : sinon il les decouvrira en ouvrant le bot)."""
    admins = tg_load_admins()
    if cid in admins:
        return False
    admins[cid] = {"name": name, "since": int(time.time()), "added_by": by}
    tg_save_admins(admins)
    print(f"[ADMIN] {name} ({cid}) nomme(e) gestionnaire par {by}", flush=True)
    tg_send(cid, f"✅ Tu as maintenant les droits gestionnaire sur le cadre photo (ajouté par {by}).\n\n" + ADMIN_HELP)
    return True


def tg_remove_admin(cid, by):
    """Retire les droits gestionnaire de cid. Renvoie son nom, ou None s'il ne les avait pas
    (ou si c'est le responsable, dont les droits sont permanents)."""
    admins = tg_load_admins()
    if cid not in admins or cid == TELEGRAM_OWNER_ID:
        return None
    who = admins.pop(cid).get("name") or cid
    tg_save_admins(admins)
    print(f"[ADMIN] {who} ({cid}) retire(e) des gestionnaires par {by}", flush=True)
    return who


def tg_add_menu(chat_id):
    """/ajouter : les personnes qui ont deja envoye des photos (un clic), sinon le
    selecteur de contacts Telegram (fonctionne meme si la personne n'a jamais ecrit au bot)."""
    admins = tg_load_admins()
    known = [(cid, v.get("name") or cid) for cid, v in tg_load_allowed().items() if cid not in admins]
    if known:
        tg_send(chat_id, "➕ Qui doit gérer le cadre ? Personnes ayant déjà envoyé des photos :",
                [[{"text": n, "callback_data": f"a:{cid}"}] for cid, n in known[:20]])
    tg_send(chat_id, "Pour quelqu'un d'autre, choisis-le dans tes contacts avec le bouton en bas de l'écran.",
            markup={"keyboard": [[{"text": "📇 Choisir dans mes contacts",
                                   "request_users": {"request_id": 1, "user_is_bot": False,
                                                     "max_quantity": 1, "request_name": True}}],
                                 [{"text": "Annuler"}]],
                    "resize_keyboard": True, "one_time_keyboard": True})


def tg_status_text():
    photos = get_photos_sorted()
    up = get_uptime() or 0
    running = viewer_proc is not None and viewer_proc.poll() is None
    lines = ["🖼 État du cadre",
             f"Diaporama : {'✅ actif' if running else '⚠️ arrêté'}",
             f"Photos : {len(photos)}",
             f"Température : {get_temp()}",
             f"Disque : {get_disk()['free_gb']} Go libres",
             f"Allumé depuis : {up // 86400} j {up % 86400 // 3600} h"]
    if photos:
        lines.append("Dernière photo : " + photo_label(photo_info(photos[0], meta_load())).split("\n")[0])
    if get_throttled().get("undervoltage_now"):
        lines.append("⚠️ Alimentation insuffisante !")
    return "\n".join(lines)


def tg_send_photos_page(chat_id, offset):
    """/photos : PHOTOS_PAGE photos a partir de offset (plus recentes d'abord), chacune
    avec son bouton Supprimer, puis un bouton pour la page suivante."""
    photos = get_photos_sorted()
    page = photos[offset:offset + PHOTOS_PAGE]
    if not page:
        tg_send(chat_id, "Il n'y a pas d'autres photos." if photos else "Aucune photo sur le cadre.")
        return
    meta = meta_load()
    for p in page:
        try:
            tg_send_photo(chat_id, tg_preview(p, 640), photo_label(photo_info(p, meta)), del_button(photo_key(p.name)))
        except Exception as e:
            print(f"[ADMIN] envoi de {p.name} impossible : {e}", flush=True)
    end = offset + len(page)
    text = f"Photos {offset + 1} à {end} sur {len(photos)}."
    more = [[{"text": f"Voir les {PHOTOS_PAGE} suivantes ▶", "callback_data": f"p:{end}"}]] if end < len(photos) else None
    tg_send(chat_id, text, more)


def tg_admin_command(chat_id, text):
    """Commandes reservees aux gestionnaires. Renvoie False si ce n'en est pas une."""
    cmd = text.split()[0].lower().split("@")[0]          # /photos@MonBot dans un groupe
    if cmd in ("/start", "/aide", "/help"):
        tg_send(chat_id, ADMIN_HELP)
    elif cmd == "/photos":
        threading.Thread(target=tg_send_photos_page, args=(chat_id, 0), daemon=True).start()
    elif cmd == "/statut":
        tg_send(chat_id, tg_status_text())
    elif cmd == "/diaporama":
        threading.Thread(target=refresh_viewer, daemon=True).start()
        tg_send(chat_id, "🔄 Diaporama relancé.")
    elif cmd == "/ajouter":
        tg_add_menu(chat_id)
    elif cmd == "/retirer":
        # ni le responsable, ni soi-meme : pas de retrait par erreur de ses propres droits
        others = [(cid, v.get("name") or cid) for cid, v in tg_load_admins().items()
                  if not v.get("owner") and cid != chat_id]
        if others:
            tg_send(chat_id, "➖ Retirer les droits gestionnaire de qui ?",
                    [[{"text": n, "callback_data": f"r:{cid}"}] for cid, n in others])
        else:
            tg_send(chat_id, "Il n'y a aucun autre gestionnaire à retirer.")
    else:
        return False
    return True


def handle_tg_callback(cq):
    """Boutons des messages envoyes aux gestionnaires : d = demander la suppression,
    c = la confirmer, x = l'annuler, p = page suivante de /photos."""
    msg = cq.get("message") or {}
    chat_id = str(msg.get("chat", {}).get("id", ""))
    frm = cq.get("from", {})
    name = (frm.get("first_name", "") + " " + frm.get("last_name", "")).strip() or frm.get("username", "") or chat_id
    action, _, arg = (cq.get("data") or "").partition(":")

    def answer(text=""):
        tg_call("answerCallbackQuery", {"callback_query_id": cq.get("id", ""), "text": text})

    def set_buttons(buttons):
        tg_call("editMessageReplyMarkup", {"chat_id": chat_id, "message_id": msg.get("message_id"),
                                           "reply_markup": json.dumps({"inline_keyboard": buttons})})

    if chat_id not in tg_load_admins():
        answer("🔒 Réservé aux gestionnaires.")
        return
    if action == "p":
        answer()
        threading.Thread(target=tg_send_photos_page, args=(chat_id, int(arg) if arg.isdigit() else 0),
                         daemon=True).start()
        return
    if action == "a":                                  # /ajouter : personne choisie dans la liste
        who = tg_load_allowed().get(arg, {}).get("name") or arg
        added = tg_add_admin(arg, who, name)
        answer("✅ Ajouté" if added else "Déjà gestionnaire")
        tg_call("editMessageText", {"chat_id": chat_id, "message_id": msg.get("message_id"),
                                    "text": f"✅ {who} a maintenant les droits gestionnaire." if added
                                    else f"{who} était déjà gestionnaire."})
        return
    if action == "r" and arg == TELEGRAM_OWNER_ID:
        answer("Le responsable du cadre ne peut pas être retiré.")
        return
    if action == "r" and arg == chat_id:
        answer("Tu ne peux pas te retirer toi-même.")
        return
    if action == "r":                                  # /retirer
        who = tg_remove_admin(arg, name)
        if who and arg != chat_id:
            tg_send(arg, "🔒 Tu ne gères plus le cadre photo.")
        answer()
        tg_call("editMessageText", {"chat_id": chat_id, "message_id": msg.get("message_id"),
                                    "text": f"➖ {who} n'a plus les droits gestionnaire." if who
                                    else "Cette personne n'était déjà plus gestionnaire."})
        return
    photo = find_photo(arg)
    if action in ("d", "c") and not photo:
        answer("Cette photo n'est déjà plus sur le cadre.")
        set_buttons([])
    elif action == "d":
        answer()
        set_buttons([[{"text": "✅ Oui, supprimer", "callback_data": f"c:{arg}"},
                      {"text": "Annuler", "callback_data": f"x:{arg}"}]])
    elif action == "x":
        answer("Suppression annulée")
        set_buttons(del_button(arg) if photo else [])
    elif action == "c":
        delete_photo(photo)
        request_refresh()
        print(f"[ADMIN] {photo.name} supprimee par {name} ({chat_id}) via Telegram", flush=True)
        answer("🗑 Photo supprimée du cadre")
        tg_call("editMessageCaption", {"chat_id": chat_id, "message_id": msg.get("message_id"),
                                       "caption": (msg.get("caption") or "") + f"\n\n🗑 Supprimée du cadre par {name}",
                                       "reply_markup": json.dumps({"inline_keyboard": []})})
    else:
        answer()


def handle_tg_update(upd):
    msg = upd.get("message") or upd.get("channel_post")
    if not msg:
        return
    chat_id = str(msg.get("chat", {}).get("id", ""))
    frm = msg.get("from", {})
    name = (frm.get("first_name", "") + " " + frm.get("last_name", "")).strip() \
        or frm.get("username", "") or chat_id
    text = (msg.get("text") or "").strip()
    allowed = tg_load_allowed()
    admins = tg_load_admins()

    # Reponse au selecteur de contacts de /ajouter
    shared = msg.get("users_shared")
    if shared and chat_id in admins:
        users = shared.get("users") or [{"user_id": u} for u in shared.get("user_ids", [])]
        for u in users:
            cid = str(u.get("user_id", ""))
            who = (u.get("first_name", "") + " " + u.get("last_name", "")).strip() or u.get("username", "") \
                or f"Gestionnaire {cid}"
            if tg_add_admin(cid, who, name):
                reply = (f"✅ {who} a maintenant les droits gestionnaire. S'il n'a jamais écrit au bot, "
                         "il doit l'ouvrir et appuyer sur « Démarrer » pour recevoir les photos.")
            else:
                reply = f"{who} était déjà gestionnaire."
            tg_send(chat_id, reply, markup={"remove_keyboard": True})
        return
    if chat_id in admins and text.lower() == "annuler":
        tg_send(chat_id, "OK, rien n'a été changé.", markup={"remove_keyboard": True})
        return

    # Gestionnaires : enregistrement par code gestionnaire, puis commandes d'administration
    if text.lower().startswith("/admin"):
        parts = text.split(maxsplit=1)
        tg_admin_register(chat_id, name, parts[1].strip() if len(parts) > 1 else "")
        return
    if chat_id in admins and text.startswith("/") and tg_admin_command(chat_id, text):
        return

    # Enregistrement par code d'acces
    if text.lower().startswith("/code") or text.lower().startswith("/start"):
        parts = text.split(maxsplit=1)
        code = parts[1].strip() if len(parts) > 1 else ""
        if TELEGRAM_CODE and code == TELEGRAM_CODE:
            allowed[chat_id] = {"name": name, "since": int(time.time()), "count": allowed.get(chat_id, {}).get("count", 0)}
            tg_save_allowed(allowed)
            tg_send(chat_id, f"Bienvenue {name} ! Tu peux maintenant envoyer tes photos, elles s'afficheront sur le cadre. 📷")
        else:
            tg_send(chat_id, "🔒 Pour envoyer des photos au cadre, enregistre-toi avec le code d'accès :\n/code TONCODE")
        return

    # Expediteur non autorise (les gestionnaires peuvent aussi envoyer des photos)
    if chat_id not in allowed and chat_id not in admins:
        tg_send(chat_id, "🔒 Tu n'es pas encore autorisé. Demande le code à un gestionnaire puis envoie :\n/code TONCODE")
        return

    # Photo (compressee) ou image envoyee en fichier
    file_id, saved = None, 0
    if msg.get("photo"):
        file_id = msg["photo"][-1]["file_id"]          # plus grande resolution
    elif msg.get("document") and (msg["document"].get("mime_type", "").startswith("image/")):
        file_id = msg["document"]["file_id"]
    if file_id:
        try:
            prefix = secure_filename(name)[:20] or "proche"
            out = tg_download(file_id, prefix)
            if out and out.suffix.lower() in EXTS:
                generate_thumbnail(out)
                meta_update(out.name, {"source": "telegram", "sender": name, "received": int(time.time()),
                                       "caption": (msg.get("caption") or "").strip()})
                saved = 1
        except Exception as e:
            print(f"Telegram download error: {e}", flush=True)
            tg_send(chat_id, "⚠️ La photo n'a pas pu être reçue en entier. Renvoie-la stp.")

    if saved:
        if chat_id in allowed:
            allowed[chat_id]["count"] = allowed[chat_id].get("count", 0) + 1
            allowed[chat_id]["last"] = int(time.time())
            tg_save_allowed(allowed)
        request_refresh()                              # debounce : une seule relance feh par rafale
        notify_admins(out, exclude=chat_id)
        cap = (msg.get("caption") or "").strip()
        tg_send(chat_id, "✅ Photo reçue, merci !" + (f'\n« {cap} »' if cap else ""))
    elif text:
        tg_send(chat_id, ADMIN_HELP if chat_id in admins else "👋 Envoie-moi une photo et elle s'affichera sur le cadre !")


def telegram_loop():
    global _tg_offset
    while True:
        if not (TELEGRAM_ENABLED and TELEGRAM_TOKEN):
            time.sleep(5)
            continue
        try:
            resp = tg_api("getUpdates", {
                "offset": _tg_offset, "timeout": 30,
                "allowed_updates": json.dumps(["message", "channel_post", "callback_query"]),
            }, timeout=40)
            if not resp.get("ok"):
                time.sleep(5)
                continue
            for upd in resp["result"]:
                _tg_offset = upd["update_id"] + 1
                try:
                    if upd.get("callback_query"):
                        handle_tg_callback(upd["callback_query"])
                    else:
                        handle_tg_update(upd)
                except Exception as e:
                    print(f"Telegram handle error: {e}", flush=True)
        except Exception as e:
            print(f"Telegram poll error: {e}", flush=True)
            time.sleep(5)


def get_throttled():
    try:
        out = subprocess.run(["vcgencmd", "get_throttled"], capture_output=True, text=True, timeout=3)
        val = int(out.stdout.strip().split("=")[1], 16)
    except Exception:
        return {"available": False}
    return {
        "available": True,
        "undervoltage_now": bool(val & 0x1),
        "freq_capped_now": bool(val & 0x2),
        "throttled_now": bool(val & 0x4),
        "undervoltage_occurred": bool(val & 0x10000),
        "freq_capped_occurred": bool(val & 0x20000),
        "throttled_occurred": bool(val & 0x40000),
    }


def get_temp():
    try:
        out = subprocess.run(["vcgencmd", "measure_temp"], capture_output=True, text=True, timeout=3)
        return out.stdout.strip().split("=")[1].replace("'C", "C")
    except Exception:
        return "N/A"


def get_network():
    result = {"internet": False, "interfaces": []}
    try:
        s = socket.create_connection(("8.8.8.8", 53), timeout=2)
        s.close()
        result["internet"] = True
    except Exception:
        result["internet"] = False
    try:
        out = subprocess.run(["ip", "-brief", "addr"], capture_output=True, text=True, timeout=3)
        for line in out.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] != "lo":
                result["interfaces"].append({"name": parts[0], "state": parts[1], "addr": parts[2]})
    except Exception:
        pass
    return result


def get_disk():
    total, used, free = shutil.disk_usage(PHOTO_DIR)
    return {"total_gb": round(total/2**30, 1), "used_gb": round(used/2**30, 1), "free_gb": round(free/2**30, 1)}


def get_uptime():
    try:
        with open("/proc/uptime") as f:
            return int(float(f.readline().split()[0]))
    except Exception:
        return None


def get_meminfo():
    try:
        info = {}
        for line in open("/proc/meminfo"):
            k, _, v = line.partition(":")
            info[k.strip()] = v.strip()
        total = int(info["MemTotal"].split()[0])
        avail = int(info.get("MemAvailable", info["MemFree"]).split()[0])
        return {"total_mb": round(total/1024), "used_mb": round((total-avail)/1024)}
    except Exception:
        return {"total_mb": 0, "used_mb": 0}


def journal(extra, lines=150):
    try:
        out = subprocess.run(
            ["journalctl", "--no-pager", "-o", "short-iso", "-n", str(lines)] + extra,
            capture_output=True, text=True, timeout=6)
        txt = (out.stdout or "").strip()
        return txt if txt else "(aucune entree)"
    except Exception as e:
        return f"(erreur lecture journal: {e})"


# ------------------------- Auth : login / logout -------------------------
@app.route("/login", methods=["GET"])
def login_page():
    if session.get("auth") or not WEB_AUTH:
        return redirect("/")
    return LOGIN_HTML.replace("__ERR__", "")


@app.route("/login", methods=["POST"])
def login_submit():
    if not WEB_AUTH:
        return redirect("/")
    user = request.form.get("user", "")
    pw = request.form.get("pass", "")
    remember = request.form.get("remember") == "1"
    if _check_login(user, pw):
        session.clear()
        session["auth"] = True
        session["csrf"] = secrets.token_urlsafe(32)
        session.permanent = remember
        return redirect("/")
    print(f"[AUTH] login FAILED user={user!r} from {_client_ip()}", flush=True)
    return LOGIN_HTML.replace("__ERR__", "Identifiant ou mot de passe incorrect."), 401


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login" if WEB_AUTH else "/")


# ------------------------- Pages / API -------------------------
@app.route("/")
@requires_auth
def index():
    return (DASHBOARD_HTML.replace("__CSRF__", session.get("csrf", ""))
            .replace("__AUTHCLS__", "" if WEB_AUTH else "noauth"))


@app.route("/api/status")
@requires_auth
def api_status():
    return jsonify({
        "throttled": get_throttled(),
        "temp": get_temp(),
        "network": get_network(),
        "disk": get_disk(),
        "uptime": get_uptime(),
        "photo_count": len(get_photos_sorted()),
        "viewer_running": viewer_proc is not None and viewer_proc.poll() is None,
        "mail_configured": bool(EMAIL and PASSWORD),
        "mail_enabled": MAIL_ENABLED,
    })


@app.route("/api/photos")
@requires_auth
def api_photos():
    photos = []
    meta = meta_load()
    for p in get_photos_sorted():
        thumb = THUMB_DIR / f"{p.stem}.jpg"
        if not thumb.exists():
            generate_thumbnail(p)
        info = photo_info(p, meta)
        photos.append({
            "name": p.name,
            "thumb": f"{p.stem}.jpg" if thumb.exists() else None,
            "size_kb": round(p.stat().st_size / 1024, 1),
            "mtime": int(p.stat().st_mtime),
            "source": info["source"],
            "sender": info.get("sender") or "",
            "received": info["received"],
            "caption": info.get("caption") or "",
        })
    return jsonify(photos)


@app.route("/thumbnails/<path:filename>")
@requires_auth
def thumbnails(filename):
    path = safe_path(THUMB_DIR, filename)
    if not path:
        return "Not found", 404
    return send_from_directory(THUMB_DIR, path.name)


@app.route("/photos/<path:filename>")
@requires_auth
def photos_full(filename):
    path = safe_path(PHOTO_DIR, filename)
    if not path:
        return "Not found", 404
    return send_from_directory(PHOTO_DIR, path.name)


@app.route("/api/photos/upload", methods=["POST"])
@requires_auth
def upload():
    files = request.files.getlist("photos")
    saved = 0
    for f in files:
        if not f.filename:
            continue
        fn = secure_filename(f.filename)
        if not fn or Path(fn).suffix.lower() not in EXTS:
            continue
        ts = int(time.time() * 1000)
        path = PHOTO_DIR / f"{ts}_{fn}"
        f.save(path)
        generate_thumbnail(path)
        meta_update(path.name, {"source": "site", "received": int(time.time())})
        saved += 1
    if saved:
        request_refresh()
    return jsonify({"saved": saved})


@app.route("/api/photos/delete", methods=["POST"])
@requires_auth
def delete():
    body = request.get_json(silent=True) or {}
    names = body.get("filenames", [])
    deleted = 0
    for name in names:
        path = safe_path(PHOTO_DIR, name)
        if path:
            delete_photo(path)
            deleted += 1
    if deleted:
        request_refresh()
    return jsonify({"deleted": deleted})


@app.route("/api/viewer/restart", methods=["POST"])
@requires_auth
def viewer_restart():
    refresh_viewer()
    return jsonify({"ok": True})


@app.route("/api/mail/fetch", methods=["POST"])
@requires_auth
def mail_fetch_now():
    if not (EMAIL and PASSWORD):
        return jsonify({"error": "mail non configure"}), 400
    new = fetch_photos()
    if new:
        request_refresh()
    return jsonify({"new": new})


# ------------------------- Onglet LOGS -------------------------
@app.route("/api/logs")
@requires_auth
def api_logs():
    src = request.args.get("source", "app")
    if src == "wifi":
        return jsonify({"text": journal(["-t", "wifi-watchdog"], 150)})
    if src == "app":
        return jsonify({"text": journal(["-u", "photoframe.service"], 150)})
    if src == "errors":
        return jsonify({"text": journal(
            ["-u", "photoframe.service", "--grep",
             "error|erreur|exception|traceback|failed|critical|refus|denied"], 200)})
    if src == "system":
        return jsonify({
            "throttled": get_throttled(),
            "temp": get_temp(),
            "uptime": get_uptime(),
            "mem": get_meminfo(),
            "disk": get_disk(),
            "voltage_log": journal(["-k", "--grep", "voltage"], 30),
        })
    return jsonify({"error": "source inconnue"}), 400


@app.route("/api/senders")
@requires_auth
def api_senders():
    return jsonify(get_senders())


# ------------------------- Onglet REGLAGES -------------------------
@app.route("/api/settings")
@requires_auth
def get_settings():
    return jsonify({
        "slide_delay": SLIDE_DELAY,
        "slide_order": SLIDE_ORDER,
        "display_mode": DISPLAY_MODE,
        "check_interval": CHECK_INTERVAL,
        "mail_enabled": MAIL_ENABLED,
        "mail_configured": bool(EMAIL and PASSWORD),
        "web_user": WEB_USER,
        "telegram_enabled": TELEGRAM_ENABLED,
        "admin_notify": ADMIN_NOTIFY,
        "telegram_configured": bool(TELEGRAM_TOKEN),
        "telegram_code": TELEGRAM_CODE,
        "telegram_admin_codes": ", ".join(TELEGRAM_ADMIN_CODES),
    })


@app.route("/api/settings", methods=["POST"])
@requires_auth
def set_settings():
    global SLIDE_DELAY, SLIDE_ORDER, CHECK_INTERVAL, MAIL_ENABLED, WEB_USER, WEB_PASS_HASH, DISPLAY_MODE
    global TELEGRAM_TOKEN, TELEGRAM_CODE, TELEGRAM_ENABLED, TELEGRAM_ADMIN_CODES, ADMIN_NOTIFY
    body = request.get_json(silent=True) or {}
    env_updates = {}
    viewer_dirty = False
    changed = []

    if "slide_delay" in body:
        try:
            d = int(body["slide_delay"])
            if 1 <= d <= 600:
                SLIDE_DELAY = str(d); env_updates["SLIDE_DELAY"] = SLIDE_DELAY
                viewer_dirty = True; changed.append("delai")
        except Exception:
            pass
    if body.get("slide_order") in ("recent", "random"):
        SLIDE_ORDER = body["slide_order"]; env_updates["SLIDE_ORDER"] = SLIDE_ORDER
        viewer_dirty = True; changed.append("ordre")
    if body.get("display_mode") in DISPLAY_MODES and body["display_mode"] != DISPLAY_MODE:
        DISPLAY_MODE = body["display_mode"]; env_updates["DISPLAY_MODE"] = DISPLAY_MODE
        viewer_dirty = True; changed.append("cadrage")    # sync_displays reprepare tout
    if "check_interval" in body:
        try:
            c = int(body["check_interval"])
            if 10 <= c <= 86400:
                CHECK_INTERVAL = c; env_updates["CHECK_INTERVAL"] = str(c); changed.append("intervalle")
        except Exception:
            pass
    if "mail_enabled" in body:
        MAIL_ENABLED = bool(body["mail_enabled"])
        env_updates["MAIL_ENABLED"] = "1" if MAIL_ENABLED else "0"; changed.append("mail")
    if body.get("web_user"):
        WEB_USER = str(body["web_user"]).strip(); env_updates["WEB_USER"] = WEB_USER; changed.append("identifiant")
    if body.get("web_pass"):
        WEB_PASS_HASH = generate_password_hash(str(body["web_pass"]))
        env_updates["WEB_PASS_HASH"] = WEB_PASS_HASH; changed.append("mot de passe")
    if "telegram_token" in body:
        TELEGRAM_TOKEN = str(body["telegram_token"]).strip()
        env_updates["TELEGRAM_TOKEN"] = TELEGRAM_TOKEN; changed.append("token telegram")
    if "telegram_code" in body:
        TELEGRAM_CODE = str(body["telegram_code"]).strip()
        env_updates["TELEGRAM_CODE"] = TELEGRAM_CODE; changed.append("code telegram")
    if "telegram_admin_codes" in body:
        codes = str(body["telegram_admin_codes"]).replace(";", ",").split(",")
        TELEGRAM_ADMIN_CODES = [c.strip() for c in codes if c.strip()]
        env_updates["TELEGRAM_ADMIN_CODES"] = ",".join(TELEGRAM_ADMIN_CODES); changed.append("codes gestionnaires")
    if "telegram_enabled" in body:
        TELEGRAM_ENABLED = bool(body["telegram_enabled"])
        env_updates["TELEGRAM_ENABLED"] = "1" if TELEGRAM_ENABLED else "0"; changed.append("telegram")
    if "admin_notify" in body:
        ADMIN_NOTIFY = bool(body["admin_notify"])
        env_updates["ADMIN_NOTIFY"] = "1" if ADMIN_NOTIFY else "0"; changed.append("envoi aux gestionnaires")

    if env_updates:
        update_env(env_updates)
    if viewer_dirty:
        request_refresh()
    return jsonify({"ok": True, "changed": changed})


@app.route("/api/telegram/status")
@requires_auth
def telegram_status():
    allowed = tg_load_allowed()
    out = {"configured": bool(TELEGRAM_TOKEN), "enabled": TELEGRAM_ENABLED,
           "allowed_count": len(allowed), "admin_count": len(tg_load_admins()), "bot": None, "ok": False}
    if TELEGRAM_TOKEN:
        try:
            me = tg_api("getMe", timeout=10)
            if me.get("ok"):
                out["ok"] = True
                out["bot"] = me["result"].get("username")
        except Exception as e:
            out["error"] = str(e)
    return jsonify(out)


@app.route("/api/telegram/senders")
@requires_auth
def telegram_senders():
    allowed = tg_load_allowed()
    admins = tg_load_admins()
    senders = [{"chat_id": k, "name": v.get("name", ""), "since": v.get("since", 0),
                "count": v.get("count", 0), "last": v.get("last", 0), "is_admin": k in admins}
               for k, v in allowed.items()]
    senders.sort(key=lambda x: (x["count"], x["last"]), reverse=True)
    return jsonify({"senders": senders})


@app.route("/api/telegram/revoke", methods=["POST"])
@requires_auth
def telegram_revoke():
    body = request.get_json(silent=True) or {}
    cid = str(body.get("chat_id", ""))
    allowed = tg_load_allowed()
    if cid in allowed:
        del allowed[cid]
        tg_save_allowed(allowed)
        return jsonify({"ok": True})
    return jsonify({"ok": False}), 404


@app.route("/api/telegram/admins")
@requires_auth
def telegram_admins():
    admins = [{"chat_id": k, "name": v.get("name", ""), "since": v.get("since", 0), "owner": bool(v.get("owner"))}
              for k, v in tg_load_admins().items()]
    admins.sort(key=lambda x: x["since"])
    return jsonify({"admins": admins})


@app.route("/api/telegram/admins/revoke", methods=["POST"])
@requires_auth
def telegram_admin_revoke():
    body = request.get_json(silent=True) or {}
    cid = str(body.get("chat_id", ""))
    if cid == TELEGRAM_OWNER_ID:
        return jsonify({"ok": False, "error": "le responsable du cadre ne peut pas être retiré"}), 403
    if not tg_remove_admin(cid, "le site web"):
        return jsonify({"ok": False}), 404
    tg_send(cid, "🔒 Tu ne gères plus le cadre photo.")
    return jsonify({"ok": True})


@app.route("/api/telegram/admins/add", methods=["POST"])
@requires_auth
def telegram_admin_add():
    """Nomme gestionnaire une personne qui a deja ecrit au bot (liste des expediteurs)."""
    body = request.get_json(silent=True) or {}
    cid = str(body.get("chat_id", ""))
    known = tg_load_allowed().get(cid)
    if not known:
        return jsonify({"ok": False, "error": "personne inconnue du bot"}), 404
    return jsonify({"ok": tg_add_admin(cid, known.get("name") or cid, "le site web")})


# ------------------------- Onglet SYSTEME -------------------------
@app.route("/api/system/restart-service", methods=["POST"])
@requires_auth
def restart_service():
    subprocess.Popen(["sudo", "-n", "systemctl", "restart", "photoframe"],
                     start_new_session=True)
    return jsonify({"ok": True})


@app.route("/api/system/reboot", methods=["POST"])
@requires_auth
def system_reboot():
    subprocess.Popen(["sudo", "-n", "reboot"], start_new_session=True)
    return jsonify({"ok": True})


LOGIN_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhotoFrame - Connexion</title>
<style>
:root{--bg:#0b0e14;--bg2:#0f1320;--card:#151a26;--accent:#5b8cff;--accent2:#9d6bff;--txt:#e8ebf2;--muted:#8b93a7;--line:#232a3a;--danger:#ff5d63;--ok:#37d39b}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--txt);
  background:radial-gradient(1200px 700px at 15% -10%,rgba(91,140,255,.18),transparent 60%),
             radial-gradient(1100px 700px at 110% 110%,rgba(157,107,255,.16),transparent 55%),var(--bg);
  display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:400px;background:linear-gradient(180deg,rgba(255,255,255,.03),rgba(255,255,255,0));
  border:1px solid var(--line);border-radius:18px;padding:34px 30px;box-shadow:0 30px 80px -30px rgba(0,0,0,.8)}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:6px}
.logo{width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,var(--accent),var(--accent2));
  display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 8px 24px -6px rgba(91,140,255,.6)}
.brand h1{font-size:20px;margin:0;font-weight:700;letter-spacing:.2px}
.sub{color:var(--muted);font-size:13px;margin:2px 0 24px}
label{display:block;font-size:12px;color:var(--muted);margin:14px 0 6px;text-transform:uppercase;letter-spacing:.05em}
input[type=text],input[type=password]{width:100%;background:#0c101a;border:1px solid #26304a;color:var(--txt);
  border-radius:10px;padding:12px 14px;font-size:14px;outline:none;transition:border .15s,box-shadow .15s}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(91,140,255,.18)}
.pwwrap{position:relative}
.pwwrap input{padding-right:46px}
.eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:auto;margin:0;padding:6px 8px;background:none;border:none;box-shadow:none;font-size:18px;line-height:1;cursor:pointer;opacity:.7}
.eye:hover{opacity:1}
.row{display:flex;align-items:center;gap:8px;margin:16px 0 4px;font-size:13px;color:var(--muted)}
.row input{width:16px;height:16px;accent-color:var(--accent)}
button{width:100%;margin-top:20px;padding:12px;border:none;border-radius:10px;cursor:pointer;font-size:15px;font-weight:600;
  color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2));transition:transform .08s,filter .15s}
button:hover{filter:brightness(1.08)} button:active{transform:translateY(1px)}
.err{background:rgba(255,93,99,.12);border:1px solid rgba(255,93,99,.4);color:#ffb4b7;
  border-radius:10px;padding:10px 12px;font-size:13px;margin-top:16px}
.err:empty{display:none}
.foot{text-align:center;color:var(--muted);font-size:11px;margin-top:22px}
</style>
</head>
<body>
<form class="card" method="POST" action="/login">
  <div class="brand">
    <div class="logo">🖼️</div>
    <h1>PhotoFrame</h1>
  </div>
  <div class="sub">Cadre photo connecté &middot; espace d'administration</div>
  <div class="err">__ERR__</div>
  <label for="user">Identifiant</label>
  <input type="text" id="user" name="user" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" autofocus required>
  <label for="pass">Mot de passe</label>
  <div class="pwwrap">
    <input type="password" id="pass" name="pass" autocomplete="current-password" autocapitalize="none" autocorrect="off" spellcheck="false" required>
    <button type="button" class="eye" onclick="togglePw()" aria-label="Afficher ou masquer le mot de passe">&#128065;</button>
  </div>
  <div class="row"><input type="checkbox" id="remember" name="remember" value="1"><label for="remember" style="margin:0;text-transform:none;letter-spacing:0;font-size:13px">Rester connecté 30 jours</label></div>
  <button type="submit">Se connecter</button>
  <div class="foot">Connexion sécurisée (HTTPS) &middot; tentatives limitées</div>
</form>
<script>
function togglePw(){
  var p = document.getElementById('pass');
  var e = document.querySelector('.eye');
  var show = p.type === 'password';
  p.type = show ? 'text' : 'password';
  e.innerHTML = show ? '&#128584;' : '&#128065;';
}
</script>
</body>
</html>
"""


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhotoFrame</title>
<style>
:root{--bg:#0b0e14;--card:#151a26;--card2:#0f1320;--accent:#5b8cff;--accent2:#9d6bff;--danger:#ff5d63;--ok:#37d39b;--warn:#f7b955;--txt:#e8ebf2;--muted:#8b93a7;--line:#232a3a}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:
  radial-gradient(1000px 500px at 100% -5%,rgba(91,140,255,.10),transparent 60%),var(--bg);color:var(--txt)}
a{color:var(--accent)}
header{position:sticky;top:0;z-index:20;padding:14px 22px;display:flex;justify-content:space-between;align-items:center;
  border-bottom:1px solid var(--line);background:rgba(11,14,20,.85);backdrop-filter:blur(10px)}
.brand{display:flex;align-items:center;gap:11px}
.logo{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accent2));
  display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 6px 18px -6px rgba(91,140,255,.6)}
.brand h1{font-size:17px;margin:0;font-weight:700;letter-spacing:.2px}
.hright{display:flex;align-items:center;gap:14px}
.conn{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted)}
.dot{width:9px;height:9px;border-radius:50%;background:var(--muted);display:inline-block}
.dot.on{background:var(--ok);box-shadow:0 0 8px var(--ok)} .dot.off{background:var(--danger)}
.logout{font-size:13px;color:var(--muted);text-decoration:none;border:1px solid var(--line);padding:7px 12px;border-radius:8px;transition:.15s}
.logout:hover{color:var(--txt);border-color:#33405e}
.noauth .auth-only{display:none}
.tabs{display:flex;gap:4px;padding:12px 18px 0;border-bottom:1px solid var(--line);flex-wrap:wrap;position:sticky;top:63px;z-index:15;background:rgba(11,14,20,.85);backdrop-filter:blur(10px)}
.tab{background:none;border:none;color:var(--muted);padding:11px 16px;cursor:pointer;font-size:14px;border-radius:9px 9px 0 0;border-bottom:2px solid transparent;transition:.15s}
.tab:hover{color:var(--txt)} .tab.active{color:var(--txt);border-bottom-color:var(--accent);background:var(--card)}
.page{display:none;animation:fade .25s ease} .page.active{display:block}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.intro{margin:18px 22px 2px;font-size:22px;font-weight:700}
.intro .sub{display:block;font-size:13px;font-weight:400;color:var(--muted);margin-top:3px}
.status-bar{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px;padding:16px 22px}
.stat{background:linear-gradient(180deg,rgba(255,255,255,.025),transparent);border:1px solid var(--line);border-radius:13px;padding:14px 16px}
.stat .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.stat .value{font-size:17px;margin-top:5px;font-weight:600}
.ok{color:var(--ok)} .warn{color:var(--warn)} .bad{color:var(--danger)}
.toolbar{display:flex;gap:10px;padding:4px 22px 16px;flex-wrap:wrap;align-items:center}
button.act,.dropzone{background:var(--card);color:var(--txt);border:1px solid #2a3247;border-radius:9px;padding:9px 15px;cursor:pointer;font-size:13px;transition:.15s}
button.act:hover{border-color:#3a4668;background:#1a2132}
button.primary{background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;color:#fff}
button.primary:hover{filter:brightness(1.08)}
/* Meme gabarit que button.act (rayon, police, transition) mais plus haut et plus
   large : c'est une action destructive, elle doit etre facile a viser. */
button.danger{background:var(--danger);color:#fff;border:1px solid transparent;border-radius:9px;
  padding:11px 18px;min-height:40px;font-size:13px;font-weight:600;cursor:pointer;transition:.15s}
button.danger:hover:not(:disabled){filter:brightness(1.1)}
button.danger:active:not(:disabled){transform:translateY(1px)}
button:disabled{opacity:.45;cursor:not-allowed;filter:none}
.dropzone{border:2px dashed #2a3247;color:var(--muted)}
.dropzone.drag{border-color:var(--accent);color:var(--accent)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(158px,1fr));gap:12px;padding:0 22px 34px}
.photo{position:relative;background:var(--card);border-radius:12px;overflow:hidden;aspect-ratio:1/1;border:1px solid var(--line)}
.photo img{width:100%;height:100%;object-fit:cover;display:block;cursor:pointer;transition:transform .3s}
.photo:hover img{transform:scale(1.05)}
.photo input{position:absolute;top:8px;left:8px;width:18px;height:18px;accent-color:var(--accent);z-index:2}
.photo .name{position:absolute;bottom:0;left:0;right:0;font-size:11px;padding:5px 7px;background:linear-gradient(transparent,rgba(0,0,0,.85));white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer}
#msg{padding:0 22px;color:var(--muted);font-size:13px;min-height:18px}
.logtabs{display:flex;gap:8px;padding:16px 22px 8px;flex-wrap:wrap}
.logtab{font-size:13px} .logtab.active{background:var(--accent);border-color:var(--accent);color:#fff}
pre.log{margin:0 22px 24px;background:#080b12;border:1px solid var(--line);border-radius:12px;padding:15px;
  font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.55;color:#c2cbdb;
  max-height:60vh;overflow:auto;white-space:pre-wrap;word-break:break-word}
.syswrap{padding:0 22px 24px}
.settings{padding:18px 22px 44px;max-width:680px}
.section{background:linear-gradient(180deg,rgba(255,255,255,.02),transparent);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin-bottom:16px}
.section h3{margin:0 0 14px;font-size:15px;display:flex;align-items:center;gap:8px}
.field{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:9px 0;flex-wrap:wrap}
.field label{font-size:13px;color:var(--muted)}
.field .ctl{display:flex;align-items:center;gap:8px}
input[type=text],input[type=password],input[type=number],select{background:#0c101a;border:1px solid #26304a;color:var(--txt);border-radius:8px;padding:8px 11px;font-size:13px;outline:none}
input:focus,select:focus{border-color:var(--accent)}
input[type=range]{accent-color:var(--accent)}
.switch{position:relative;width:44px;height:24px}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;inset:0;background:#2a3247;border-radius:24px;transition:.2s;cursor:pointer}
.slider:before{content:"";position:absolute;height:18px;width:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}
.switch input:checked+.slider{background:var(--ok)} .switch input:checked+.slider:before{transform:translateX(20px)}
.hint{font-size:11px;color:var(--muted);margin-top:2px}
.saved{color:var(--ok);font-size:12px;margin-left:8px}
.sndtbl{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}
.sndtbl th,.sndtbl td{text-align:left;padding:8px;border-bottom:1px solid var(--line)}
.sndtbl th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.sndtbl td.num{text-align:center;font-weight:600}
.sndtbl tbody tr:hover{background:#0e1320}
.sndtbl .em{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--accent)}
</style>
</head>
<body class="__AUTHCLS__">
<header>
  <div class="brand"><div class="logo">🖼️</div><h1>PhotoFrame</h1></div>
  <div class="hright">
    <span class="conn"><span id="conn" class="dot"></span> <span id="connTxt">...</span></span>
    <a class="logout auth-only" href="/logout">Déconnexion</a>
  </div>
</header>

<div class="tabs">
  <button class="tab active" data-page="home" onclick="showTab('home')">Accueil</button>
  <button class="tab" data-page="logs" onclick="showTab('logs')">Logs</button>
  <button class="tab" data-page="mail" onclick="showTab('mail')">Mail &amp; Erreurs</button>
  <button class="tab" data-page="settings" onclick="showTab('settings')">Réglages</button>
</div>

<!-- ACCUEIL -->
<section id="home" class="page active">
  <div class="intro">Tableau de bord<span class="sub" id="introSub">Cadre photo connecté</span></div>
  <div class="status-bar" id="status"></div>
  <div class="toolbar">
    <label class="dropzone" id="drop">Glisser des photos ou cliquer
      <input type="file" id="fileInput" accept=".jpg,.jpeg,.png,.bmp,.gif" multiple style="display:none">
    </label>
    <select id="senderFilter" title="Afficher les photos d'un seul expéditeur" onchange="loadPhotos()">
      <option value="">Toutes les photos</option>
    </select>
    <button class="act" onclick="toggleAll()">Tout sélectionner</button>
    <button class="act" id="deselBtn" onclick="deselectAll()" disabled>Tout désélectionner</button>
    <button class="danger" id="delBtn" onclick="deleteSelected()" disabled>Supprimer la sélection</button>
    <button class="act" onclick="restartViewer()">Redémarrer le diaporama</button>
  </div>
  <div id="msg"></div>
  <div class="grid" id="grid"></div>
</section>

<!-- LOGS -->
<section id="logs" class="page">
  <div class="logtabs">
    <button class="act logtab active" data-src="wifi" onclick="showLog('wifi')">Reconnexions WiFi</button>
    <button class="act logtab" data-src="app" onclick="showLog('app')">Appli</button>
    <button class="act logtab" data-src="system" onclick="showLog('system')">Système</button>
    <button class="act" onclick="loadLog()" style="margin-left:auto">Rafraîchir</button>
  </div>
  <pre class="log" id="logtext">Chargement...</pre>
  <div class="syswrap" id="sysbox" style="display:none"></div>
</section>

<!-- MAIL & ERREURS -->
<section id="mail" class="page">
  <div class="settings" style="max-width:880px">
    <div class="section">
      <h3>&#9888;&#65039; Journal d'erreurs
        <button class="act" onclick="loadErrors()" style="margin-left:auto;font-size:12px;padding:5px 10px">Rafraîchir</button>
      </h3>
      <pre class="log" id="errtext" style="margin:0;max-height:38vh">Chargement...</pre>
    </div>
    <div class="section">
      <h3>&#128233; Expéditeurs
        <button class="act" onclick="loadSenders()" style="margin-left:auto;font-size:12px;padding:5px 10px">Rafraîchir</button>
      </h3>
      <div class="hint">Toutes les adresses mail qui ont écrit à la boîte du cadre.
        La boîte est relevée automatiquement toutes les <span id="mailEvery">60</span> s :
        rien à déclencher à la main.</div>
      <div id="senders" style="margin-top:8px">Chargement...</div>
    </div>
  </div>
</section>

<!-- REGLAGES -->
<section id="settings" class="page">
  <div class="settings">
    <div class="section">
      <h3>Diaporama</h3>
      <div class="field">
        <label>Délai par photo <span id="delayVal"></span></label>
        <div class="ctl"><input type="range" id="slideDelay" min="2" max="60" step="1" oninput="delayVal.textContent=this.value+' s'"></div>
      </div>
      <div class="field">
        <label>Ordre d'affichage</label>
        <div class="ctl">
          <select id="slideOrder">
            <option value="recent">Plus récentes d'abord</option>
            <option value="random">Aléatoire</option>
          </select>
        </div>
      </div>
      <div class="field">
        <label>Cadrage des photos</label>
        <div class="ctl">
          <select id="displayMode">
            <option value="mixte">Mixte : recadré (paysage) / fond flou (portrait)</option>
            <option value="flou">Fond flou (photo entière)</option>
            <option value="recadre">Recadré plein écran</option>
            <option value="bandes">Bandes noires</option>
          </select>
        </div>
      </div>
      <div class="hint">Changer le cadrage prépare à nouveau toutes les photos (~2 s par photo) : le cadre se met à jour progressivement.</div>
      <button class="primary" onclick="saveSettings(['slide_delay','slide_order','display_mode'], this)">Enregistrer</button>
    </div>

    <div class="section">
      <h3>Mail Gmail</h3>
      <div class="field">
        <label>Récupération automatique</label>
        <div class="ctl"><span id="mailState" class="hint"></span>
          <label class="switch"><input type="checkbox" id="mailEnabled"><span class="slider"></span></label>
        </div>
      </div>
      <div class="field">
        <label>Intervalle de vérification</label>
        <div class="ctl"><input type="number" id="checkInterval" min="10" max="3600" style="width:90px"> <span class="hint">secondes</span></div>
      </div>
      <button class="primary" onclick="saveSettings(['mail_enabled','check_interval'], this)">Enregistrer</button>
    </div>

    <div class="section">
      <h3>&#128241; Telegram (photos des proches)</h3>
      <div class="field">
        <label>État du bot</label>
        <div class="ctl"><span id="tgStatus" class="hint">...</span></div>
      </div>
      <div class="field">
        <label>Réception activée</label>
        <div class="ctl"><label class="switch"><input type="checkbox" id="tgEnabled"><span class="slider"></span></label></div>
      </div>
      <div class="field">
        <label>Token du bot (BotFather)</label>
        <div class="ctl"><input type="password" id="tgToken" placeholder="laisser vide = inchangé" style="width:200px" autocomplete="off"></div>
      </div>
      <div class="field">
        <label>Code d'accès (à donner aux proches)</label>
        <div class="ctl"><input type="text" id="tgCode" placeholder="ex: MONCODE" style="width:160px"></div>
      </div>
      <div class="field">
        <label>Codes gestionnaires à usage unique (un par personne, séparés par des virgules)</label>
        <div class="ctl"><input type="text" id="tgAdminCodes" placeholder="ex : CODE1, CODE2" style="width:240px" autocomplete="off"></div>
      </div>
      <div class="field">
        <label>Envoyer chaque nouvelle photo aux gestionnaires (sinon : /photos à la demande)</label>
        <div class="ctl"><label class="switch"><input type="checkbox" id="adminNotify"><span class="slider"></span></label></div>
      </div>
      <button class="primary" onclick="saveTelegram(this)">Enregistrer</button>
      <div class="hint" style="margin-top:12px">Expéditeurs autorisés <button class="act" onclick="loadTgSenders()" style="font-size:11px;padding:3px 8px;margin-left:6px">Rafraîchir</button></div>
      <div id="tgSenders" style="margin-top:6px">-</div>
      <div class="hint" style="margin-top:14px">Gestionnaires : chacun s'inscrit en envoyant au bot <b>/admin</b> suivi de son code (ex. <b>/admin MONCODE</b>) ; le code disparaît de la liste dès qu'il a servi. Un gestionnaire peut aussi en ajouter un autre avec /ajouter. Ils consultent les photos avec /photos (chacune avec un bouton Supprimer), et disposent aussi de /statut et /diaporama.
        <button class="act" onclick="loadTgAdmins()" style="font-size:11px;padding:3px 8px;margin-left:6px">Rafraîchir</button></div>
      <div id="tgAdmins" style="margin-top:6px">-</div>
    </div>

    <div class="section">
      <h3>Système</h3>
      <div class="field"><label>Relancer le diaporama (feh)</label>
        <button class="act" onclick="restartViewer()">Redémarrer</button></div>
      <div class="field"><label>Relancer le service web</label>
        <button class="act" onclick="sysAction('restart-service','Redémarrage du service...')">Redémarrer le service</button></div>
      <div class="field"><label>Redémarrer le Raspberry Pi</label>
        <button class="danger" onclick="if(confirm('Redémarrer le Pi maintenant ?'))sysAction('reboot','Redémarrage du Pi... (~1 min)')">Redémarrer le Pi</button></div>
    </div>

    <div class="section auth-only">
      <h3>Sécurité web</h3>
      <div class="field"><label>Identifiant</label>
        <div class="ctl"><input type="text" id="webUser" autocomplete="username"></div></div>
      <div class="field"><label>Nouveau mot de passe</label>
        <div class="ctl"><input type="password" id="webPass" placeholder="laisser vide = inchangé" autocomplete="new-password"></div></div>
      <div class="hint">Le mot de passe est stocké haché (jamais en clair). Après changement, tu devras te reconnecter.</div>
      <button class="primary" style="margin-top:10px" onclick="saveSecurity(this)">Mettre à jour</button>
    </div>
  </div>
</section>

<script>
const CSRF = "__CSRF__";
async function api(url, opts){
  opts = opts || {};
  if((opts.method||'GET').toUpperCase() !== 'GET') opts.headers = Object.assign({'X-CSRF':CSRF}, opts.headers||{});
  const r = await fetch(url, opts);
  if(r.status === 401){ location.href = '/login'; throw new Error('auth'); }
  return r.json();
}
function fmtBool(bad, okTxt, badTxt){ return bad ? `<span class="bad">${badTxt}</span>` : `<span class="ok">${okTxt}</span>`; }
function esc(s){ return (s||'').toString().replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function showTab(name){
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id===name));
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.page===name));
  if(name==='logs') loadLog();
  if(name==='mail') loadMailErrors();
  if(name==='settings') loadSettings();
}

function loadMailErrors(){ loadErrors(); loadSenders(); }
async function loadErrors(){
  const pre = document.getElementById('errtext');
  pre.textContent = 'Chargement...';
  const r = await api('/api/logs?source=errors');
  pre.textContent = (r.text && r.text !== '(aucune entree)') ? r.text : 'Aucune erreur enregistrée. 🎉';
  pre.scrollTop = pre.scrollHeight;
}
async function loadSenders(){
  const box = document.getElementById('senders');
  box.innerHTML = 'Lecture de la boîte mail...';
  const s = await api('/api/senders');
  if(!s.available){ box.innerHTML = `<span class="warn">${s.error ? esc(s.error) : 'Mail non configuré'}</span>`; return; }
  if(!s.senders.length){ box.innerHTML = '<span class="hint">Aucun message dans la boîte.</span>'; return; }
  const rows = s.senders.map(x => `<tr>
      <td class="em">${esc(x.email)}</td>
      <td>${esc(x.name || '')}</td>
      <td class="num">${x.count}</td>
      <td>${x.last ? new Date(x.last*1000).toLocaleDateString('fr-FR') : '-'}</td>
    </tr>`).join('');
  box.innerHTML = `<div class="hint" style="margin-bottom:8px">${s.senders.length} adresse(s) &middot; ${s.analyzed}/${s.total} message(s) analysés</div>
    <table class="sndtbl"><thead><tr><th>Adresse</th><th>Nom</th><th>Mails</th><th>Dernier</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

async function loadStatus(){
  const s = await api('/api/status');
  const t = s.throttled;
  const voltage = t.available ? fmtBool(t.undervoltage_now || t.undervoltage_occurred, 'OK', t.undervoltage_now ? 'ACTIVE' : 'Détectée') : 'N/A';
  const net = s.network;
  const iface = net.interfaces.map(i => `${i.name}:${i.state}`).join(' ') || 'aucune';
  document.getElementById('conn').className = 'dot ' + (net.internet ? 'on':'off');
  document.getElementById('connTxt').textContent = net.internet ? 'En ligne' : 'Hors ligne';
  document.getElementById('status').innerHTML = `
    <div class="stat"><div class="label">Alimentation</div><div class="value">${voltage} <span style="color:var(--muted)">${s.temp}</span></div></div>
    <div class="stat"><div class="label">Réseau</div><div class="value">${fmtBool(!net.internet,'Connecté','Hors ligne')}<br><span style="font-size:11px;color:var(--muted)">${iface}</span></div></div>
    <div class="stat"><div class="label">Diaporama</div><div class="value">${s.viewer_running ? '<span class="ok">Actif</span>' : '<span class="bad">Arrêté</span>'}</div></div>
    <div class="stat"><div class="label">Mail</div><div class="value">${s.mail_configured ? (s.mail_enabled?'<span class="ok">Actif</span>':'<span class="warn">En pause</span>') : '<span class="warn">Non configuré</span>'}</div></div>
    <div class="stat"><div class="label">Disque</div><div class="value">${s.disk.free_gb} Go libres</div></div>
    <div class="stat"><div class="label">Photos</div><div class="value">${s.photo_count}</div></div>
  `;
  document.getElementById('introSub').textContent = `${s.photo_count} photo(s) au mur`;
}

let anchorIdx = null;      // ancre pour la selection par plage (Shift+clic)
let lastPhotoKey = null;   // signature de la derniere liste de photos affichee

// Etiquette des vignettes : canal + expediteur + date de reception.
const SOURCE_ICONS = {telegram: '📱', mail: '✉️', site: '💻', inconnue: '📷'};
function photoWho(p){
  if(p.sender) return p.sender;
  return p.source === 'site' ? 'Ajout depuis le site' : p.source === 'mail' ? 'Mail' : 'Mail ou site';
}
function photoDate(p){
  const d = new Date(p.received * 1000), opt = {day: 'numeric', month: 'short'};
  if(d.getFullYear() !== new Date().getFullYear()) opt.year = 'numeric';
  return d.toLocaleDateString('fr-FR', opt);
}
// Remplit le filtre (expediteurs tries par nombre de photos) et renvoie le filtre
// effectif : retour a "toutes" si l'expediteur choisi n'a plus de photo.
function fillSenderFilter(all){
  const sel = document.getElementById('senderFilter');
  const counts = {};
  all.forEach(p => { const w = photoWho(p); counts[w] = (counts[w] || 0) + 1; });
  const cur = sel.value;
  const names = Object.keys(counts).sort((a, b) => counts[b] - counts[a] || a.localeCompare(b));
  sel.innerHTML = `<option value="">Toutes les photos (${all.length})</option>` +
    names.map(n => `<option value="${esc(n)}">${esc(n)} (${counts[n]})</option>`).join('');
  sel.value = counts[cur] ? cur : '';
  return sel.value;
}

async function loadPhotos(){
  const all = await api('/api/photos');
  const grid = document.getElementById('grid');
  const names = all.map(p => p.name).join('|');
  // Si ni la liste des photos ni le filtre n'ont change, on ne reconstruit pas la grille :
  // sinon le rafraichissement automatique (setInterval) effacerait les cases cochees.
  if(document.getElementById('senderFilter').value + '|' + names === lastPhotoKey && grid.children.length) return;
  // Le filtre n'affiche QUE les photos de l'expediteur choisi : "Tout selectionner" et
  // la suppression ne peuvent donc jamais toucher une photo cachee.
  const who = fillSenderFilter(all);
  const photos = who ? all.filter(p => photoWho(p) === who) : all;
  // La liste a change : on memorise la selection en cours pour la restaurer apres.
  const wasChecked = new Set([...grid.querySelectorAll('.sel:checked')].map(b => b.dataset.name));
  grid.innerHTML = photos.map(p => `
    <div class="photo">
      <input type="checkbox" class="sel" data-name="${esc(p.name)}">
      <img src="/thumbnails/${encodeURIComponent(p.thumb)}" loading="lazy" title="Clic = sélectionner · Double-clic = ouvrir · Ctrl/Shift = plusieurs">
      <div class="name" title="${p.caption ? '« ' + esc(p.caption) + ' » - ' : ''}Ouvrir la photo (${esc(p.name)})">${SOURCE_ICONS[p.source] || '📷'} ${esc(photoWho(p))} - ${photoDate(p)}</div>
    </div>
  `).join('');
  if(wasChecked.size) grid.querySelectorAll('.sel').forEach(b => { if(wasChecked.has(b.dataset.name)) b.checked = true; });
  lastPhotoKey = who + '|' + names;
  anchorIdx = null;
  syncDelBtn();
}

// Le bouton rouge annonce combien de photos partiront, et reste desactive tant
// que rien n'est coche (avant, le clic ne faisait rien sans rien expliquer).
function syncDelBtn(){
  const n = document.querySelectorAll('.sel:checked').length;
  const d = document.getElementById('deselBtn'); if(d) d.disabled = (n === 0);
  const b = document.getElementById('delBtn');
  if(!b) return;
  b.disabled = (n === 0);
  b.textContent = n ? `Supprimer la sélection (${n})` : 'Supprimer la sélection';
}

// Tout deselectionner : decoche toutes les cases et remet l'ancre a zero.
function deselectAll(){
  document.querySelectorAll('#grid .sel').forEach(b => b.checked = false);
  anchorIdx = null;
  syncDelBtn();
}

document.addEventListener('change', e => { if(e.target.classList.contains('sel')) syncDelBtn(); });

// Selection rapide facon explorateur Windows :
//  - clic simple n'importe ou sur la vignette = (de)selection de cette photo
//  - double-clic sur l'image                  = ouvrir la photo en grand
//  - clic simple sur le NOM du fichier        = ouvrir la photo en grand
//  - Ctrl/Cmd+clic                            = (de)selection individuelle
//  - Shift+clic                               = selection de toute la plage depuis l'ancre
document.getElementById('grid').addEventListener('click', e => {
  const tile = e.target.closest('.photo'); if(!tile) return;
  const box = tile.querySelector('.sel'); if(!box) return;
  const mod = e.shiftKey || e.ctrlKey || e.metaKey;
  // Le nom du fichier ouvre la photo (et ne (de)selectionne jamais). e.detail < 2 :
  // on ignore le 2e clic d'un double-clic pour ne pas ouvrir deux onglets.
  if(e.target.classList.contains('name') && !mod){
    if(e.detail < 2) window.open('/photos/' + encodeURIComponent(box.dataset.name), '_blank');
    return;
  }
  // Sinon : toute la vignette (de)selectionne. Si le clic n'est pas sur la case, on bascule.
  const boxes = [...document.querySelectorAll('#grid .sel')];
  const idx = boxes.indexOf(box);
  if(e.target !== box){ e.preventDefault(); box.checked = !box.checked; }
  // Shift+clic : etendre la selection de l'ancre jusqu'a l'element clique.
  if(e.shiftKey && anchorIdx !== null){
    const a = Math.min(anchorIdx, idx), b = Math.max(anchorIdx, idx);
    for(let i = a; i <= b; i++) boxes[i].checked = box.checked;
  }
  anchorIdx = idx;
  syncDelBtn();
});

// Double-clic sur l'image => ouvrir la photo en grand. Les deux clics simples du
// double-clic (de)selectionnent deux fois, donc la selection revient a son etat initial.
document.getElementById('grid').addEventListener('dblclick', e => {
  if(e.target.tagName !== 'IMG') return;
  const tile = e.target.closest('.photo'); if(!tile) return;
  const box = tile.querySelector('.sel'); if(!box) return;
  window.open('/photos/' + encodeURIComponent(box.dataset.name), '_blank');
});

function toggleAll(){
  const boxes = document.querySelectorAll('.sel');
  const allChecked = [...boxes].every(b => b.checked);
  boxes.forEach(b => b.checked = !allChecked);
  syncDelBtn();
}

async function deleteSelected(){
  const names = [...document.querySelectorAll('.sel:checked')].map(b => b.dataset.name);
  if(!names.length) return;
  if(!confirm(`Supprimer ${names.length} photo(s) ?`)) return;
  await api('/api/photos/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({filenames: names})});
  loadPhotos(); loadStatus();
}

async function restartViewer(){ await api('/api/viewer/restart', {method:'POST'}); loadStatus(); }

async function uploadFiles(files){
  const fd = new FormData();
  [...files].forEach(f => fd.append('photos', f));
  document.getElementById('msg').textContent = 'Envoi en cours...';
  await api('/api/photos/upload', {method:'POST', body: fd});
  document.getElementById('msg').textContent = 'Import terminé.';
  loadPhotos(); loadStatus();
}

const drop = document.getElementById('drop');
const fileInput = document.getElementById('fileInput');
drop.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', e => uploadFiles(e.target.files));
['dragover','dragenter'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('drag'); }));
['dragleave','drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('drag'); }));
drop.addEventListener('drop', e => uploadFiles(e.dataTransfer.files));

/* LOGS */
let logSrc = 'wifi';
function showLog(src){
  logSrc = src;
  document.querySelectorAll('.logtab').forEach(b => b.classList.toggle('active', b.dataset.src===src));
  loadLog();
}
async function loadLog(){
  const pre = document.getElementById('logtext');
  const sysbox = document.getElementById('sysbox');
  if(logSrc === 'system'){
    pre.style.display='none'; sysbox.style.display='block';
    sysbox.innerHTML = 'Chargement...';
    const s = await api('/api/logs?source=system');
    const t = s.throttled;
    const uv = t.available ? (t.undervoltage_now?'<span class="bad">ACTIVE</span>':(t.undervoltage_occurred?'<span class="warn">Détectée depuis boot</span>':'<span class="ok">Jamais</span>')) : 'N/A';
    const up = s.uptime!=null ? `${Math.floor(s.uptime/86400)}j ${Math.floor(s.uptime%86400/3600)}h ${Math.floor(s.uptime%3600/60)}min` : 'N/A';
    sysbox.innerHTML = `
      <div class="status-bar" style="padding:0 0 14px">
        <div class="stat"><div class="label">Sous-tension</div><div class="value">${uv}</div></div>
        <div class="stat"><div class="label">Température</div><div class="value">${s.temp}</div></div>
        <div class="stat"><div class="label">Uptime</div><div class="value">${up}</div></div>
        <div class="stat"><div class="label">Mémoire</div><div class="value">${s.mem.used_mb} / ${s.mem.total_mb} Mo</div></div>
        <div class="stat"><div class="label">Disque</div><div class="value">${s.disk.free_gb} Go libres</div></div>
      </div>
      <div class="label" style="margin-bottom:6px">Historique sous-tension (noyau)</div>
      <pre class="log" style="margin:0">${(s.voltage_log||'(aucune)').replace(/</g,'&lt;')}</pre>`;
  } else {
    pre.style.display='block'; sysbox.style.display='none';
    pre.textContent = 'Chargement...';
    const r = await api('/api/logs?source='+logSrc);
    pre.textContent = r.text || '(vide)';
    pre.scrollTop = pre.scrollHeight;
  }
}

/* REGLAGES */
async function loadSettings(){
  const s = await api('/api/settings');
  document.getElementById('slideDelay').value = parseInt(s.slide_delay)||8;
  document.getElementById('delayVal').textContent = (parseInt(s.slide_delay)||8)+' s';
  document.getElementById('slideOrder').value = s.slide_order;
  document.getElementById('displayMode').value = s.display_mode;
  document.getElementById('checkInterval').value = s.check_interval;
  const me = document.getElementById('mailEvery');
  if(me) me.textContent = s.check_interval;
  document.getElementById('mailEnabled').checked = s.mail_enabled;
  document.getElementById('mailState').textContent = s.mail_configured ? '' : '(mail non configuré)';
  document.getElementById('mailEnabled').disabled = !s.mail_configured;
  document.getElementById('webUser').value = s.web_user;
  document.getElementById('tgEnabled').checked = s.telegram_enabled;
  document.getElementById('adminNotify').checked = s.admin_notify;
  document.getElementById('tgCode').value = s.telegram_code || '';
  document.getElementById('tgAdminCodes').value = s.telegram_admin_codes || '';
  loadTgStatus(); loadTgSenders(); loadTgAdmins();
}
async function loadTgStatus(){
  const el = document.getElementById('tgStatus');
  el.textContent = 'vérification...';
  const s = await api('/api/telegram/status');
  if(!s.configured){ el.innerHTML = '<span class="warn">non configuré (colle le token)</span>'; return; }
  if(s.ok){ el.innerHTML = `<span class="ok">connecté</span> @${esc(s.bot||'')} &middot; ${s.allowed_count} personne(s) autorisée(s) &middot; ${s.admin_count} gestionnaire(s)`; }
  else { el.innerHTML = `<span class="bad">token invalide</span> ${esc(s.error||'')}`; }
}
async function loadTgSenders(){
  const box = document.getElementById('tgSenders');
  const r = await api('/api/telegram/senders');
  if(!r.senders || !r.senders.length){ box.innerHTML = '<span class="hint">Aucune personne enregistrée pour l\\'instant.</span>'; return; }
  box.innerHTML = '<table class="sndtbl"><thead><tr><th>Nom</th><th>Photos</th><th>Depuis</th><th></th></tr></thead><tbody>' +
    r.senders.map(x => `<tr>
      <td>${esc(x.name)}</td>
      <td class="num">${x.count}</td>
      <td>${x.since ? new Date(x.since*1000).toLocaleDateString('fr-FR') : '-'}</td>
      <td>${x.is_admin ? '<span class="hint">gestionnaire</span>' : `<button class="act" style="padding:3px 8px;font-size:11px" onclick="promoteTg('${esc(x.chat_id)}')">Nommer gestionnaire</button>`}
        <button class="danger" style="padding:3px 8px;font-size:11px" onclick="revokeTg('${esc(x.chat_id)}')">Révoquer</button></td>
    </tr>`).join('') + '</tbody></table>';
}
async function loadTgAdmins(){
  const box = document.getElementById('tgAdmins');
  const r = await api('/api/telegram/admins');
  if(!r.admins || !r.admins.length){ box.innerHTML = '<span class="hint">Aucun gestionnaire inscrit pour le moment.</span>'; return; }
  box.innerHTML = '<table class="sndtbl"><thead><tr><th>Gestionnaire</th><th>Depuis</th><th></th></tr></thead><tbody>' +
    r.admins.map(x => `<tr>
      <td>${esc(x.name)}</td>
      <td>${x.since ? new Date(x.since*1000).toLocaleDateString('fr-FR') : '-'}</td>
      <td>${x.owner ? '<span class="hint">responsable (permanent)</span>' : `<button class="danger" style="padding:3px 8px;font-size:11px" onclick="revokeTgAdmin('${esc(x.chat_id)}')">Retirer</button>`}</td>
    </tr>`).join('') + '</tbody></table>';
}
async function promoteTg(cid){
  if(!confirm('Donner les droits gestionnaire à cette personne ? Elle recevra chaque nouvelle photo et pourra en supprimer.')) return;
  await api('/api/telegram/admins/add', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({chat_id: cid})});
  loadTgSenders(); loadTgAdmins(); loadTgStatus();
}
async function revokeTgAdmin(cid){
  if(!confirm('Retirer ce gestionnaire ? Il ne pourra plus gérer le cadre depuis Telegram.')) return;
  await api('/api/telegram/admins/revoke', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({chat_id: cid})});
  loadTgAdmins(); loadTgStatus();
}
async function revokeTg(cid){
  if(!confirm('Révoquer cette personne ? Elle devra se réenregistrer avec le code.')) return;
  await api('/api/telegram/revoke', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({chat_id: cid})});
  loadTgSenders(); loadTgStatus();
}
async function saveTelegram(btn){
  const body = {
    telegram_code: document.getElementById('tgCode').value.trim(),
    telegram_admin_codes: document.getElementById('tgAdminCodes').value.trim(),
    telegram_enabled: document.getElementById('tgEnabled').checked,
    admin_notify: document.getElementById('adminNotify').checked,
  };
  const tok = document.getElementById('tgToken').value.trim();
  if(tok) body.telegram_token = tok;
  btn.disabled = true;
  await api('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  document.getElementById('tgToken').value = '';
  btn.disabled = false; flash(btn);
  setTimeout(() => { loadTgStatus(); loadTgSenders(); loadTgAdmins(); }, 800);
}
function flash(btn){
  const s = document.createElement('span'); s.className='saved'; s.textContent='enregistré';
  btn.after(s); setTimeout(()=>s.remove(), 2000);
}
async function saveSettings(keys, btn){
  const map = {
    slide_delay: () => document.getElementById('slideDelay').value,
    slide_order: () => document.getElementById('slideOrder').value,
    display_mode: () => document.getElementById('displayMode').value,
    check_interval: () => document.getElementById('checkInterval').value,
    mail_enabled: () => document.getElementById('mailEnabled').checked,
  };
  const body = {}; keys.forEach(k => body[k] = map[k]());
  btn.disabled = true;
  await api('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  btn.disabled = false; flash(btn); loadStatus();
}
async function saveSecurity(btn){
  const user = document.getElementById('webUser').value.trim();
  const pass = document.getElementById('webPass').value;
  const body = {}; if(user) body.web_user = user; if(pass) body.web_pass = pass;
  if(!Object.keys(body).length){ alert('Rien à changer.'); return; }
  if(!confirm('Changer les identifiants ? Tu devras te reconnecter.')) return;
  btn.disabled = true;
  await api('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  document.getElementById('webPass').value='';
  alert('Identifiants mis à jour. Tu vas être redirigé vers la connexion.');
  location.href = '/logout';
}
async function sysAction(action, msg){
  await api('/api/system/'+action, {method:'POST'});
  document.getElementById('msg').textContent = msg;
  alert(msg);
}

/* init */
loadStatus(); loadPhotos();
setInterval(() => { if(document.getElementById('home').classList.contains('active')){ loadStatus(); loadPhotos(); } }, 8000);
setInterval(() => { if(logSrc && document.getElementById('logs').classList.contains('active')) loadLog(); }, 10000);
</script>
</body>
</html>
"""


def cleanup(*_):
    if viewer_proc:
        try: viewer_proc.terminate()
        except Exception: pass
    os._exit(0)


def run_web():
    app.run(host="127.0.0.1", port=WEB_PORT, threaded=True, use_reloader=False)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    threading.Thread(target=run_web, daemon=True).start()
    threading.Thread(target=telegram_loop, daemon=True).start()
    threading.Thread(target=refresh_worker, daemon=True).start()
    threading.Thread(target=viewer_watchdog, daemon=True).start()
    if EMAIL and PASSWORD:
        fetch_photos()
    else:
        print("[MAIL] GMAIL_USER/GMAIL_PASS non definis, fetch mail desactive.")
    refresh_viewer()
    if EMAIL and PASSWORD:
        mail_loop()
    else:
        while True:
            time.sleep(3600)
