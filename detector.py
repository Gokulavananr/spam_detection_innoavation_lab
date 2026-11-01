"""Spam Shield AI - detection engine (v2)
Fixes vs v1: robust paths, multi-scale QR decoding, QR masked before OCR,
fuzzy keyword matching (handles OCR typos), links found in text are scored,
fewer URL false positives, UPI/other payload types, shorteners, punycode.
"""
import difflib
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

import cv2
import joblib
import pytesseract
from pyzbar import pyzbar

BASE = Path(__file__).resolve().parent

# ---- Tesseract: PATH first, then common Windows location ----
_t = shutil.which("tesseract") or next(
    (p for p in (r"C:\Program Files\Tesseract-OCR\tesseract.exe",) if Path(p).exists()), None)
if _t:
    pytesseract.pytesseract.tesseract_cmd = _t

# ---- ML model (optional: app still works on rules if missing) ----
_mp = next((p for p in (BASE / "models" / "text_spam_model.pkl",
                        BASE / "text_spam_model.pkl") if p.exists()), None)
MODEL = joblib.load(_mp) if _mp else None

# Strong = pressure/scam wording (25 pts each). Weak = words common in legit mail too (8 pts each).
STRONG_WORDS = ["urgent", "suspended", "suspension", "verify", "identity", "password", "expires",
                "locked", "unauthorized", "immediately", "congratulations", "winner", "prize",
                "claim", "lottery"]
WEAK_WORDS = ["account", "alert", "security", "payment", "invoice", "confirm", "refund", "limited"]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "rb.gy", "shorturl.at", "ow.ly", "tiny.cc"}
BAD_TLDS = {"xyz", "top", "club", "online", "ru", "tk", "icu", "click", "cfd",
            "sbs", "buzz", "work", "zip", "mov", "cn"}
BRANDS = ["paypal", "google", "apple", "microsoft", "amazon", "netflix", "paytm",
          "phonepe", "icici", "facebook", "instagram", "whatsapp", "fedex"]
KEYWORDS = {"login", "verify", "account", "secure", "update", "bank", "pay", "free",
            "gift", "invoice", "billing", "password", "wallet", "crypto", "claim",
            "reward", "prize", "kyc", "suspend", "confirm", "otp", "refund"}
SPECIAL = {
    "wifi": (50, "WiFi configuration payload - never join networks from unknown QR codes."),
    "upi": (60, "UPI payment payload - scanning pays money OUT; you never scan to receive money."),
    "javascript": (90, "Executable javascript: payload."),
    "data": (80, "Embedded data: payload (can hide a fake page)."),
    "intent": (50, "Android intent payload (can launch apps)."),
    "tel": (30, "Phone-call payload (possible vishing)."),
    "sms": (30, "SMS payload (possible smishing)."),
    "smsto": (30, "SMS payload (possible smishing)."),
    "mailto": (25, "Pre-filled email payload."),
    "bitcoin": (50, "Cryptocurrency payment payload."),
}
_SLD = {"co.uk", "co.in", "com.au", "org.in", "gov.in", "ac.in", "com.br", "co.jp"}


def _registered(host):
    p = host.split(".")
    return ".".join(p[-3:]) if len(p) >= 3 and ".".join(p[-2:]) in _SLD else ".".join(p[-2:])


def score_url(url):
    u = url.strip()
    low = u.lower()
    if low.startswith("begin:vcard"):
        return 60, ["Contact-card (vCard) payload - common in spear-phishing."]
    if not low.startswith(("http://", "https://")):
        scheme = low.split(":", 1)[0]
        if scheme in SPECIAL:
            return SPECIAL[scheme][0], [SPECIAL[scheme][1]]
        return 0, []

    risk, why = 0, []
    try:
        p = urlparse(u)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return 40, ["Malformed URL."]

    if low.startswith("http://"):
        risk += 20; why.append("Insecure HTTP protocol.")
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}|0x[0-9a-f]+|\d{8,10}", host):
        risk += 40; why.append("Host is a raw IP address.")
    if host in SHORTENERS:
        risk += 30; why.append("URL shortener hides the real destination.")
    if "xn--" in host:
        risk += 30; why.append("Punycode domain (possible lookalike characters).")
    if "@" in (p.netloc or ""):
        risk += 30; why.append("'@' in URL can disguise the real host.")
    if port and port not in (80, 443):
        risk += 15; why.append(f"Non-standard port {port}.")

    tokens = set(re.split(r"[^a-z0-9]+", (host + " " + p.path).lower()))
    kws = sorted(tokens & KEYWORDS)
    if kws:
        risk += min(15 + 5 * (len(kws) - 1), 30)
        why.append("Suspicious keywords: " + ", ".join(kws))

    tld = host.rsplit(".", 1)[-1]
    if tld in BAD_TLDS:
        risk += 25; why.append(f"High-risk TLD (.{tld}).")

    label = _registered(host).split(".")[0]
    for b in BRANDS:
        if b in host and label != b:
            risk += 35; why.append(f"Possible brand impersonation ({b})."); break

    if len(host.split(".")) > 4:
        risk += 15; why.append("Too many subdomains.")
    if host.count("-") >= 2:
        risk += 10; why.append("Multiple hyphens in domain.")
    if len(u) > 100:
        risk += 10; why.append("Very long URL.")
    return min(risk, 100), why


# ------------------------- vision -------------------------
def decode_qr_codes(img):
    """Return {payload: (x, y, w, h)} using pyzbar at several scales, then OpenCV."""
    found = {}
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    for s in (1.0, 0.5, 2.0, 3.0):
        g = gray if s == 1.0 else cv2.resize(
            gray, None, fx=s, fy=s,
            interpolation=cv2.INTER_AREA if s < 1 else cv2.INTER_CUBIC)
        for v in (g, cv2.bitwise_not(g)):
            for o in pyzbar.decode(v, symbols=[pyzbar.ZBarSymbol.QRCODE]):
                r = o.rect
                found.setdefault(o.data.decode("utf-8", "ignore"),
                                 tuple(int(c / s) for c in (r.left, r.top, r.width, r.height)))
        if found:
            return found
    try:  # fallback detector
        ok, texts, pts, _ = cv2.QRCodeDetector().detectAndDecodeMulti(gray)
        if ok:
            for t, pt in zip(texts, pts):
                if t:
                    found[t] = cv2.boundingRect(pt.astype(int))
    except cv2.error:
        pass
    return found


def extract_text(img, qr_rects):
    """OCR with QR area blanked out and light preprocessing."""
    work = img.copy()
    for x, y, w, h in qr_rects:
        cv2.rectangle(work, (x - 8, y - 8), (x + w + 8, y + h + 8), (255, 255, 255), -1)
    g = cv2.cvtColor(work, cv2.COLOR_BGR2GRAY)
    if g.mean() < 110:                      # dark theme screenshot
        g = cv2.bitwise_not(g)
    if g.shape[1] < 1600:
        g = cv2.resize(g, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    _, g = cv2.threshold(g, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return pytesseract.image_to_string(g, config="--psm 6").strip()


# ------------------------- text -------------------------
def analyze_text(text):
    """-> (risk 0-100, ml_probability, rule_hits)"""
    if not text:
        return 0, 0.0, []
    ml = float(MODEL.predict_proba([text])[0][1]) if MODEL else 0.0
    low = text.lower()
    strong, weak = set(), set()
    for w in re.findall(r"[a-z]{5,}", low):          # fuzzy match tolerates OCR typos
        m = difflib.get_close_matches(w, STRONG_WORDS + WEAK_WORDS, n=1, cutoff=0.82)
        if m:
            (strong if m[0] in STRONG_WORDS else weak).add(m[0])
    if re.search(r"scan (the |this |our )?(qr|code)|scan to ", low):
        strong.add("scan-QR lure")
    hits = sorted(strong | weak)
    rule = min(85, 25 * len(strong) + 8 * len(weak))
    # SMS-trained model is noisy on emails: trust it fully only when very confident
    ml_part = int(ml * 100) if ml >= 0.9 else int(ml * 45)
    return max(ml_part, rule), ml, hits


LINK_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.I)


def analyze_image(image_path):
    img = cv2.imread(str(image_path))
    if img is None:
        raise ValueError("Could not read image file.")

    qr = decode_qr_codes(img)
    ocr = extract_text(img, list(qr.values()))
    text_risk, ml, hits = analyze_text(ocr)

    reasons = []
    if hits:
        reasons.append("Pressure/credential cues: " + ", ".join(hits))
    if ml >= 0.9:
        reasons.append(f"ML classifier is highly confident this is spam (p={ml:.2f})")

    def best(urls, prefix=""):
        risk, why = 0, []
        for u in urls:
            r, w = score_url(u)
            if r > risk:
                risk, why = r, [prefix + x for x in w]
        return risk, why

    qr_urls = list(qr)
    qr_risk, qr_reasons = best(qr_urls)
    text_urls = [("https://" + u if u.lower().startswith("www.") else u).rstrip(".,;:")
                 for u in LINK_RE.findall(ocr)]
    link_risk, link_reasons = best(text_urls, "Link in text: ")

    url_risk = max(qr_risk, link_risk)
    final = max(text_risk, url_risk)
    if text_risk >= 50 and url_risk >= 30:   # corroborating signals
        final = min(100, final + 15)

    level = "HIGH RISK" if final >= 70 else "MEDIUM RISK" if final >= 40 else "LOW RISK"
    return {
        "risk_level": level, "risk_score": final,
        "ocr_text_preview": ocr[:500],
        "text_risk": text_risk, "ml_probability": round(ml, 3),
        "text_reason": " | ".join(reasons),
        "qr_codes_found": len(qr_urls), "qr_urls": qr_urls,
        "qr_risk": qr_risk, "qr_reasons": qr_reasons,
        "text_urls": text_urls, "link_risk": link_risk, "link_reasons": link_reasons,
    }