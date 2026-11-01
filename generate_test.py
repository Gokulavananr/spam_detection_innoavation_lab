"""Generates a labelled test set in ./test_images  (spam_*.png / normal_*.png)."""
import os
import textwrap

import qrcode
from PIL import Image, ImageDraw, ImageFont

OUT = "test_images"
os.makedirs(OUT, exist_ok=True)


def font(size):
    for f in ("arial.ttf", "DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(f, size)
        except OSError:
            pass
    return ImageFont.load_default()


def make(name, lines, payload=None, dark=False, red_first=False):
    bg = (17, 24, 39) if dark else (255, 255, 255)
    fg = (255, 255, 255) if dark else (0, 0, 0)
    img = Image.new("RGB", (800, 800), bg)
    d = ImageDraw.Draw(img)
    y = 50
    for i, line in enumerate(lines):
        for part in textwrap.wrap(line, 48):
            d.text((50, y), part, fill=(255, 0, 0) if (red_first and i == 0) else fg, font=font(24))
            y += 38
        y += 12
    if payload:
        q = qrcode.QRCode(box_size=8, border=4)
        q.add_data(payload)
        q.make(fit=True)
        qi = q.make_image(fill_color=fg, back_color=bg).convert("RGB")
        img.paste(qi, ((800 - qi.width) // 2, max(y + 30, 300)))
    img.save(f"{OUT}/{name}.png")
    print("generated", name)


# ---------------- malicious ----------------
make("spam_bank", ["URGENT: Your bank account has been suspended!",
                   "Scan the QR code below to verify your identity:"],
     "http://verify-account-login.xyz/secure", red_first=True)
make("spam_paypal", ["Security alert: unauthorized login detected on your PayPal account.",
                     "Scan the QR code immediately to confirm your password."],
     "https://paypal-secure-login.top/signin", red_first=True)
make("spam_ip", ["Invoice #88213 payment overdue.", "Scan to view and pay the invoice now."],
     "http://185.234.12.9/invoice/pay")
make("spam_upi", ["Congratulations! Your refund of Rs 4999 is ready.", "Scan this QR to receive your refund."],
     "upi://pay?pa=refund.desk@upi&pn=Refund&am=4999")
make("spam_shortener_dark", ["Your package is on hold. Pay the customs fee urgently.",
                             "Scan the QR code to confirm delivery."],
     "https://bit.ly/3xYzAbC", dark=True)
make("spam_textlink", ["URGENT: Your account is locked.",
                       "Verify your identity now at http://secure-bank-verify.top/login to avoid suspension."],
     None, red_first=True)

make("spam_fake_alert", ["Security alert", "We noticed a new sign-in to your Google Account on a Windows device. If this was not you, secure your account now.", "Review activity: http://accounts-google-verify.top/check"], None)

# ---------------- legitimate ----------------
make("normal_meeting", ["Hello Team,", "Here is the link to our weekly meeting notes."],
     "https://www.google.com")
make("normal_github", ["Hi all,", "The project repository is available at the QR code below."],
     "https://github.com/openai/openai-python")
make("normal_newsletter", ["Weekly newsletter", "Scan to read the full article on Wikipedia."],
     "https://www.wikipedia.org")
make("normal_statement", ["Hi, your monthly statement for October is ready.",
                          "You can view it any time at https://www.hdfcbank.com"], None)
make("normal_security_alert", ["Security alert", "We noticed a new sign-in to your Google Account on a Windows device. If this was you, you don't need to do anything. If not, we'll help you secure your account.", "Review activity: https://myaccount.google.com/notifications"], None)
make("normal_plain", ["Lunch at 1 pm in the cafeteria.", "Please bring your project reports."], None)