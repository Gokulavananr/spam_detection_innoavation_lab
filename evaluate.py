"""Runs the detector on test_images/ and prints precision / recall / F1.
Label comes from the file name: spam_*.png = malicious, normal_*.png = legitimate."""
from pathlib import Path

from detector import analyze_image

THRESHOLD = 40          # score >= 40 counts as "flagged"
rows, tp, fp, tn, fn = [], 0, 0, 0, 0

for p in sorted(Path("test_images").glob("*.png")):
    truth = p.name.startswith("spam_")
    r = analyze_image(p)
    flagged = r["risk_score"] >= THRESHOLD
    tp += truth and flagged
    fn += truth and not flagged
    fp += (not truth) and flagged
    tn += (not truth) and not flagged
    rows.append((p.name, "SPAM" if truth else "NORMAL", r["risk_score"], r["risk_level"],
                 r["qr_codes_found"], "OK" if truth == flagged else "WRONG"))

print(f"{'file':26}{'truth':8}{'score':>6}  {'level':12}{'QRs':>4}  result")
for n, t, s, l, q, ok in rows:
    print(f"{n:26}{t:8}{s:>6}  {l:12}{q:>4}  {ok}")

prec = tp / (tp + fp) if tp + fp else 0
rec = tp / (tp + fn) if tp + fn else 0
f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
print(f"\nTP={tp} FP={fp} TN={tn} FN={fn}")
print(f"Accuracy={(tp + tn) / len(rows):.2f}  Precision={prec:.2f}  Recall={rec:.2f}  F1={f1:.2f}")