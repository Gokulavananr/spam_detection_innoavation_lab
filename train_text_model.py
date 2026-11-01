from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

BASE = Path(__file__).resolve().parent
(BASE / "models").mkdir(exist_ok=True)
csv = next(p for p in (BASE / "data" / "spam.csv", BASE / "spam.csv") if p.exists())

df = pd.read_csv(csv, encoding="latin1")[["v1", "v2"]]
df.columns = ["label", "text"]
df["label"] = df["label"].map({"ham": 0, "spam": 1})

Xtr, Xte, ytr, yte = train_test_split(df["text"], df["label"], test_size=0.2,
                                      stratify=df["label"], random_state=42)
pipe = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, stop_words="english")),
    ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
])
pipe.fit(Xtr, ytr)

pred = pipe.predict(Xte)
report = classification_report(yte, pred, target_names=["ham", "spam"])
cm = confusion_matrix(yte, pred)
print(report)
print("Confusion matrix [[TN FP] [FN TP]]:\n", cm)
(BASE / "models" / "metrics.txt").write_text(report + "\n" + str(cm))

pipe.fit(df["text"], df["label"])          # final model uses all data
joblib.dump(pipe, BASE / "models" / "text_spam_model.pkl")
print("Saved models/text_spam_model.pkl")