import numpy as np
from sklearn.ensemble import IsolationForest

class AnomalyEngine:
    def __init__(self):
        self.model = IsolationForest(contamination=0.08, random_state=42)
        self.trained = False

    def fit(self, features):
        self.model.fit(np.asarray(features, dtype=float))
        self.trained = True

    def score(self, features):
        if not self.trained:
            raise RuntimeError("Model has not been trained")
        x = np.asarray(features, dtype=float)
        prediction = self.model.predict(x)
        raw = self.model.decision_function(x)
        scores = np.clip(0.5 - raw, 0, 1)
        return [{"label": "ANOMALY" if p == -1 else "NORMAL", "score": float(s)}
                for p, s in zip(prediction, scores)]
