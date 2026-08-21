# CUSTOM_LAYERD_MODEL.md — Layer D local ML classifier: the model artifact

Layer D scores unknown PE files for maliciousness ON-BOX (no cloud, no API key), the
complement to Layer C's AI verdict. The **pipeline** — feature extraction, scoring,
conservative calibration, honest defaults — is built and tested
(`ml_features.py`, `ml_classifier.py`, `test_ml.py`). What ships is scaffolding that
**flags nothing until a validated model artifact is loaded**. This guide is what the
model is and how it plugs in — deliberately separated, because the model is a
data-science project, not a code change, and conflating them is how Layer D would
overclaim.

## The model is a separate, validated, versioned artifact — NOT built here

Per the roadmap (correctly): the model + its **false-positive calibration is its own
first-class project**. A misfiring classifier is worse than none. So:

- **Training** is offline, against a real corpus of malicious + benign PEs (e.g. an
  EMBER-style dataset). The output is one model artifact.
- **Calibration** — choosing `malicious_threshold` against that corpus so the
  false-positive rate is acceptable — is the deliverable that gates enabling Layer D,
  not a tail task. The shipped default threshold (0.90) is deliberately HIGH so an
  *un*calibrated deployment errs toward silence, not noise.
- **The artifact must declare `feature_version`** matching `ml_features.FEATURE_VERSION`.
  A mismatch is refused, never scored — a model is only valid for the features it was
  trained on.

## The training + calibration harness (built: `ml_train.py` + `ml_model.py`)

The model-sourcing path is built and dependency-free:

- **`ml_train.py`** (build-time, numpy) turns a labeled corpus into an artifact:
  `python3 ml_train.py --malicious DIR --benign DIR --out model.json --target-fpr 0.01`.
  It extracts features with the **same `ml_features.extract`** the endpoint uses (parity —
  a model is never trained on features that differ from what it scores), trains a
  standardized logistic regression, and **calibrates the malicious threshold on a held-out
  split to keep the false-positive rate at/under the target**, recording achieved metrics in
  the artifact. It refuses a single-class corpus (you cannot calibrate an FP rate without
  both classes) and SKIPS non-PE files (never trains on faked features).
- **`ml_model.py`** loads the artifact and scores with the **standard library only** — no
  numpy/sklearn on the endpoint. `ml_model.load(path)` is the loader to pass to
  `ml_classifier.load_model(path, loader=ml_model.load)`; any malformed/oversized/wrong-version
  artifact returns `None` (Layer D stays in the safe no-verdict state). `model_compile_check`
  is the rule_updater gate — a model that does not load + satisfy the interface never replaces
  a good one on an endpoint.

Proven end-to-end (2026-08-21) on a real-PE corpus: extract → train → calibrate (FP budget
held) → save → load → `ml_classifier` scores a real high-entropy PE malicious and a real
low-entropy PE benign, and the pure-Python scorer matches the numpy trainer to 1e-9.

**What is still deferred is the CORPUS, not the code:** a production model needs a real,
representative EMBER-style dataset and a deliberate false-positive budget. That curation is
the data-science project this harness serves — the harness itself is done.

The artifact is a transparent standardized logistic regression (a per-feature scaler + weight
vector + bias + thresholds). A richer model (tree ensemble) can ship the same way by giving
`ml_model.load()` another `kind` + scorer; the `ml_classifier` contract does not change.

## How it plugs in (the interface contract)

Implement `ml_classifier.Model` (or use `ml_model.LogisticModel` from a trained artifact):
```python
class MyModel(ml_classifier.Model):
    feature_version = ml_features.FEATURE_VERSION
    def predict_proba(self, vector):   # vector = ml_features.to_vector(feats), len 278
        return float(...)              # P(malicious) in [0, 1]
```
Load it with `ml_classifier.load_model(path, loader=your_deserializer)`. Any failure
(bad artifact, wrong interface, missing feature_version) keeps Layer D in the safe
`no_model -> no verdict` state — it never scores with a broken model.

## Distribution rides the existing fleet channel

A model is just another versioned artifact: distribute it to endpoints via
`rule_updater.update_ruleset` (mandatory digest, no-redirect, size-bounded,
compile-check-before-activate — where the "compile-check" is "the artifact loads and
satisfies the Model interface at the expected feature_version"). Endpoint model
versions report through `engine_inventory`, so uneven Layer-D coverage is visible like
every other engine.

## The posture, restated (do not let this drift)

- **Advisory only.** A Layer-D verdict is a finding INPUT — it never quarantines a file
  or changes a finding's status on its own. Same as Layer C.
- **Middle band is `suspicious`, not `malicious`.** Only high-confidence yields an
  accusation; the rest is a hint for a human / Layer C.
- **No model, no verdict.** Until a calibrated model is loaded, Layer D contributes
  nothing — which is the correct, honest state, not a gap to paper over.
