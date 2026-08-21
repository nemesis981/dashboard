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

## How it plugs in (the interface contract)

Implement `ml_classifier.Model`:
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
