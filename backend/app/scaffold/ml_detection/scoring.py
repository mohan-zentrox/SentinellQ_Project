"""SCAFFOLD ONLY -- C8 ML detection: online scoring of events.

Owner (per docs/TEAM.md): [4] AI/ML & Automation Engineer + Analytics.

TODO(C8): implement `score_event(event) -> float` using a model artifact
produced by training.py, writing the result onto Alert.ml_score /
Alert.ml_model_version (see app/models/alert.py) when the score crosses a
tenant-configurable threshold.

TODO(C8): decide whether ML-produced alerts flow through the same
app/services/rule_engine.py::run_rule dedup path or a parallel
`run_ml_scoring` entrypoint invoked alongside app/api/v1/rules.py's
run-all endpoint.
"""

# Intentionally no logic yet. See module docstring for scope.
