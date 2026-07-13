"""SCAFFOLD ONLY -- C8 ML anomaly detection / training pipeline.

Owner (per docs/TEAM.md): [4] AI/ML & Automation Engineer + Analytics,
supported by [2] Data Engineering & Data Science Lead (feature pipelines).

TODO(C8): offline training job.
    - Pull normalized events from the telemetry store abstraction
      (app/services/telemetry_store.py) over a rolling training window.
    - Feature engineering: per-actor/per-source behavioral aggregates
      (event counts, rare-action indicators, time-of-day, geo-velocity).
    - Train an unsupervised anomaly model (e.g. isolation forest /
      autoencoder) per tenant or per tenant-cohort.
    - Version and persist model artifacts (see Alert.ml_model_version on
      app/models/alert.py, already reserved for this).
    - Track training runs / metrics (precision proxy, drift) for the
      Analytics module (FM8) to surface.

TODO(C8): define TrainingJob entity + scheduling (cron / triggered by data
volume thresholds) once the data pipeline (FM2/FM3) has enough production
volume to make this worthwhile.
"""

# Intentionally no logic yet. See module docstring for scope.
