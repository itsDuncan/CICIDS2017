"""
Machine learning pipeline for SOC Sentinel.

Modules:
    features  — feature selection and metadata
    data      — load training/validation/test sets from warehouse
    baseline  — Random Forest binary classifier
    multiclass — XGBoost multi-class attack family classifier
    anomaly   — Isolation Forest for novel attack detection
    evaluate  — model evaluation utilities
    priority  — priority score fusion logic
    score     — scoring pipeline writing back to warehouse
"""