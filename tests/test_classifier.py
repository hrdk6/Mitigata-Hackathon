"""Tests for the technology-agnostic Naive Bayes vulnerability classifier and recall scoring."""
import pytest
from nighttrace.reasoning.classifier import NaiveBayesVulnClassifier, default_classifier, DEFAULT_TRAINING_DATA


def test_naive_bayes_training_and_vocabulary():
    clf = NaiveBayesVulnClassifier()
    clf.train(DEFAULT_TRAINING_DATA)
    assert clf.trained
    assert "sql_injection" in clf.classes
    assert "path_traversal" in clf.classes
    assert "reflected_xss" in clf.classes
    assert "default_credentials" in clf.classes
    assert "id" in clf.vocabulary
    assert "file" in clf.vocabulary
    assert "q" in clf.vocabulary


def test_technology_agnostic_predictions():
    # Database parameter predicts SQL injection with high confidence
    best, prob = default_classifier.predict_best_class(param="id", path="/api/v1/items")
    assert best == "sql_injection"
    assert prob > 0.40

    best, prob = default_classifier.predict_best_class(param="item_id", path="/products")
    assert best == "sql_injection"
    assert prob > 0.40

    # File path parameter predicts Path Traversal with high confidence
    best, prob = default_classifier.predict_best_class(param="file", path="/download")
    assert best == "path_traversal"
    assert prob > 0.40

    best, prob = default_classifier.predict_best_class(param="filename", path="/view")
    assert best == "path_traversal"
    assert prob > 0.40

    # Search parameter predicts Reflected XSS with high confidence
    best, prob = default_classifier.predict_best_class(param="q", path="/search")
    assert best == "reflected_xss"
    assert prob > 0.40

    best, prob = default_classifier.predict_best_class(param="search", path="/find")
    assert best == "reflected_xss"
    assert prob > 0.40

    # Login parameter predicts default credentials
    best, prob = default_classifier.predict_best_class(param="username", path="/login")
    assert best == "default_credentials"
    assert prob > 0.40


def test_rank_candidates_prioritizes_high_probability():
    candidates = [
        ("/search", "q"),
        ("/download", "file"),
        ("/items", "id"),
    ]

    # For SQL Injection, ('/items', 'id') must be ranked FIRST
    ranked_sqli = default_classifier.rank_candidates("web-sql-injection", candidates)
    assert ranked_sqli[0] == ("/items", "id")

    # For Path Traversal, ('/download', 'file') must be ranked FIRST
    ranked_traversal = default_classifier.rank_candidates("web-path-traversal", candidates)
    assert ranked_traversal[0] == ("/download", "file")

    # For Reflected XSS, ('/search', 'q') must be ranked FIRST
    ranked_xss = default_classifier.rank_candidates("web-reflected-input", candidates)
    assert ranked_xss[0] == ("/search", "q")


def test_recall_and_precision_metrics(tmp_path):
    from nighttrace.blackboard import Blackboard
    from nighttrace.scoring import compute
    from nighttrace.models import Status

    # Create dummy ground truth
    gt_file = tmp_path / "ground_truth.yaml"
    gt_file.write_text("""
services:
  - "127.0.0.1:8000"
weaknesses:
  - type: sql_injection
    host: 127.0.0.1
  - type: path_traversal
    host: 127.0.0.1
flags:
  - "FLAG{test}"
""", encoding="utf-8")

    bb = Blackboard()
    bb.upsert_asset("127.0.0.1", 8000, "http", "Test", "network")

    # Insert 2 confirmed findings matching the ground truth
    fid1, _ = bb.add_finding(title="SQLi", type="sql_injection", surface="web", ptes="exploitation", severity="high", asset_host="127.0.0.1")
    bb.update_finding(fid1, status=Status.CONFIRMED.value)

    fid2, _ = bb.add_finding(title="LFI", type="path_traversal", surface="web", ptes="exploitation", severity="high", asset_host="127.0.0.1")
    bb.update_finding(fid2, status=Status.CONFIRMED.value)

    scores = compute(bb, str(gt_file))
    assert "recall" in scores
    assert "precision" in scores
    assert scores["recall"]["value"] == 1.0  # 2/2 planted weaknesses found -> 100% Recall
    assert scores["recall"]["grade"] == "Great"
    assert scores["precision"]["value"] == 1.0  # 0 false alarms -> 100% Precision
    assert scores["precision"]["grade"] == "Great"


def test_classifier_cross_validation_recall_score():
    clf = NaiveBayesVulnClassifier()
    metrics = clf.train(DEFAULT_TRAINING_DATA, run_evaluation=True)
    assert clf.recall_score >= 0.85, f"Expected macro recall >= 0.85, got {clf.recall_score}"
    assert clf.precision_score >= 0.80
    assert "per_class" in metrics
    report = clf.format_evaluation_report(metrics)
    assert "Macro Average" in report
    assert "Empirical Recall Score" in report


def test_custom_dataset_training_and_export(tmp_path):
    clf = NaiveBayesVulnClassifier()
    export_file = tmp_path / "dataset.json"
    clf.export_dataset(export_file)
    assert export_file.is_file()

    # Train from exported file
    clf2 = NaiveBayesVulnClassifier()
    metrics = clf2.train_from_file(export_file)
    assert clf2.trained
    assert len(clf2.classes) >= 5

