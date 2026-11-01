from db.worker_result import normalize_worker_result


def test_cognitive_result_contract_keeps_outcome_and_observation():
    result = normalize_worker_result(
        {
            "status": "done",
            "outcome": "supports",
            "observation_summary": "stored evidence distinguishes states",
            "alternative_explanation": "none",
            "evidence_refs": ["ev-1"],
            "confidence": "medium",
        }
    )
    assert result["outcome"] == "supports"
    assert result["observation_summary"]


def test_support_without_evidence_is_inconclusive():
    result = normalize_worker_result({"status": "done", "outcome": "supports", "summary": "looks useful"})
    assert result["outcome"] == "inconclusive"
