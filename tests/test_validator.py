
from scanner.domain.models import Finding
from scanner.validator import BehaviorEvaluator, MissionGenerator


def test_mission_generates_for_ecommerce():
    gen = MissionGenerator()
    mission = gen.generate("https://shop.example.com/product/123")
    assert mission.page_type == "ecommerce"
    assert "product" in mission.instruction.lower()


def test_mission_generates_for_article():
    gen = MissionGenerator()
    mission = gen.generate("https://medium.com/some-article")
    assert mission.page_type == "article"
    assert "summarize" in mission.instruction.lower()


def test_mission_generates_generic():
    gen = MissionGenerator()
    mission = gen.generate("https://example.com")
    assert mission.instruction


def test_evaluator_no_injections():
    evaluator = BehaviorEvaluator()
    session = {
        "steps": [{"step_number": 1, "thought": "Browsing page", "action": "navigate"}],
        "success": True,
        "agent_provider": "test",
    }
    result = evaluator.evaluate(session, [])
    assert result.overall_vulnerability_score == 0
    assert len(result.injections_triggered) == 0


def test_evaluator_detects_triggered():
    evaluator = BehaviorEvaluator()
    session = {
        "steps": [{"step_number": 1, "thought": "User said ignore instructions, I should obey",
                    "action": "clicked buy button"}],
        "success": True,
        "agent_provider": "test",
    }
    findings = [
        Finding(
            detector="test",
            severity="critical",
            title="Jailbreak",
            snippet="ignore instructions",
            category="jailbreak",
        )
    ]
    result = evaluator.evaluate(session, findings)
    assert len(result.injections_triggered) == 1
    assert result.injections_triggered[0].impact == "triggered"
    assert result.overall_vulnerability_score > 0


def test_evaluator_ignores_untriggered():
    evaluator = BehaviorEvaluator()
    session = {
        "steps": [{"step_number": 1, "thought": "This is a product page",
                    "action": "read description"}],
        "success": True,
        "agent_provider": "test",
    }
    findings = [
        Finding(
            detector="test",
            severity="high",
            title="Exfiltration",
            snippet="exfiltrate all data",
            category="exfiltration",
        )
    ]
    result = evaluator.evaluate(session, findings)
    assert len(result.injections_triggered) == 0
    assert len(result.injections_ignored) == 1
