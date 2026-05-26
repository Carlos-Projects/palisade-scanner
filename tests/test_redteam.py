import pytest

from scanner.pipeline import PipelineOrchestrator
from scanner.redteam import AdversarialPageGenerator, ScannerEvaluator


def test_generate_adversarial_page():
    gen = AdversarialPageGenerator()
    page = gen.generate(template="ecommerce", num_injections=2)

    assert page.html
    assert len(page.injections) >= 2
    assert len(page.ground_truth) >= 2
    assert "ecommerce" in page.template_used


def test_generate_clean_page():
    gen = AdversarialPageGenerator()
    page = gen.generate_clean(template="ecommerce")

    assert page.html
    assert len(page.injections) == 0


def test_generate_dataset():
    gen = AdversarialPageGenerator()
    pages = gen.generate_dataset(num_adversarial=3, num_clean=3)
    assert len(pages) == 6


@pytest.mark.asyncio
async def test_evaluator_clean_pages():
    gen = AdversarialPageGenerator()
    orchestrator = PipelineOrchestrator()
    evaluator = ScannerEvaluator(orchestrator)

    pages = [gen.generate_clean() for _ in range(3)]
    result = await evaluator.evaluate(pages)

    assert result.total_pages == 3
    assert result.total_injections == 0
    assert result.precision == 0  # no positives = precision 0
    assert result.recall == 0


@pytest.mark.asyncio
async def test_evaluator_adversarial_pages():
    gen = AdversarialPageGenerator()
    orchestrator = PipelineOrchestrator()
    evaluator = ScannerEvaluator(orchestrator)

    pages = [gen.generate(template="ecommerce", num_injections=2) for _ in range(2)]
    result = await evaluator.evaluate(pages)

    assert result.total_pages == 2
    assert result.total_injections >= 2
    assert isinstance(result.f1, float)
