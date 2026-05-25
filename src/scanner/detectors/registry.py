from scanner.detectors.base import BaseDetector
from scanner.detectors.hidden_text import HiddenTextDetector
from scanner.detectors.injection_patterns import InjectionPatternMatcher
from scanner.detectors.metadata_analyzer import MetadataAnalyzer
from scanner.detectors.exfiltration import ExfiltrationDetector
from scanner.detectors.instruction_classifier import InstructionClassifier
from scanner.detectors.unicode_adv import AdvancedUnicodeDetector
from scanner.detectors.stego_markers import StegoMarkersDetector
from scanner.detectors.entropy import EntropyAnalyzer
from scanner.detectors.image_stego import ImageStegoDetector
from scanner.domain.models import Finding


def default_detectors(
    llm_provider: str = "openai",
    llm_model: str = "gpt-4o-mini",
    llm_api_key: str | None = None,
) -> list[BaseDetector]:
    return [
        HiddenTextDetector(),
        InjectionPatternMatcher(),
        MetadataAnalyzer(),
        ExfiltrationDetector(),
        AdvancedUnicodeDetector(),
        StegoMarkersDetector(),
        EntropyAnalyzer(),
        ImageStegoDetector(),
        InstructionClassifier(
            provider=llm_provider,
            model=llm_model,
            api_key=llm_api_key,
        ),
    ]
