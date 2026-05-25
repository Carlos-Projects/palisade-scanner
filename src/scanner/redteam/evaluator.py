from scanner.domain.models import EvaluationReport, GeneratedPage, PageResult
from scanner.pipeline import PipelineOrchestrator


class ScannerEvaluator:
    """Evaluates scanner performance against generated adversarial pages.

    Metrics: precision, recall, F1, latency, detection rate by
    category, embedding method, and severity.
    """

    def __init__(self, orchestrator: PipelineOrchestrator):
        self.orchestrator = orchestrator

    async def evaluate(self, pages: list[GeneratedPage]) -> EvaluationReport:
        results: list[PageResult] = []
        all_tp = all_fp = all_fn = 0

        by_cat: dict[str, dict] = {}
        by_method: dict[str, dict] = {}
        by_severity: dict[str, dict] = {}

        for page in pages:
            report = await self.orchestrator.scan_content(page.html, url=page.url or "redteam")
            expected = page.ground_truth

            detected_texts = set()
            for f in report.findings:
                detected_texts.add(f.snippet[:80])

            tp = sum(1 for gt in expected if any(
                dt.lower() in gt["text"].lower() for dt in detected_texts
            ))
            fp = sum(1 for f in report.findings if not any(
                f.snippet[:80].lower() in gt["text"].lower() for gt in expected
            )) if expected else 0
            fn = len(expected) - tp if expected else 0

            all_tp += tp
            all_fp += fp
            all_fn += fn

            for gt in expected:
                cat = gt["category"]
                method = gt["method"]
                sv = gt["severity"]
                is_detected = any(gt["text"][:80] in dt for dt in detected_texts)

                for d in [by_cat.setdefault(cat, {"tp": 0, "fn": 0}),
                          by_method.setdefault(method, {"tp": 0, "fn": 0}),
                          by_severity.setdefault(sv, {"tp": 0, "fn": 0})]:
                    if is_detected:
                        d["tp"] += 1
                    else:
                        d["fn"] += 1

            results.append(PageResult(
                page_id=page.id,
                template=page.template_used,
                num_expected=len(expected),
                num_detected=len(report.findings),
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                latency_ms=report.scan_time_ms,
            ))

        precision = all_tp / (all_tp + all_fp) if (all_tp + all_fp) > 0 else 0
        recall = all_tp / (all_tp + all_fn) if (all_tp + all_fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        return EvaluationReport(
            total_pages=len(pages),
            total_injections=all_tp + all_fn,
            total_detections=all_tp + all_fp,
            precision=precision,
            recall=recall,
            f1=f1,
            by_category=by_cat,
            by_method=by_method,
            by_severity=by_severity,
            page_results=results,
            recommendations=self._generate_recommendations(results, by_cat, by_method),
        )

    def _generate_recommendations(self, results, by_cat, by_method) -> list[str]:
        recs = []
        low_cat = [(c, d) for c, d in by_cat.items()
                    if d["tp"] + d["fn"] > 0 and d["tp"] / (d["tp"] + d["fn"]) < 0.5]
        for cat, data in low_cat:
            recs.append(f"Low detection rate for category '{cat}': {data['tp']}/{data['tp'] + data['fn']}")

        low_method = [(m, d) for m, d in by_method.items()
                       if d["tp"] + d["fn"] > 0 and d["tp"] / (d["tp"] + d["fn"]) < 0.5]
        for method, data in low_method:
            recs.append(f"Low detection rate for embedding method '{method}': {data['tp']}/{data['tp'] + data['fn']}")

        return recs
