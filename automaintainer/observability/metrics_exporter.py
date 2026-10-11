from typing import Dict, Any
from automaintainer.observability.metrics import MetricsCollector, get_metrics

class PrometheusMetricsExporter:
    """
    Prometheus /metrics Text Exporter.
    Translates internal MetricsCollector counters to OpenMetrics/Prometheus format.
    """

    def __init__(self, collector: MetricsCollector = None):
        self.collector = collector or get_metrics()

    def generate_prometheus_text(self) -> str:
        lines = []
        metrics_dict = self.collector.snapshot()

        for k, v in metrics_dict.items():
            metric_name = f"automaintainer_{k}"
            lines.append(f"# TYPE {metric_name} counter")
            lines.append(f"{metric_name} {v}")

        return "\n".join(lines) + "\n"
