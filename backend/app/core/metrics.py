"""Minimal in-process metrics registry, exposed in Prometheus text format.

Deliberately dependency-free rather than pulling in `prometheus-client`: this
repo's requirements.txt is kept light on purpose, and the surface needed here
(counters + latency histograms, scraped from one process) is small enough that
a dict of dicts is honest about what it is.

Known limitation, stated rather than hidden: these counters are per-process
and reset on restart, so with multiple uvicorn workers a scrape sees one
worker's view. That is fine for local dev and a single-replica deployment; a
real multi-replica deployment should swap this for `prometheus-client` with a
multiprocess collector, or push to a statsd/OTLP sidecar. The call sites
(`metrics.increment` / `metrics.observe`) are the seam for that change.
"""
from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any

#: Latency buckets in milliseconds.
_BUCKETS = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000)

Labels = dict[str, str] | None


def _label_key(labels: Labels) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((labels or {}).items()))


def _render_labels(key: tuple[tuple[str, str], ...], extra: dict[str, str] | None = None) -> str:
    pairs = dict(key)
    if extra:
        pairs.update(extra)
    if not pairs:
        return ""
    inner = ",".join(f'{k}="{v}"' for k, v in sorted(pairs.items()))
    return "{" + inner + "}"


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple, float]] = defaultdict(lambda: defaultdict(float))
        self._histograms: dict[str, dict[tuple, dict[str, Any]]] = defaultdict(dict)
        self._gauges: dict[str, dict[tuple, float]] = defaultdict(lambda: defaultdict(float))

    def increment(self, name: str, labels: Labels = None, value: float = 1.0) -> None:
        with self._lock:
            self._counters[name][_label_key(labels)] += value

    def set_gauge(self, name: str, value: float, labels: Labels = None) -> None:
        with self._lock:
            self._gauges[name][_label_key(labels)] = value

    def observe(self, name: str, value: float, labels: Labels = None) -> None:
        key = _label_key(labels)
        with self._lock:
            series = self._histograms[name].get(key)
            if series is None:
                series = {"count": 0, "sum": 0.0, "buckets": dict.fromkeys(_BUCKETS, 0)}
                self._histograms[name][key] = series
            series["count"] += 1
            series["sum"] += value
            for bucket in _BUCKETS:
                if value <= bucket:
                    series["buckets"][bucket] += 1

    def render(self) -> str:
        """Prometheus text exposition format."""
        lines: list[str] = []
        with self._lock:
            for name, series in sorted(self._counters.items()):
                lines.append(f"# TYPE {name} counter")
                for key, value in sorted(series.items()):
                    lines.append(f"{name}{_render_labels(key)} {value:g}")
            for name, series in sorted(self._gauges.items()):
                lines.append(f"# TYPE {name} gauge")
                for key, value in sorted(series.items()):
                    lines.append(f"{name}{_render_labels(key)} {value:g}")
            for name, by_labels in sorted(self._histograms.items()):
                lines.append(f"# TYPE {name} histogram")
                for key, data in sorted(by_labels.items()):
                    cumulative = 0
                    for bucket in _BUCKETS:
                        cumulative = data["buckets"][bucket]
                        lines.append(f"{name}_bucket{_render_labels(key, {'le': str(bucket)})} {cumulative}")
                    lines.append(f"{name}_bucket{_render_labels(key, {'le': '+Inf'})} {data['count']}")
                    lines.append(f"{name}_sum{_render_labels(key)} {data['sum']:g}")
                    lines.append(f"{name}_count{_render_labels(key)} {data['count']}")
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        """Test helper."""
        with self._lock:
            self._counters.clear()
            self._histograms.clear()
            self._gauges.clear()


metrics = MetricsRegistry()
