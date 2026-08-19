"""
TriageHound v2.0 — Performance Metrics Collector
===================================================
Instruments the v2.0 pipeline with timing, resource usage, and
accuracy metrics for research evaluation.

Usage:
    from modules.metrics import MetricsCollector
    mc = MetricsCollector()
    mc.start("Normalization")
    ...
    mc.stop("Normalization")
    mc.report()
"""

import time
import platform
import os
import json
from datetime import datetime


class MetricsCollector:
    """
    Collects and reports performance and accuracy metrics for
    the TriageHound v2.0 intelligence pipeline.
    """

    def __init__(self):
        self.timings = {}
        self._start_times = {}
        self.counters = {}
        self.system_info = self._collect_system_info()

    def start(self, phase_name):
        """Start timing a phase."""
        self._start_times[phase_name] = time.perf_counter()

    def stop(self, phase_name):
        """Stop timing a phase and record the duration."""
        if phase_name in self._start_times:
            elapsed = time.perf_counter() - self._start_times[phase_name]
            self.timings[phase_name] = elapsed
            del self._start_times[phase_name]
            return elapsed
        return 0.0

    def count(self, metric_name, value=1):
        """Increment a counter metric."""
        self.counters[metric_name] = self.counters.get(metric_name, 0) + value

    def set_counter(self, metric_name, value):
        """Set a counter to a specific value."""
        self.counters[metric_name] = value

    def get_total_pipeline_time(self):
        """Get the total time across all measured phases."""
        return sum(self.timings.values())

    def report(self):
        """Print a formatted metrics report to the console."""
        total = self.get_total_pipeline_time()

        print()
        print("    ================================================")
        print("     PERFORMANCE METRICS")
        print("    ================================================")
        print(f"    Platform      : {self.system_info['os']}")
        print(f"    Python        : {self.system_info['python']}")
        print(f"    Processor     : {self.system_info['processor']}")
        print(f"    Total Pipeline: {total*1000:.1f} ms")
        print("    ------------------------------------------------")

        if self.timings:
            print("    Phase Timings:")
            for name, elapsed in self.timings.items():
                pct = (elapsed / total * 100) if total > 0 else 0
                bar_len = int(pct / 5)
                bar = '#' * bar_len + '.' * (20 - bar_len)
                print(f"      {name:<28s} {elapsed*1000:>8.1f} ms  "
                      f"[{bar}] {pct:>5.1f}%")

        if self.counters:
            print("    ------------------------------------------------")
            print("    Metrics:")
            for name, value in sorted(self.counters.items()):
                print(f"      {name:<28s} {value:>8}")

        print("    ================================================")
        print()

    def to_dict(self):
        """Export metrics as a dictionary (for JSON serialization)."""
        return {
            'timestamp': datetime.now().isoformat(),
            'system_info': self.system_info,
            'total_pipeline_ms': round(self.get_total_pipeline_time() * 1000, 2),
            'phase_timings_ms': {
                name: round(elapsed * 1000, 2)
                for name, elapsed in self.timings.items()
            },
            'counters': dict(self.counters),
        }

    def save(self, filepath):
        """Save metrics to a JSON file."""
        data = self.to_dict()
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def _collect_system_info(self):
        """Collect basic system information."""
        try:
            import psutil
            mem = psutil.virtual_memory()
            memory_gb = round(mem.total / (1024**3), 1)
        except ImportError:
            memory_gb = 'N/A'

        return {
            'os': f"{platform.system()} {platform.release()} ({platform.version()})",
            'python': platform.python_version(),
            'processor': platform.processor() or platform.machine(),
            'memory_gb': memory_gb,
            'hostname': platform.node(),
        }
