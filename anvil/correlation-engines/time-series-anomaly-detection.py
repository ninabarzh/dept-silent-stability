from typing import Tuple
import statistics
from datetime import datetime
from collections import defaultdict


class RPKIAnomalyDetector:
    """
    Detects anomalies in RPKI validation patterns.
    Uses statistical methods that even Ponder Stibbons would approve of.
    """

    def __init__(self, baseline_window: int = 100):
        self.baseline_window = baseline_window
        self.validation_history = defaultdict(list)

    def detect_validation_anomaly(
            self,
            prefix: str,
            current_valid_count: int,
            current_invalid_count: int,
            timestamp: datetime
    ) -> Tuple[bool, str]:
        """
        Detect if current validation pattern is anomalous.
        Returns (is_anomalous, description).
        """
        key = prefix
        history = self.validation_history[key]

        # Record current observation
        observation = {
            'timestamp': timestamp,
            'valid': current_valid_count,
            'invalid': current_invalid_count,
            'ratio': current_valid_count / max(current_invalid_count, 1)
        }
        history.append(observation)

        # Keep only recent history
        if len(history) > self.baseline_window:
            history.pop(0)

        # Need sufficient baseline
        if len(history) < 10:
            return False, "Insufficient baseline data"

        # Calculate baseline statistics
        ratios = [obs['ratio'] for obs in history[:-1]]
        mean_ratio = statistics.mean(ratios)
        stdev_ratio = statistics.stdev(ratios) if len(ratios) > 1 else 0

        current_ratio = observation['ratio']

        # Detect sudden increase (potential attack)
        if stdev_ratio > 0:
            z_score = (current_ratio - mean_ratio) / stdev_ratio

            if z_score > 3:  # 3 sigma event
                return True, f"Anomalous validation spike detected (z-score: {z_score:.2f}). Baseline ratio: {mean_ratio:.2f}, Current: {current_ratio:.2f}"

        # Detect consensus shift
        recent_valids = [obs['valid'] for obs in history[-5:]]
        if all(v >= 3 for v in recent_valids) and current_valid_count >= 3:
            if mean_ratio < 2 and current_ratio >= 3:
                return True, "Sudden validator consensus on previously rejected prefix"

        return False, "No anomaly detected"
