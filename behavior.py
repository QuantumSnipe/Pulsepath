"""Conservative outbound change detection from fresh, local socket counters.

No payload inspection, reputation lookup, or malware verdict. Learning and raw
counter comparisons live only in memory and restart whenever recording pauses.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from typing import Any


class OutboundMonitor:
    def __init__(
        self, window_seconds=60, minimum_windows=6, baseline_windows=20,
        minimum_bytes=10 * 1024 * 1024, ratio=5, consecutive_windows=2,
        cooldown_seconds=1800, max_gap_seconds=10,
    ):
        self.window_seconds = window_seconds
        self.minimum_windows = minimum_windows
        self.baseline_windows = baseline_windows
        self.minimum_bytes = minimum_bytes
        self.ratio = ratio
        self.consecutive_windows = consecutive_windows
        self.cooldown_seconds = cooldown_seconds
        self.max_gap_seconds = max_gap_seconds
        self.states: OrderedDict[tuple, dict[str, Any]] = OrderedDict()

    def reset(self):
        self.states.clear()

    def observe(self, flows: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
        events = []
        present = set()
        received_at = now
        for flow in flows:
            sample_time = flow.get("last_seen", received_at)
            now = sample_time if isinstance(sample_time, (int, float)) else received_at
            key = (
                str(flow.get("process") or "Unknown").strip().casefold(),
                str(flow.get("protocol") or "TCP").upper(),
                flow.get("remote_port"), flow.get("destination_key") or flow.get("remote_ip"),
            )
            if key in present:
                continue
            present.add(key)
            state = self.states.get(key)
            if state is None:
                state = {"baseline": deque(maxlen=self.baseline_windows), "last_alert": None,
                         "previous": {}, "time": now, "start": now, "bytes": 0, "run": 0}
                self.states[key] = state
            self.states.move_to_end(key)
            sockets = flow.get("sockets") or [flow]
            current = {}
            valid = 0 <= received_at - now <= self.max_gap_seconds
            for socket in sockets:
                identity = (socket.get("id"), socket.get("first_seen"))
                counter = socket.get("bytes_out")
                fresh = socket.get("last_seen")
                if (not identity[0] or socket.get("source") != "nettop"
                        or type(counter) is not int or counter < 0
                        or not isinstance(fresh, (int, float)) or fresh != now
                        or identity in current):
                    valid = False
                    break
                current[identity] = counter
            elapsed = now - state["time"]
            previous = state["previous"]
            comparable = (valid and bool(current) and current.keys() == previous.keys()
                          and 0 < elapsed <= self.max_gap_seconds
                          and all(value >= previous[identity] for identity, value in current.items()))
            if not comparable:
                state.update(previous=current if valid else {}, time=now, start=now, bytes=0, run=0)
                continue
            state["bytes"] += sum(value - previous[identity] for identity, value in current.items())
            state.update(previous=current, time=now)
            duration = now - state["start"]
            if duration < self.window_seconds:
                continue
            measured = state["bytes"]
            normalized = measured * self.window_seconds / duration
            baseline = state["baseline"]
            reference = max(baseline, default=0)
            threshold = max(self.minimum_bytes, self.ratio * reference)
            unusual = len(baseline) >= self.minimum_windows and normalized > threshold
            if unusual:
                state["run"] += 1
                if (state["run"] >= self.consecutive_windows
                        and (state["last_alert"] is None or now - state["last_alert"] >= self.cooldown_seconds)):
                    # Use a measured socket as the map anchor; grouped totals
                    # describe this stream, not necessarily this one endpoint.
                    anchor = max(sockets, key=lambda item: item["bytes_out"] - previous[(item["id"], item.get("first_seen"))])
                    events.append({
                        "event_type": "outbound_change", "process": flow.get("process") or "Unknown",
                        "remote_ip": anchor.get("remote_ip") or flow.get("remote_ip"),
                        "remote_port": flow.get("remote_port"), "protocol": key[1],
                        "destination_key": flow.get("destination_key"), "service": flow.get("service"),
                        "provider": (flow.get("network_reference") or {}).get("name"),
                        "bytes_out": measured, "window_seconds": duration,
                        "baseline_bytes_out": reference, "baseline_window_seconds": self.window_seconds,
                        "baseline_window_count": len(baseline), "threshold_bytes_out": threshold,
                        "consecutive_windows": state["run"], "measured_socket_count": len(current),
                        "source": "nettop", "coverage": "All observed sockets in this stream; unobserved traffic is unknown",
                    })
                    state["last_alert"] = now
            else:
                state["run"] = 0
                baseline.append(normalized)
            state.update(start=now, bytes=0)
        # A missing stream breaks continuity even if it reappears next poll.
        for key, state in self.states.items():
            if key not in present:
                state.update(previous={}, start=now, bytes=0, run=0)
        while len(self.states) > 1024:
            self.states.popitem(last=False)
        return events
