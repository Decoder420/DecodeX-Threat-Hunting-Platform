from collections import defaultdict
from datetime import datetime

class AnomalyDetector:
    def __init__(self):
        self.host_event_count = defaultdict(int)
        self.user_login_hours = defaultdict(list)

    def build_baseline(self, events):
        for e in events:
            self.host_event_count[e.host] += 1

            if e.timestamp:
                hour = e.timestamp.hour
                self.user_login_hours[e.user].append(hour)

    def detect(self, event):
        alerts = []

        # 🚨 1. High Activity Spike
        if self.host_event_count[event.host] > 20:
            alerts.append({
                "id": "anomaly_high_activity",
                "severity": "medium",
                "description": f"Unusual high activity on host {event.host}"
            })

        # 🚨 2. Unusual Login Time
        if event.user and event.timestamp:
            hours = self.user_login_hours.get(event.user, [])

            if hours:
                avg_hour = sum(hours) / len(hours)

                if abs(event.timestamp.hour - avg_hour) > 6:
                    alerts.append({
                        "id": "anomaly_login_time",
                        "severity": "medium",
                        "description": f"User {event.user} logged in at unusual time"
                    })

        # 🚨 3. Rare Process Execution
        if event.process and "powershell" in event.process.lower():
            if self.host_event_count[event.host] < 3:
                alerts.append({
                    "id": "rare_process_execution",
                    "severity": "high",
                    "description": f"Rare process {event.process} on host {event.host}"
                })

        return alerts