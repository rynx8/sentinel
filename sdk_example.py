"""
Sentinel SDK pattern — how an AI agent integrates with Sentinel.

The agent asks Sentinel for permission BEFORE executing any action.
Sentinel logs it to the tamper-evident chain and returns a decision
the agent must enforce.

Run the server first (python app.py), then: python sdk_example.py
"""

import requests

SENTINEL_URL = "http://localhost:5000"


class SentinelGuard:
    def __init__(self, agent_id):
        self.agent_id = agent_id

    def check(self, action_type, target, params=None):
        """Returns the decision dict. Raise/skip on anything not allowed."""
        r = requests.post(
            f"{SENTINEL_URL}/api/v1/actions",
            json={
                "agent_id": self.agent_id,
                "action_type": action_type,
                "target": target,
                "params": params or {},
            },
            timeout=5,
        )
        r.raise_for_status()
        return r.json()


if __name__ == "__main__":
    guard = SentinelGuard("agt_demo_sdk")

    # An agent about to make an API call:
    verdict = guard.check("http_request", "https://api.anthropic.com/v1/messages",
                          {"method": "POST"})
    print("api call:", verdict["decision"])          # -> allowed

    # The same agent about to read credentials:
    verdict = guard.check("file_read", "/app/.env")
    print(".env read:", verdict["decision"],
          "| rule:", verdict["rule"])                # -> blocked | credential-access

    # And about to send an email:
    verdict = guard.check("send_email", "customer@example.com",
                          {"subject": "Your refund"})
    print("email:", verdict["decision"])             # -> pending (human approval)

    if verdict["decision"] != "allowed":
        print("agent holds the email until a human approves it in the dashboard")
