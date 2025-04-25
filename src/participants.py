import random
import uuid
from datatypes import ReportedEvent
from blockchain import SimpleBlockchain

class Watcher:
    """Monitors a blockchain and reports events."""
    def __init__(self, watcher_id, monitored_chain: SimpleBlockchain, is_malicious=False):
        self.watcher_id = watcher_id
        self.monitored_chain = monitored_chain
        self.is_malicious = is_malicious
        self.seen_event_ids = set()
        self.type = "Malicious" if is_malicious else "Honest"
        # print(f"  Watcher {self.watcher_id} ({self.type}) initialized monitoring {monitored_chain.chain_id}.")

    def monitor_and_report(self):
        """
        Scans the monitored blockchain for new events and reports them.
        Malicious watchers might fabricate events.
        """
        reports = []
        # --- Honest Behavior ---
        if not self.is_malicious:
            all_event_ids = self.monitored_chain.get_all_event_ids()
            new_event_ids = set(all_event_ids) - self.seen_event_ids
            for event_id in new_event_ids:
                event = self.monitored_chain.get_event(event_id)
                if event:
                    report = ReportedEvent(
                        event_id=event.event_id,
                        source_chain_id=event.source_chain_id,
                        target_chain_id=event.target_chain_id,
                        data=event.data,
                        reporter_id=self.watcher_id
                    )
                    reports.append(report)
                    self.seen_event_ids.add(event_id)
                    # print(f"  Watcher {self.watcher_id} (Honest): Reported valid event {event_id[:8]}")

        # --- Malicious Behavior (Fabricate one event per step with value) ---
        else:
            fake_event_id = f"fake-{str(uuid.uuid4())}"
            fake_report = ReportedEvent(
                event_id=fake_event_id,
                source_chain_id=self.monitored_chain.chain_id, # Pretend it's from monitored chain
                target_chain_id="target-chain-malicious",
                data={"amount": random.randint(500, 5000), "recipient": "attacker_addr"},
                reporter_id=self.watcher_id
            )
            reports.append(fake_report)
            # print(f"  Watcher {self.watcher_id} (Malicious): Fabricated event {fake_event_id[:8]}")

        return reports

class Guard:
    """Verifies events reported by Watchers."""
    def __init__(self, guard_id, known_blockchains: dict[str, SimpleBlockchain], is_malicious=False):
        self.guard_id = guard_id
        self.known_blockchains = known_blockchains
        self.is_malicious = is_malicious
        self.type = "Malicious" if is_malicious else "Honest"
        # print(f"  Guard {self.guard_id} ({self.type}) initialized.")

    def verify_event(self, reported_event: ReportedEvent):
        """
        Checks if the reported event actually exists and is valid on the source chain.
        Malicious guards might lie about verification (approve fake, deny real).
        """
        source_chain = self.known_blockchains.get(reported_event.source_chain_id)
        if not source_chain:
            # print(f"  Guard {self.guard_id}: Unknown source chain {reported_event.source_chain_id} for event {reported_event.event_id[:8]}. Cannot verify.")
            return False # Cannot verify if chain is unknown

        actual_event = source_chain.get_event(reported_event.event_id)
        is_actually_valid = actual_event and actual_event.data == reported_event.data

        # --- Honest Behavior ---
        if not self.is_malicious:
            # print(f"  Guard {self.guard_id} (Honest): Verified event {reported_event.event_id[:8]} -> {is_actually_valid}")
            return is_actually_valid

        # --- Malicious Behavior (Ex: Collusion/Disruption) ---
        else:
            is_fabricated = reported_event.event_id.startswith("fake-")

            if is_fabricated:
                 # print(f"  Guard {self.guard_id} (Malicious): Falsely verifying fabricated event {reported_event.event_id[:8]} as VALID.")
                 return True
            else:
                 if random.random() < 0.5: # 50% chance to deny a real event
                      # print(f"  Guard {self.guard_id} (Malicious): Falsely verifying real event {reported_event.event_id[:8]} as INVALID.")
                      return False
                 else:
                     # print(f"  Guard {self.guard_id} (Malicious): Behaving honestly for real event {reported_event.event_id[:8]}. Result: {is_actually_valid}")
                     return is_actually_valid