import random
import uuid
import time # Can use step counts instead, but time module is available if needed
from collections import defaultdict, namedtuple
import statistics # For calculating average latency

# --- Configuration ---
NUM_WATCHERS = 10
NUM_GUARDS = 5
WATCHER_MALICIOUS_RATIO = 0.3  # 30% of watchers might be malicious
GUARD_MALICIOUS_RATIO = 0.3    # 30% of guards might be malicious
GUARD_THRESHOLD_RATIO = 0.6  # 60% of Guards must verify for an event to pass

# --- Data Structures ---

Event = namedtuple("Event", ["event_id", "source_chain_id", "target_chain_id", "data", "is_valid"])
ReportedEvent = namedtuple("ReportedEvent", ["event_id", "source_chain_id", "target_chain_id", "data", "reporter_id"])

# --- Simplified Blockchain Model ---

class SimpleBlockchain:
    """A simplified representation of a blockchain holding actual events."""
    def __init__(self, chain_id):
        self.chain_id = chain_id
        self.events = {}  # event_id -> Event
        # print(f"Blockchain '{self.chain_id}' initialized.") # Less verbose

    def add_event(self, target_chain_id, data):
        """Adds a new legitimate event to this blockchain."""
        event_id = str(uuid.uuid4())
        new_event = Event(
            event_id=event_id,
            source_chain_id=self.chain_id,
            target_chain_id=target_chain_id,
            data=data,
            is_valid=True
        )
        self.events[event_id] = new_event
        # print(f"[Blockchain:{self.chain_id}] Added valid event {event_id[:8]} for target {target_chain_id}")
        return new_event

    def get_event(self, event_id):
        """Retrieve an event by its ID."""
        return self.events.get(event_id)

    def get_all_event_ids(self):
        """Return all valid event IDs on this chain."""
        return list(self.events.keys())

# --- Rosenbridge Participant Models ---

class Watcher:
    """Monitors a blockchain and reports events."""
    def __init__(self, watcher_id, monitored_chain, is_malicious=False):
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
            # Malicious watchers fabricate an event with a monetary value
            fake_event_id = f"fake-{str(uuid.uuid4())}"
            fake_report = ReportedEvent(
                event_id=fake_event_id,
                source_chain_id=self.monitored_chain.chain_id, # Pretend it's from monitored chain
                target_chain_id="target-chain-malicious",
                # **Include amount for impact score calculation**
                data={"amount": random.randint(500, 5000), "recipient": "attacker_addr"},
                reporter_id=self.watcher_id
            )
            reports.append(fake_report)
            # print(f"  Watcher {self.watcher_id} (Malicious): Fabricated event {fake_event_id[:8]}")

        return reports

class Guard:
    """Verifies events reported by Watchers."""
    def __init__(self, guard_id, known_blockchains, is_malicious=False):
        self.guard_id = guard_id
        self.known_blockchains = known_blockchains
        self.is_malicious = is_malicious
        self.type = "Malicious" if is_malicious else "Honest"
        # print(f"  Guard {self.guard_id} ({self.type}) initialized.")

    def verify_event(self, reported_event):
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
                 # Malicious guard approves a known fake event (Collusion)
                 # print(f"  Guard {self.guard_id} (Malicious): Falsely verifying fabricated event {reported_event.event_id[:8]} as VALID.")
                 return True
            else:
                 # Malicious guard might deny a real event (Disruption)
                 if random.random() < 0.5: # 50% chance to deny a real event
                      # print(f"  Guard {self.guard_id} (Malicious): Falsely verifying real event {reported_event.event_id[:8]} as INVALID.")
                      return False
                 else:
                     # Or behave honestly sometimes
                     # print(f"  Guard {self.guard_id} (Malicious): Behaving honestly for real event {reported_event.event_id[:8]}. Result: {is_actually_valid}")
                     return is_actually_valid

# --- Simulation Environment ---

class RosenbridgeSimulation:
    """Orchestrates the simulation of Rosenbridge components and tracks metrics."""
    def __init__(self, num_watchers, num_guards, watcher_malicious_ratio, guard_malicious_ratio, guard_threshold_ratio):
        self.num_watchers = num_watchers
        self.num_guards = num_guards
        self.watcher_malicious_ratio = watcher_malicious_ratio
        self.guard_malicious_ratio = guard_malicious_ratio
        self.guard_threshold = max(1, int(num_guards * guard_threshold_ratio)) # Ensure threshold is at least 1 if guards exist

        print(f"\nInitializing Simulation:")
        print(f" Watchers: {num_watchers} ({int(num_watchers * watcher_malicious_ratio)} malicious)")
        print(f" Guards: {num_guards} ({int(num_guards * guard_malicious_ratio)} malicious)")
        print(f" Guard Threshold: {self.guard_threshold} / {num_guards}")

        self.blockchains = {}
        self.watchers = []
        self.guards = []

        # State tracking
        self.pending_reports = defaultdict(list) # event_id -> [ReportedEvent]
        self.guard_signatures = defaultdict(dict) # event_id -> {guard_id: bool}
        self.finalized_events = set() # event_ids that passed guard threshold
        self.processed_event_ids = set() # All event_ids seen by guards

        # --- New Metrics Tracking ---
        self.event_first_reported_step = {} # event_id -> step_num
        self.confirmation_latencies = [] # List of (step_num_finalized - step_num_reported)
        self.stats = {
            "valid_events_created": 0,
            "fabricated_events_reported": 0, # Count attempts
            "valid_events_finalized": 0,
            "fabricated_events_finalized": 0, # Successful attack count
            # Derived metrics calculated at the end:
            # "false_positives": 0, # Valid events rejected
            # "correctly_rejected_fraudulent": 0, # Fabricated events rejected
            # "false_acceptance_rate": 0.0,
            "attack_impact_value": 0, # Cumulative value from finalized fraudulent events
        }

    def setup(self, chain_ids=["ChainA", "ChainB"]):
        """Creates blockchains, watchers, and guards."""
        print("\n--- Setting up Simulation Environment ---")
        for chain_id in chain_ids:
            self.blockchains[chain_id] = SimpleBlockchain(chain_id)
        if not self.blockchains: print("Error: No blockchains defined."); return
        available_chains = list(self.blockchains.values())

        print("Creating Watchers...")
        num_malicious_watchers = int(self.num_watchers * self.watcher_malicious_ratio)
        malicious_indices_w = random.sample(range(self.num_watchers), num_malicious_watchers)
        for i in range(self.num_watchers):
            is_malicious = i in malicious_indices_w
            monitored_chain = random.choice(available_chains)
            watcher = Watcher(f"W{i}", monitored_chain, is_malicious)
            self.watchers.append(watcher)

        print("Creating Guards...")
        num_malicious_guards = int(self.num_guards * self.guard_malicious_ratio)
        malicious_indices_g = random.sample(range(self.num_guards), num_malicious_guards)
        for i in range(self.num_guards):
            is_malicious = i in malicious_indices_g
            guard = Guard(f"G{i}", self.blockchains, is_malicious)
            self.guards.append(guard)
        print("--- Setup Complete ---")

    def trigger_event(self, source_chain_id, target_chain_id, data):
        """Manually trigger a new valid event on a source chain."""
        if source_chain_id in self.blockchains:
            event = self.blockchains[source_chain_id].add_event(target_chain_id, data)
            self.stats["valid_events_created"] += 1
            # print(f"[Sim] Triggered valid event {event.event_id[:8]} on {source_chain_id}")
            return event
        else:
            print(f"Error: Cannot trigger event, source chain '{source_chain_id}' not found.")
            return None

    def run_simulation_step(self, step_num):
        """Runs one step: Watchers report, Guards verify, Finalize & Track Metrics."""
        # print(f"\n--- Simulation Step {step_num} ---")

        # 1. Watchers monitor and report
        # print(" Watcher Reporting Phase...")
        new_reports_this_step = []
        for watcher in self.watchers:
            reports = watcher.monitor_and_report()
            new_reports_this_step.extend(reports)

        # Collate reports & Track first reporting step
        for report in new_reports_this_step:
            event_id = report.event_id
            is_newly_reported = event_id not in self.pending_reports and event_id not in self.finalized_events and event_id not in self.processed_event_ids

            # Record reporting step only the *first* time we see this event ID overall
            if is_newly_reported and event_id not in self.event_first_reported_step:
                 self.event_first_reported_step[event_id] = step_num
                 # Track if it's a fabricated event being reported *for the first time*
                 if event_id.startswith("fake-"):
                     self.stats["fabricated_events_reported"] += 1

            # Add report to pending list (allow multiple watchers reporting same event)
            self.pending_reports[event_id].append(report)

        # 2. Guards verify pending reports
        # print("\n Guard Verification Phase...")
        events_to_verify = list(self.pending_reports.keys()) # Process current pending events

        if not events_to_verify:
             # print("  No new events reported for verification.")
             pass # Continue to check finalization even if no new reports

        for event_id in events_to_verify:
            # Skip if already finalized OR if already processed by guards *in a previous step*
            # We only process pending reports once. If it fails threshold, it stays pending
            # For simplicity: once processed by guards (signatures gathered), it's done for now.
            if event_id in self.finalized_events or event_id in self.processed_event_ids:
                 continue

            reports_for_event = self.pending_reports[event_id]
            if not reports_for_event: continue

            representative_report = reports_for_event[0] # Guards verify based on the first report content
            # print(f"  Guards verifying event {event_id[:8]} (Reported by {len(reports_for_event)} watchers)")

            self.processed_event_ids.add(event_id) # Mark event ID as processed by guards now

            for guard in self.guards:
                 if guard.guard_id not in self.guard_signatures.get(event_id, {}): # Avoid double-voting
                     verification_result = guard.verify_event(representative_report)
                     if event_id not in self.guard_signatures: self.guard_signatures[event_id] = {}
                     self.guard_signatures[event_id][guard.guard_id] = verification_result

        # 3. Check for finalized events (Guard Consensus) & Update Metrics
        # print("\n Finalization Phase...")
        newly_finalized_ids = []
        event_ids_processed_this_step = list(self.guard_signatures.keys()) # Check all events with signatures

        for event_id in event_ids_processed_this_step:
             if event_id in self.finalized_events: continue # Already finalized

             signatures = self.guard_signatures[event_id]
             positive_signatures = sum(1 for sig in signatures.values() if sig is True)

             # print(f"  Event {event_id[:8]}: Received {positive_signatures}/{len(signatures)} positive signatures (Threshold: {self.guard_threshold})")

             if positive_signatures >= self.guard_threshold:
                 self.finalized_events.add(event_id)
                 newly_finalized_ids.append(event_id)
                 # print(f"  ✅ Event {event_id[:8]} FINALIZED.")

                 # --- METRIC UPDATES ---
                 # Calculate Latency
                 report_step = self.event_first_reported_step.get(event_id, step_num) # Default to current step if missing? Should be present.
                 latency = step_num - report_step
                 self.confirmation_latencies.append(latency)

                 is_fabricated = event_id.startswith("fake-")
                 representative_report = self.pending_reports[event_id][0] # Get data

                 if is_fabricated:
                     # Attack succeeded
                     self.stats["fabricated_events_finalized"] += 1
                     # Add to Attack Impact Score
                     amount = representative_report.data.get('amount', 0) # Safely get amount
                     self.stats["attack_impact_value"] += amount
                     # print(f"    Attack Impact: Added {amount}. Total: {self.stats['attack_impact_value']}")
                 else:
                     # Check if it was actually valid (redundant check, but good practice)
                     source_chain = self.blockchains.get(representative_report.source_chain_id)
                     actual_event = source_chain.get_event(event_id) if source_chain else None
                     if actual_event and actual_event.is_valid and actual_event.data == representative_report.data:
                         self.stats["valid_events_finalized"] += 1
                     else:
                         # This is a problem - finalized but shouldn't have been (e.g. data mismatch approved)
                         print(f"  ⚠️ WARNING: Finalized event {event_id[:8]} seems invalid/mismatched despite signatures! Data: {representative_report.data}")
                         # Decide how to count this - could be a separate stat or part of 'fabricated' success?
                         # For now, let's count it as a successful attack as it's wrongly processed.
                         self.stats["fabricated_events_finalized"] += 1 # Count as bad finalization
                         amount = representative_report.data.get('amount', 0) # Include potential value loss
                         self.stats["attack_impact_value"] += amount


             # else: # Not enough signatures yet
             # If all guards have voted and it didn't reach threshold, it's effectively rejected for now
             # if len(signatures) == self.num_guards:
             #     print(f"  Event {event_id[:8]} REJECTED (Insufficient Signatures)")


        # 4. Clean up finalized events from pending reports
        for event_id in newly_finalized_ids:
            if event_id in self.pending_reports:
                del self.pending_reports[event_id]
        # Decide if rejected events should also be removed or kept pending for retry logic
        # Simple approach: remove all processed events from pending
        # for event_id in event_ids_processed_this_step:
        #    if event_id in self.pending_reports:
        #        del self.pending_reports[event_id]


        # print(f"--- End of Step {step_num} ---")

    def report_results(self):
        """Calculates and prints the final statistics including new metrics."""
        print("\n--- Simulation Results ---")

        # --- Basic Counts ---
        print(f"Total Valid Events Created: {self.stats['valid_events_created']}")
        print(f"Total Fabricated Events Reported (Attempts): {self.stats['fabricated_events_reported']}")
        print("-" * 20)
        print(f"Valid Events Finalized (Correctly Processed): {self.stats['valid_events_finalized']}")
        print(f"Fabricated Events Finalized (Successful Attacks): {self.stats['fabricated_events_finalized']}")
        print("-" * 20)

        # --- NEW METRICS Calculations ---

        # 1. Detection Rate / Correct Rejections
        # Number of fabricated events reported but NOT finalized
        correctly_rejected_fraudulent = self.stats['fabricated_events_reported'] - self.stats['fabricated_events_finalized']
        print(f"Detection Rate (Correctly Rejected Fraudulent): {correctly_rejected_fraudulent}")

        # 2. False Positives (Valid events rejected)
        # Number of valid events created but NOT finalized
        false_positives = self.stats['valid_events_created'] - self.stats['valid_events_finalized']
        print(f"False Positives (Valid Events Rejected): {false_positives}")

        # 3. False Acceptance Rate
        if self.stats['fabricated_events_reported'] > 0:
            false_acceptance_rate = (self.stats['fabricated_events_finalized'] / self.stats['fabricated_events_reported']) * 100
            print(f"False Acceptance Rate: {self.stats['fabricated_events_finalized']}/{self.stats['fabricated_events_reported']} = {false_acceptance_rate:.2f}%")
        else:
            print("False Acceptance Rate: N/A (No fraudulent events reported)")

        # 4. Event Confirmation Latency
        if self.confirmation_latencies:
            avg_latency = statistics.mean(self.confirmation_latencies)
            min_latency = min(self.confirmation_latencies)
            max_latency = max(self.confirmation_latencies)
            print(f"Event Confirmation Latency (steps):")
            print(f"  Average: {avg_latency:.2f}")
            print(f"  Min: {min_latency}")
            print(f"  Max: {max_latency}")
            # print(f"  (Raw Latencies: {self.confirmation_latencies})") # Optional: for debugging
        else:
            print("Event Confirmation Latency: N/A (No events finalized)")

        # 5. Attack Impact Score
        print(f"Attack Impact Score (Total Value of Finalized Fraudulent Events): {self.stats['attack_impact_value']}")

        print("-" * 20)
        # Optional: Other summary stats
        # print(f"Total Events Processed by Guards: {len(self.processed_event_ids)}")
        # print(f"Total Events Finalized (Valid + Fabricated): {len(self.finalized_events)}")
        print("--- End of Report ---")


if __name__ == "__main__":
    # Initialize Simulation
    sim = RosenbridgeSimulation(
        num_watchers=NUM_WATCHERS,
        num_guards=NUM_GUARDS,
        watcher_malicious_ratio=WATCHER_MALICIOUS_RATIO,
        guard_malicious_ratio=GUARD_MALICIOUS_RATIO,
        guard_threshold_ratio=GUARD_THRESHOLD_RATIO
    )

    # Setup chains and participants
    sim.setup(chain_ids=["ChainA", "ChainB", "ChainC"])

    # Simulation Steps
    num_simulation_steps = 10 # More steps for better latency stats
    events_per_step = 3

    for i in range(num_simulation_steps):
        current_step = i + 1
        # print(f"\nStarting Simulation Step {current_step}/{num_simulation_steps}") # Less verbose run

        # Trigger some new valid events in each step
        for j in range(events_per_step):
             source = random.choice(list(sim.blockchains.keys()))
             target = random.choice([c for c in sim.blockchains.keys() if c != source])
             sim.trigger_event(
                 source_chain_id=source,
                 target_chain_id=target,
                 # Ensure valid events also have 'amount' if needed for comparison or other metrics
                 data={"amount": random.randint(10, 1000), "tx_id": f"tx_{current_step}_{j}", "recipient": "valid_user"}
             )

        # Run the watcher/guard logic for the step
        sim.run_simulation_step(current_step)
        # time.sleep(0.1) # Optional small delay

    # Report final results with new metrics
    sim.report_results()