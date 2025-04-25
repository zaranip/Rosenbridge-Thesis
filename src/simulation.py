import random
import uuid
import time
from collections import defaultdict
import statistics

import config
from datatypes import Event, ReportedEvent
from blockchain import SimpleBlockchain
from participants import Watcher, Guard

class RosenbridgeSimulation:
    """Orchestrates the simulation of Rosenbridge components and tracks metrics."""
    def __init__(self):
        # Read configuration directly from the imported module
        self.num_watchers = config.NUM_WATCHERS
        self.num_guards = config.NUM_GUARDS
        self.watcher_malicious_ratio = config.WATCHER_MALICIOUS_RATIO
        self.guard_malicious_ratio = config.GUARD_MALICIOUS_RATIO
        self.guard_threshold = max(1, int(config.NUM_GUARDS * config.GUARD_THRESHOLD_RATIO))

        print(f"\nInitializing Simulation:")
        print(f" Watchers: {self.num_watchers} ({int(self.num_watchers * self.watcher_malicious_ratio)} malicious)")
        print(f" Guards: {self.num_guards} ({int(self.num_guards * self.guard_malicious_ratio)} malicious)")
        print(f" Guard Threshold: {self.guard_threshold} / {self.num_guards}")

        self.blockchains: dict[str, SimpleBlockchain] = {}
        self.watchers: list[Watcher] = []
        self.guards: list[Guard] = []

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
            "fabricated_events_reported": 0,
            "valid_events_finalized": 0,
            "fabricated_events_finalized": 0,
            "attack_impact_value": 0,
        }

    def setup(self, chain_ids):
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
        new_reports_this_step = []
        for watcher in self.watchers:
            reports = watcher.monitor_and_report()
            new_reports_this_step.extend(reports)

        # Collate reports & Track first reporting step
        for report in new_reports_this_step:
            event_id = report.event_id
            is_newly_reported = event_id not in self.pending_reports and event_id not in self.finalized_events and event_id not in self.processed_event_ids
            if is_newly_reported and event_id not in self.event_first_reported_step:
                 self.event_first_reported_step[event_id] = step_num
                 if event_id.startswith("fake-"):
                     self.stats["fabricated_events_reported"] += 1
            self.pending_reports[event_id].append(report)

        # 2. Guards verify pending reports
        events_to_verify = list(self.pending_reports.keys())
        if not events_to_verify: pass

        for event_id in events_to_verify:
            if event_id in self.finalized_events or event_id in self.processed_event_ids: continue
            reports_for_event = self.pending_reports[event_id]
            if not reports_for_event: continue
            representative_report = reports_for_event[0]
            self.processed_event_ids.add(event_id)
            for guard in self.guards:
                 if guard.guard_id not in self.guard_signatures.get(event_id, {}):
                     verification_result = guard.verify_event(representative_report)
                     if event_id not in self.guard_signatures: self.guard_signatures[event_id] = {}
                     self.guard_signatures[event_id][guard.guard_id] = verification_result

        # 3. Check for finalized events (Guard Consensus) & Update Metrics
        newly_finalized_ids = []
        event_ids_processed_this_step = list(self.guard_signatures.keys())

        for event_id in event_ids_processed_this_step:
             if event_id in self.finalized_events: continue
             signatures = self.guard_signatures[event_id]
             positive_signatures = sum(1 for sig in signatures.values() if sig is True)

             if positive_signatures >= self.guard_threshold:
                 self.finalized_events.add(event_id)
                 newly_finalized_ids.append(event_id)
                 report_step = self.event_first_reported_step.get(event_id, step_num)
                 latency = step_num - report_step
                 self.confirmation_latencies.append(latency)
                 is_fabricated = event_id.startswith("fake-")
                 representative_report = self.pending_reports[event_id][0]
                 amount = representative_report.data.get('amount', 0)

                 if is_fabricated:
                     self.stats["fabricated_events_finalized"] += 1
                     self.stats["attack_impact_value"] += amount
                 else:
                     source_chain = self.blockchains.get(representative_report.source_chain_id)
                     actual_event = source_chain.get_event(event_id) if source_chain else None
                     if actual_event and actual_event.is_valid and actual_event.data == representative_report.data:
                         self.stats["valid_events_finalized"] += 1
                     else:
                         print(f"  ⚠️ WARNING: Finalized event {event_id[:8]} seems invalid/mismatched despite signatures! Data: {representative_report.data}")
                         self.stats["fabricated_events_finalized"] += 1 # Count as bad finalization
                         self.stats["attack_impact_value"] += amount

        # 4. Clean up finalized events from pending reports
        for event_id in newly_finalized_ids:
            if event_id in self.pending_reports:
                del self.pending_reports[event_id]


    def report_results(self):
        """Calculates and prints the final statistics including new metrics."""
        print("\n--- Simulation Results ---")
        print(f"Total Valid Events Created: {self.stats['valid_events_created']}")
        print(f"Total Fabricated Events Reported (Attempts): {self.stats['fabricated_events_reported']}")
        print("-" * 20)
        print(f"Valid Events Finalized (Correctly Processed): {self.stats['valid_events_finalized']}")
        print(f"Fabricated Events Finalized (Successful Attacks): {self.stats['fabricated_events_finalized']}")
        print("-" * 20)

        correctly_rejected_fraudulent = self.stats['fabricated_events_reported'] - self.stats['fabricated_events_finalized']
        print(f"Detection Rate (Correctly Rejected Fraudulent): {correctly_rejected_fraudulent}")
        false_positives = self.stats['valid_events_created'] - self.stats['valid_events_finalized']
        print(f"False Positives (Valid Events Rejected): {false_positives}")

        if self.stats['fabricated_events_reported'] > 0:
            false_acceptance_rate = (self.stats['fabricated_events_finalized'] / self.stats['fabricated_events_reported']) * 100
            print(f"False Acceptance Rate: {self.stats['fabricated_events_finalized']}/{self.stats['fabricated_events_reported']} = {false_acceptance_rate:.2f}%")
        else:
            print("False Acceptance Rate: N/A (No fraudulent events reported)")

        if self.confirmation_latencies:
            avg_latency = statistics.mean(self.confirmation_latencies)
            min_latency = min(self.confirmation_latencies)
            max_latency = max(self.confirmation_latencies)
            print(f"Event Confirmation Latency (steps):")
            print(f"  Average: {avg_latency:.2f}")
            print(f"  Min: {min_latency}")
            print(f"  Max: {max_latency}")
        else:
            print("Event Confirmation Latency: N/A (No events finalized)")

        print(f"Attack Impact Score (Total Value of Finalized Fraudulent Events): {self.stats['attack_impact_value']}")
        print("--- End of Report ---")