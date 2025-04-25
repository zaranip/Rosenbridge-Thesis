import random
import time

from simulation import RosenbridgeSimulation
import config

if __name__ == "__main__":
    sim = RosenbridgeSimulation()

    # Setup chains and participants using config values
    sim.setup(chain_ids=config.CHAIN_IDS)

    # Simulation Steps using config values
    print(f"\n--- Running Simulation ({config.NUM_SIMULATION_STEPS} steps) ---")
    for i in range(config.NUM_SIMULATION_STEPS):
        current_step = i + 1
        # Trigger some new valid events in each step
        for j in range(config.EVENTS_PER_STEP):
             # Ensure there are chains to choose from
             if not sim.blockchains:
                 print("Error: No blockchains initialized in simulation. Exiting loop.")
                 break
             source = random.choice(list(sim.blockchains.keys()))
             # Ensure there's a different chain available for target
             possible_targets = [c for c in sim.blockchains.keys() if c != source]
             if not possible_targets:
                 # print(f"Warning: Only one chain '{source}', cannot create cross-chain event.")
                 continue # Skip event creation if no valid target
             target = random.choice(possible_targets)
             sim.trigger_event(
                 source_chain_id=source,
                 target_chain_id=target,
                 data={"amount": random.randint(10, 1000), "tx_id": f"tx_{current_step}_{j}", "recipient": "valid_user"}
             )
        else: # Continue if inner loop wasn't broken
            # Run the watcher/guard logic for the step
            sim.run_simulation_step(current_step)
            continue
        break # Exit outer loop if inner loop was broken (due to no chains)

    sim.report_results()

    print("\nSimulation Finished.")