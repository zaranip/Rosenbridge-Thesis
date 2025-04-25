import matplotlib.pyplot as plt
import networkx as nx
import hashlib
import random

# Define total number of Guards
total_guards = 10
guards = [f'Guard {i+1}' for i in range(total_guards)]

# Parameters for committee selection
committee_size = 4
threshold = 3  # Minimum signatures required

# Simulate VRF using hash function for committee selection
def vrf_select_committee(guards, seed, committee_size):
    hashed_guards = []
    for guard in guards:
        combined = (guard + seed).encode('utf-8')
        hash_digest = hashlib.sha256(combined).hexdigest()
        hashed_guards.append((guard, hash_digest))
    # Sort based on hash to simulate randomness
    sorted_guards = sorted(hashed_guards, key=lambda x: x[1])
    committee = [guard for guard, _ in sorted_guards[:committee_size]]
    return committee

# Simulate transaction verification process
def simulate_verification(committee, threshold):
    # Randomly decide which committee members approve the transaction
    approvals = random.sample(committee, k=threshold)
    return approvals

# Visualization
def visualize_committee(guards, committee, approvals):
    G = nx.DiGraph()

    # Add all guards
    for guard in guards:
        G.add_node(guard, color='lightgray')

    # Highlight committee members
    for member in committee:
        G.nodes[member]['color'] = 'skyblue'

    # Highlight approvals
    for approver in approvals:
        G.nodes[approver]['color'] = 'green'

    # Add transaction node
    G.add_node('Transaction', color='orange')

    # Connect approvers to transaction
    for approver in approvals:
        G.add_edge(approver, 'Transaction')

    # Draw the graph
    colors = [G.nodes[node]['color'] for node in G.nodes()]
    pos = nx.spring_layout(G, seed=42)
    plt.figure(figsize=(10, 6))
    nx.draw(G, pos, with_labels=True, node_color=colors, node_size=1500, font_size=10, arrows=True)
    plt.title('Multi-Signature Verification with Randomized Committees')
    plt.show()

# Simulation parameters
seed = 'blockchain_state_seed'  # This would be dynamic in a real scenario

# Select committee using VRF simulation
committee = vrf_select_committee(guards, seed, committee_size)

# Simulate verification
approvals = simulate_verification(committee, threshold)

# Visualize the process
visualize_committee(guards, committee, approvals)
