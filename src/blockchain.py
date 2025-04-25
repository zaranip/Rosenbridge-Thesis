import uuid
from datatypes import Event

class SimpleBlockchain:
    """A simplified representation of a blockchain holding actual events."""
    def __init__(self, chain_id):
        self.chain_id = chain_id
        self.events = {}  # event_id -> Event
        # print(f"Blockchain '{self.chain_id}' initialized.")

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