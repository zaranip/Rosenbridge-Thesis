from collections import namedtuple

Event = namedtuple("Event", ["event_id", "source_chain_id", "target_chain_id", "data", "is_valid"])
ReportedEvent = namedtuple("ReportedEvent", ["event_id", "source_chain_id", "target_chain_id", "data", "reporter_id"])