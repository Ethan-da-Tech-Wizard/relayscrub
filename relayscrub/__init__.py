# Program: relayscrub - __init__.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Package front door for relayscrub: re-exports the scrubber (scrub.py) and untrusted-reply fencer (inbound.py) functions as the public API.

"""RelayScrub: Zero-Dependency, Offline Deterministic Privacy Scrubber & Untrusted LLM Content Fencing Framework for AI Agents.

Clean public API exports:
- scrub_outbound: Pure stdlib deterministic outbound prompt scrubber.
- restore_inbound: Swap restorable placeholders (<HOST-n>, <PATH-n>) back to local values.
- ingest_untrusted_reply: Nonce fencing, HTML defanging, prompt injection detection, and <think> separation.
- make_fence: Generates tamper-evident cryptographic nonce fences.
"""

# Pull the outbound privacy-scrubbing tools up to the package level, so users can write `from relayscrub import scrub_outbound`.
from .scrub import (
    scrub_outbound,
    restore_inbound,
    scrub_with_map,
    normalise,
    RelayMap,
    ScrubError,
    Detector,
    load_names,
)
# Pull the inbound untrusted-reply tools up to the package level too.
from .inbound import (
    ingest_untrusted_reply,
    ingest,
    make_fence,
    defang,
    extract_items,
    render_table,
)

# Package version string.
__version__ = "1.0.0"

# The names that `from relayscrub import *` exposes (the public API).
__all__ = [
    "scrub_outbound",
    "restore_inbound",
    "ingest_untrusted_reply",
    "make_fence",
    "ingest",
    "defang",
    "extract_items",
    "render_table",
    "scrub_with_map",
    "normalise",
    "RelayMap",
    "ScrubError",
    "Detector",
    "load_names",
    "__version__",
]
