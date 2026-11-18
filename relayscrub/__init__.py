# ==============================================================================
# Program: __init__.py (relayscrub package)
# Programmer: Ethan-da-Tech-Wizard
# Course: CIS 156 / Advanced Systems
# Last Modified: November 18, 2026
# Purpose: Top-level package exports for RelayScrub privacy scrubber & fencer.
#          Provides zero-dependency, offline deterministic privacy scrubbing
#          and untrusted LLM content fencing for autonomous AI agents.
#          Exports:
#            - scrub_outbound: Outbound prompt privacy sanitizer
#            - restore_inbound: Reversible placeholder substitution for hosts/paths
#            - ingest_untrusted_reply: Inbound content fencer & prompt injection scanner
#            - make_fence: Cryptographic nonce fence builder
# ==============================================================================

"""RelayScrub: Zero-Dependency, Offline Deterministic Privacy Scrubber & Untrusted LLM Content Fencing Framework for AI Agents.

Clean public API exports:
- scrub_outbound: Pure stdlib deterministic outbound prompt scrubber.
- restore_inbound: Swap restorable placeholders (<HOST-n>, <PATH-n>) back to local values.
- ingest_untrusted_reply: Nonce fencing, HTML defanging, prompt injection detection, and <think> separation.
- make_fence: Generates tamper-evident cryptographic nonce fences.
"""

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
from .inbound import (
    ingest_untrusted_reply,
    ingest,
    make_fence,
    defang,
    extract_items,
    render_table,
)

__version__ = "1.0.0"

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
