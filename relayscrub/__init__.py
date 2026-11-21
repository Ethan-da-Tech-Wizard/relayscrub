# ==============================================================================
# Program: __init__.py (relayscrub package)
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Top-level package exports for RelayScrub privacy scrubber & fencer.
#          Provides offline, standard-library-only privacy scrubbing
#          and untrusted LLM content fencing for autonomous AI agents.
#          Exports:
#            - scrub_outbound: Outbound prompt privacy sanitizer
#            - restore_inbound: Reversible placeholder substitution for hosts/paths
#            - ingest_untrusted_reply: Inbound content fencer & prompt injection scanner
#            - make_fence: Cryptographic nonce fence builder
# ==============================================================================

"""RelayScrub: an experimental offline, stdlib-only scrubber for secrets and personal data in prompts, plus fencing for untrusted LLM replies.

Clean public API exports:
- scrub_outbound: Pure stdlib deterministic outbound prompt scrubber.
- restore_inbound: Swap restorable placeholders (<HOST-n>, <PATH-n>) back to local values.
- ingest_untrusted_reply: Nonce fencing, HTML defanging, prompt injection detection, and <think> separation.
- make_fence: Generates tamper-evident cryptographic nonce fences.
"""

# Outbound side (scrub.py): scrubbing, restoring placeholders, and the supporting types.
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
# Inbound side (inbound.py): fencing and classifying untrusted model replies.
from .inbound import (
    ingest_untrusted_reply,
    ingest,
    make_fence,
    defang,
    extract_items,
    render_table,
)

# Package version; keep in sync with setup.py and pyproject.toml.
__version__ = "1.0.0"

# Explicit public API for 'from relayscrub import *'.
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
