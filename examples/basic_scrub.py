# Program: relayscrub - basic_scrub.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Runnable demo that scrubs a sample prompt full of fake secrets with scrub_outbound, prints an audit report, and restores only the harmless paths in a pretend reply.

"""Educational example: deterministic privacy scrubbing with reversible restoration of paths.

Shows how credentials, IPs, MACs, emails and paths are scrubbed from a prompt before it
leaves the machine, how the audit report avoids leaking secrets, and how RelayMap restores
harmless paths in the reply."""

# Import the public API from the relayscrub package.
from relayscrub import scrub_outbound, scrub_with_map, restore_inbound, RelayMap


def main():
    """Execute end-to-end outbound privacy scrubbing and inbound restoration demo."""
    # Everything printed below walks through the demo step by step.
    print("=== RelayScrub: Basic Outbound Privacy Scrubbing Demo ===\n")

    # Sample prompt containing a mixture of benign text and high-risk secrets
    # The sample text. Every secret in it is made-up example data.
    sample_prompt = """
    Please help debug this script running on worker-node-01.
    Database configuration:
    - Host: 192.168.1.45 (internal interface: 00:00:00:00:00:00)
    - Admin email: security-admin@internal-corp.test
    - Config file: /Users/alice/projects/backend/config.json
    - AWS S3 backup bucket access key: AKIAIOSFODNN7EXAMPLE
    - OpenAI translation key: sk-live998234abcfed0192837465019283
    - Database password: pass=SuperSecretPassword123!

    Error log:
    Connection timed out while connecting to 10.0.0.12:5432 from /home/deploy/.pgpass.
    """

    # Show the input as written.
    print("--- 1. Original Unscrubbed Prompt ---")
    print(sample_prompt.strip())
    print()

    # Step 1: Create a local, in-memory RelayMap for reversible identifiers
    relay_map = RelayMap()

    # Step 2: Perform deterministic outbound scrubbing
    # Returns (clean text or None, report). None means the scrubber failed closed.
    clean_text, report = scrub_outbound(sample_prompt, mapping=relay_map)

    print("--- 2. Scrubbed Prompt (Safe for External LLM API) ---")
    # Only use the text if scrubbing succeeded and passed verification.
    if clean_text is not None and report["ok"]:
        print(clean_text.strip())
    else:
        print(f"[BLOCKED] Scrubbing failed closed: {report.get('reason')}")
        return

    # The report holds only counts and categories, never the secret values.
    print("\n--- 3. Redaction Audit Report (Safe for Logging) ---")
    print(f"Status: OK = {report['ok']}")
    print(f"Redaction Counts: {report['counts']}")
    print(f"Total Redacted Items: {report['total']}")
    print(f"Placeholders Escaped: {report['placeholders_escaped']}")
    print("Note: The report contains ONLY counts and category tags - never raw secrets.")

    print("\n--- 4. Simulated LLM Response with Reversible Restoration ---")
    # Pretend reply from an outside model; it refers to placeholders like <IP-1> instead of real values.
    simulated_llm_reply = (
        "Based on your configuration, the timeout connecting to <IP-1> indicates "
        "that firewall rules on <IP-2> may be blocking port 5432. "
        "Check permissions on file <PATH-1> and <PATH-2>."
    )
    print("LLM Response Received:")
    print(simulated_llm_reply)

    # Step 3: Restore benign paths while keeping credentials and IPs masked
    # Swap <HOST-n>/<PATH-n> back to real values locally; IPs, keys and passwords are never restored.
    restored_reply = restore_inbound(simulated_llm_reply, relay_map)
    print("\nRestored Response (Benign paths restored, secrets/IPs preserved as placeholders):")
    print(restored_reply)
    print("\nNotice that paths (/Users/alice/... and /home/deploy/...) were restored,")
    print("while IP addresses, passwords, and API keys remain safe placeholders.")


# Run the demo only when this file is executed directly, not when imported.
if __name__ == "__main__":
    main()
