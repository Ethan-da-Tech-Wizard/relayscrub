# ==============================================================================
# Program: basic_scrub.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Educational Example: Deterministic Privacy Scrubbing & Reversible Restoration.
#          Demonstrates how to scrub sensitive credentials (AWS keys, OpenAI keys,
#          passwords, private IPs, MAC addresses, emails, and filesystem paths)
#          from agent prompts before external API transmission, audit redactions
#          without leaking secrets, and safely restore harmless paths using RelayMap.
# ==============================================================================

from relayscrub import scrub_outbound, scrub_with_map, restore_inbound, RelayMap


def main():
    """Execute end-to-end outbound privacy scrubbing and inbound restoration demo."""
    print("=== RelayScrub: Basic Outbound Privacy Scrubbing Demo ===\n")

    # Sample prompt containing a mixture of benign text and high-risk secrets
    # Every secret below is fake and for demonstration only.
    sample_prompt = """
    Please help debug this script running on worker-node-01.
    Database configuration:
    - Host: 192.168.1.45 (internal interface: 00:1A:2B:3C:4D:5E)
    - Admin email: security-admin@internal-corp.test
    - Config file: /Users/alice/projects/backend/config.json
    - AWS S3 backup bucket access key: AKIAIOSFODNN7EXAMPLE
    - OpenAI translation key: sk-live998234abcfed0192837465019283
    - Database password: pass=SuperSecretPassword123!

    Error log:
    Connection timed out while connecting to 10.0.0.12:5432 from /home/deploy/.pgpass.
    """

    print("--- 1. Original Unscrubbed Prompt ---")
    print(sample_prompt.strip())
    print()

    # Step 1: Create a local, in-memory RelayMap for reversible identifiers
    relay_map = RelayMap()

    # Step 2: Perform deterministic outbound scrubbing
    # scrub_outbound returns (None, report) on failure - the demo stops rather than printing raw input.
    clean_text, report = scrub_outbound(sample_prompt, mapping=relay_map)

    print("--- 2. Scrubbed Prompt (Safe for External LLM API) ---")
    if clean_text is not None and report["ok"]:
        print(clean_text.strip())
    else:
        print(f"[BLOCKED] Scrubbing failed closed: {report.get('reason')}")
        return

    print("\n--- 3. Redaction Audit Report (Safe for Logging) ---")
    print(f"Status: OK = {report['ok']}")
    print(f"Redaction Counts: {report['counts']}")
    print(f"Total Redacted Items: {report['total']}")
    print(f"Placeholders Escaped: {report['placeholders_escaped']}")
    print("Note: The report contains ONLY counts and category tags - never raw secrets.")

    print("\n--- 4. Simulated LLM Response with Reversible Restoration ---")
    simulated_llm_reply = (
        "Based on your configuration, the timeout connecting to <IP-1> indicates "
        "that firewall rules on <IP-2> may be blocking port 5432. "
        "Check permissions on file <PATH-1> and <PATH-2>."
    )
    print("LLM Response Received:")
    print(simulated_llm_reply)

    # Step 3: Restore benign paths while keeping credentials and IPs masked
    restored_reply = restore_inbound(simulated_llm_reply, relay_map)
    print("\nRestored Response (Benign paths restored, secrets/IPs preserved as placeholders):")
    print(restored_reply)
    print("\nNotice that paths (/Users/alice/... and /home/deploy/...) were restored,")
    print("while IP addresses, passwords, and API keys remain safe placeholders.")


if __name__ == "__main__":
    main()
