"""Cross-tool deduplication and correlation.

Dedup rules:
- Same CWE + same location type + same normalized location = duplicate.
  The first finding absorbs the second; correlated_tools records both.
- Same CWE + different location types (e.g. file vs URL) = correlated,
  not duplicate. Both survive; each gets the other's tool in correlated_tools.
- Findings with no CWE are never merged (no reliable correlation key).
"""

from normalizer.models import Finding


def _dedup_key(f: Finding) -> str | None:
    """Return the dedup key, or None if this finding cannot be deduped."""
    if not f.cwe:
        return None
    return f"{f.cwe}|{f.location_type.value}|{f.location}"


def _correlation_key(f: Finding) -> str | None:
    """Return a broader key for cross-type correlation (CWE only)."""
    if not f.cwe:
        return None
    return f.cwe


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Deduplicate and correlate findings.

    Returns (deduplicated_findings, merge_count).
    """
    seen: dict[str, Finding] = {}  # dedup_key -> primary finding
    merge_count = 0

    # Phase 1: exact dedup (same CWE + same location type + same location)
    surviving: list[Finding] = []
    for f in findings:
        key = _dedup_key(f)
        if key is None:
            # No CWE, keep as-is
            surviving.append(f)
            continue

        if key in seen:
            # Merge into existing finding
            existing = seen[key]
            if f.tool not in existing.correlated_tools and f.tool != existing.tool:
                existing.correlated_tools.append(f.tool)
            merge_count += 1
        else:
            seen[key] = f
            surviving.append(f)

    # Phase 2: cross-type correlation (same CWE, different location type)
    # Group surviving findings by CWE
    by_cwe: dict[str, list[Finding]] = {}
    for f in surviving:
        ck = _correlation_key(f)
        if ck:
            by_cwe.setdefault(ck, []).append(f)

    for cwe, group in by_cwe.items():
        if len(group) < 2:
            continue
        # Each finding in the group gets all other tools as correlated
        all_tools = {f.tool for f in group}
        for f in group:
            others = all_tools - {f.tool} - set(f.correlated_tools)
            f.correlated_tools.extend(sorted(others))

    # Sort by severity (critical first), then by CWE
    surviving.sort(key=lambda f: (f.severity_rank, f.cwe or "ZZZ"))

    return surviving, merge_count
