"""Entries without a bundle: a closed list of exact names (one today) that
skip only the bundle link check and the run minimum. Every other check holds."""
import json
from pathlib import Path

from tools.checks import entry as E
from test_checks import repo, head, commit, run_on  # noqa: F401
import entryfix as EF

FIX = Path(__file__).resolve().parent / "fixtures" / "pass"


def add_named(d, name, runs=3, firewall="on", block_edit=None, side_edit=None):
    fp = (FIX / "win11-fwon.fp").read_text()
    fp = fp.replace("#@ name: win11-fwon", "#@ name: " + name)
    fp = fp.replace("Fingerprint win11-fwon", "Fingerprint " + name)
    fp = fp.replace("#@ runs: 6", "#@ runs: %d" % runs).replace("#@ firewall: on", "#@ firewall: " + firewall)
    if block_edit:
        fp = block_edit(fp)
    prov = {"name": name, "firewall": firewall, "runs": runs, "probe_version": "0.3.2", "derive_version": "0.3.2"}
    if side_edit:
        side_edit(prov)
    (d / "entries" / (name + ".fp")).write_text(fp)
    (d / "entries" / (name + ".provenance.json")).write_text(json.dumps(prov) + "\n")


def test_list_is_closed_and_exact():
    assert E.NO_BUNDLE_ENTRIES == ("ubuntu2404",)
    assert E.NO_BUNDLE_MIN_RUNS == 3


def test_ubuntu2404_passes_without_bundle(repo):
    base = head(repo)
    add_named(repo, "ubuntu2404")
    commit(repo)
    errors, _ = run_on(repo, base)
    assert errors == [], errors


def test_other_name_without_bundle_still_fails(repo):
    for name, fw in (("ws2022-fwon", "on"), ("ws2019-fwoff", "off")):
        base = head(repo)
        add_named(repo, name, runs=6, firewall=fw)
        commit(repo, name)
        errors, _ = run_on(repo, base)
        assert any("no bundle" in e for e in errors), (name, errors)


def test_other_name_with_three_runs_fails_run_minimum():
    fp = (FIX / "win11-fwon.fp").read_text().replace("#@ runs: 6", "#@ runs: 3")
    side = json.dumps({"name": "win11-fwon", "firewall": "on", "runs": 3,
                       "probe_version": "0.3.2", "derive_version": "0.3.2"})
    assert any("out of range" in e for e in E.check_entry("win11-fwon", fp, side))


def test_ubuntu2404_below_three_runs_fails():
    for runs in (1, 2):
        fp = (FIX / "win11-fwon.fp").read_text().replace("win11-fwon", "ubuntu2404").replace("#@ runs: 6", "#@ runs: %d" % runs)
        side = json.dumps({"name": "ubuntu2404", "firewall": "on", "runs": runs,
                           "probe_version": "0.3.2", "derive_version": "0.3.2"})
        assert any("out of range" in e for e in E.check_entry("ubuntu2404", fp, side))


def test_ubuntu2404_malformed_block_fails(repo):
    base = head(repo)
    add_named(repo, "ubuntu2404", block_edit=lambda t: t.replace("\nWIN(", "\nWINX("))
    commit(repo)
    errors, _ = run_on(repo, base)
    assert errors, errors


def test_ubuntu2404_mismatched_sidecar_fails(repo):
    base = head(repo)
    add_named(repo, "ubuntu2404", side_edit=lambda p: p.update(runs=4))
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("sidecar runs" in e for e in errors), errors


def test_ubuntu2404_wrong_firewall_fails(repo):
    base = head(repo)
    add_named(repo, "ubuntu2404", firewall="off")
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("firewall" in e for e in errors), errors


def test_ubuntu2404_sibling_check_still_applies(repo):
    EF.add_valid(repo)
    base = commit(repo, "base win11")
    add_named(repo, "ubuntu2404")
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("duplicate fingerprint of win11-fwon" in e for e in errors), errors


def test_ubuntu2404_with_bundle_in_pr_gets_link_check(repo):
    base = head(repo)
    add_named(repo, "ubuntu2404")
    EF.add_bundle(repo, "ubuntu2404")
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any(e.startswith("ubuntu2404: link:") for e in errors), errors
