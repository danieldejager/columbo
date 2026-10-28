"""Bundle to entry link: re-run derive on the bundle runs committed in the
same PR and require the entry block to equal the result.

Rule (docs/check-rules.md): entry <name> is linked to bundle `<name>` and,
if present, bundle `<name>-restart`. Both must be changed in the same PR.
All run JSONs of the linked bundles are sorted by run id and passed to
tools/derive/derive.py; fields that vary between runs go through the same
rule tools/derive/build_db.py applies (SP and ISR become the min to max
range, any other varying field is refused). The rendered block, without
derive's comment lines, must equal the entry block byte for byte.
"""
import json
import os
import sys

_DERIVE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "derive")


def _derive_mods():
    if _DERIVE not in sys.path:
        sys.path.insert(0, _DERIVE)
    import derive as D  # noqa: E402
    import build_db as BD  # noqa: E402
    return D, BD


def derive_version():
    return _derive_mods()[0].__version__


def linked_labels(name):
    return (name, name + "-restart")


def derive_block(name, run_texts):
    """Return the personality block derive renders for these run JSON texts.
    Raise ValueError when the runs cannot be turned into one block."""
    D, BD = _derive_mods()
    docs = [json.loads(t) for t in run_texts]
    docs.sort(key=lambda d: str(d["run_id"]))
    result = D.derive(docs, os_name=name, os_build="")
    try:
        BD._resolve_fields(result["obs"])
    except BD.BuildError as e:
        raise ValueError(str(e))
    text = D.render_personality(result)
    return text[text.index("\nFingerprint ") + 1:]


def check_link(name, prov, block, bundles):
    """bundles: {label: {"manifest": dict, "runs": [run JSON text]}} for the
    bundles changed in this PR. Return a list of errors."""
    labels = [lb for lb in linked_labels(name) if lb in bundles]
    if name not in bundles:
        return ["link: no bundle %r changed in this PR; an entry needs its bundle in the same PR" % name]
    runs, errs = [], []
    for lb in labels:
        man = bundles[lb]["manifest"]
        if man.get("firewall") != prov.get("firewall"):
            errs.append("link: bundle %s firewall does not match the entry" % lb)
        for k in ("probe_version", "derive_version"):
            if man.get(k) != prov.get(k):
                errs.append("link: bundle %s %s does not match the entry" % (lb, k))
        runs += bundles[lb]["runs"]
    if str(len(runs)) != prov.get("runs"):
        errs.append("link: entry runs %s but linked bundles hold %d run files" % (prov.get("runs"), len(runs)))
    if prov.get("derive_version") != derive_version():
        errs.append("link: derive_version %s is not the vendored derive %s"
                    % (prov.get("derive_version"), derive_version()))
    try:
        want = derive_block(name, runs)
    except Exception as e:  # fail closed
        return errs + ["link: derive could not run on the bundle: %s" % type(e).__name__]
    if want != block:
        errs.append("link: entry block does not equal derive output for its bundle")
    return errs
