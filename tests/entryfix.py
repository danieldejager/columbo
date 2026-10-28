"""Helpers to put the synthetic fixture entry and its bundle into a test repo."""
import shutil
from pathlib import Path

FIX = Path(__file__).resolve().parent / "fixtures"
NAME = "win11-fwon"


def add_entry(d, src=FIX / "pass", name=NAME):
    (d / "entries").mkdir(exist_ok=True)
    shutil.copy(src / (name + ".fp"), d / "entries")
    sc = src / (name + ".provenance.json")
    if sc.exists():
        shutil.copy(sc, d / "entries")


def add_bundle(d, label=NAME):
    dst = d / "bundles" / label
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(FIX / "bundles" / NAME, dst)
    if label != NAME:
        m = dst / "manifest.txt"
        m.write_text(m.read_text().replace("label=" + NAME, "label=" + label))
    return dst


def add_valid(d):
    add_entry(d)
    return add_bundle(d)
