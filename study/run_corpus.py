"""Run the static survey over each repository in a local corpus directory.

    python3 -I study/run_corpus.py corpus study/private/results.json

Reads source files only (via strangertest.source_audit). Run it with ``-I`` so
nothing in the cloned repositories can shadow a standard-library import. The
per-repository output names third-party projects, so it is written under
``study/private/`` (gitignored) and is for private disclosure only.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))

from strangertest.source_audit import survey  # noqa: E402


def main(argv):
    corpus, out_path = argv[1], argv[2]
    results = {}
    totals = {}
    print(f"{'repo':42} {'files':>6} {'handlers':>8} {'state':>6} {'flagged':>7}  net")
    for name in sorted(os.listdir(corpus)):
        path = os.path.join(corpus, name)
        if not os.path.isdir(path):
            continue
        report = survey(path)
        results[name] = report.to_dict(include_all=True)
        c = report.counts()
        for key, value in c.items():
            totals[key] = totals.get(key, 0) + value
        print(
            f"{name:42} {c['files_scanned']:>6} {c['handlers']:>8} "
            f"{c['handlers_touching_state']:>6} {c['flagged']:>7}  "
            f"{'yes' if report.network_hints else 'no'}"
        )
    print(
        f"{'TOTAL':42} {totals.get('files_scanned', 0):>6} {totals.get('handlers', 0):>8} "
        f"{totals.get('handlers_touching_state', 0):>6} {totals.get('flagged', 0):>7}"
    )
    with open(out_path, "w") as f:
        json.dump({"totals": totals, "repos": results}, f, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
