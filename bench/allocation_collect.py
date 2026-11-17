#!/usr/bin/env python3
# Copyright (c) 2026 WebCpp.org
#
# Distributed under the Boost Software License, Version 1.0. (See
# accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt)

"""Collects the allocation tests' records and renders the table of doc/allocation.adoc.

    allocation_collect.py --lane native=<build dir> --lane wasip2=<build dir> ... \
        --data doc/measurements.allocation.json --page doc/allocation.adoc
    allocation_collect.py --render-only --data ... --page ...
    allocation_collect.py --check --data ... --page ...

Every `record key=value ...` line that test allocation and test allocation_openssl print
(allocation.output and allocation_openssl.output under a lane's build directory) becomes one
case of the data file, shaped like doc/measurements.throughput.json's: operation, backend,
target, implementation and the counts. The page's table, between the `tag::table[]` and
`end::table[]` lines, is rendered from the data and never typed; --check fails when the page
differs from what the data renders.

The table is built only from release builds: the counting programs are bench/Jamfile's
allocation_release and allocation_openssl_release (`b2 libs/hash/bench//allocation_release
libs/hash/bench//allocation_openssl_release`, at variant=release, one build directory per
target), and an output whose build directory, b2's bench/<name>.test/<toolset>/<variant>/..., is not
variant=release, or does not say (the lanes' test/ directories included), is refused before
anything is written. The data records the build and each target's toolset, and `--render-only` and
`--check` refuse data whose build is not variant=release. The ordinary allocation tests of the
lanes keep their variant and are never collected.
"""

import argparse
import datetime
import json
import pathlib
import platform
import sys

TARGETS = ["native", "wasip2", "wasip3", "emscripten"]
# What the table is built from, and only from: bench/Jamfile's allocation_release and
# allocation_openssl_release, which fix variant=release themselves.
BUILD = "variant=release"
RELEASE_ONLY = (
    "the table is built only from release builds: bench/Jamfile's allocation_release and "
    "allocation_openssl_release at " + BUILD
)
KEPT = {"argon2id", "scrypt", "sodium_init", "hkdf", "pbkdf2"}


def build_of(output):
    """(toolset, variant) of an output as b2's build directory names them,
    bench/<name>.test/<toolset>/<variant>/...;
    None when its path does not say."""
    parts = output.resolve().parts
    if "bench" not in parts:
        return None
    last = len(parts) - 1 - parts[::-1].index("bench")
    after = parts[last + 1 :]
    if after and after[0].endswith(".test"):
        after = after[1:]  # b2's directory of the run target, bench/<name>.test/
    return (after[0], after[1]) if len(after) > 2 else None


def check_release(outputs):
    """Exits naming each output not built at variant=release, before anything is written."""
    others = []
    for target, output in outputs:
        build = build_of(output)
        if build is None:
            others.append(
                "%s=%s is not in b2's bench/<name>.test/<toolset>/<variant>/..., so its "
                "variant cannot be read" % (target, output)
            )
        elif build[1] != "release":
            others.append("%s=%s was built at variant=%s" % (target, output, build[1]))
    if others:
        sys.exit("allocation_collect.py: " + ", ".join(others) + ": " + RELEASE_ONLY)


def check_data(path, data):
    """Exits when the data was not built at variant=release."""
    if data.get("build") != BUILD:
        sys.exit(
            "allocation_collect.py: %s was built with %s, not %s: %s"
            % (path, data.get("build"), BUILD, RELEASE_ONLY)
        )


def parse(path):
    """The records of one output file, as dictionaries."""
    cases = []
    for line in path.read_text().splitlines():
        if not line.startswith("record "):
            continue
        fields = dict(token.split("=", 1) for token in line.split()[1:])
        cases.append(fields)
    return cases


def outputs_of(lanes):
    """The (target, output) pairs of the lanes' build directories: every program's output file,
    the exceptions-off twins left out."""
    return [
        (target, output)
        for target, directory in lanes
        for output in sorted(
            pathlib.Path(directory).rglob("allocation*.output"),
            key=lambda path: ("openssl" in path.name, path.name),
        )
        if "no_exceptions" not in output.name
    ]


def collect(outputs):
    cases = []
    counted = {}
    toolsets = {}
    for target, output in outputs:
        toolsets[target] = build_of(output)[0]
        for record in parse(output):
            if record["operation"] == "counter":
                counted[target] = record["c_counted"] == "1"
            elif record["operation"] in KEPT:
                case = {
                    "operation": record["operation"],
                    "backend": record["backend"],
                    "target": target,
                    "implementation": "backends::" + record["backend"],
                    "operator_new": int(record["new"]),
                }
                if "hmac" in record:
                    case["hmac"] = record["hmac"]
                    case["call"] = int(record["call"])
                    case["openssl_allocations"] = int(record["openssl"])
                else:
                    case["c_allocator_calls"] = int(record["c"])
                    case["c_allocator_counted"] = record["counted"] == "1"
                cases.append(case)
    return {
        "measurement": "allocations per call, native with the C allocator counted where it can be",
        "date": datetime.date.today().isoformat(),
        "build": BUILD,
        "toolsets": toolsets,
        "machine": {"os": platform.platform(), "cpu": platform.processor()},
        "c_allocator_counted": counted,
        "cases": cases,
    }


def render(data):
    rows = []
    by_target = {t: [c for c in data["cases"] if c["target"] == t] for t in TARGETS}
    for target in TARGETS:
        for c in by_target[target]:
            if c["operation"] in ("argon2id", "scrypt", "sodium_init"):
                counted = "C library calls: %d" % c["c_allocator_calls"]
                if not c["c_allocator_counted"]:
                    counted = "C library: not counted"
                rows.append((c["operation"], c["backend"], target, str(c["operator_new"]), counted))
        for op in ("hkdf", "pbkdf2"):
            mine = [c for c in by_target[target] if c["operation"] == op]
            if not mine:
                continue

            def at(hmac, call):
                return str(
                    next(
                        c["openssl_allocations"]
                        for c in mine
                        if c["hmac"] == hmac and c["call"] == call
                    )
                )

            detail = "OpenSSL: %s first call (hmac_sha2_256), " % at("hmac_sha2_256", 1)
            detail += "%s first call (hmac_sha2_512), " % at("hmac_sha2_512", 1)
            detail += "%s steady state" % at("hmac_sha2_512", 2)
            rows.append((op, "openssl", target, "0", detail))
    lines = [
        '[cols="1,1,1,1,3",options="header"]',
        "|===",
        "| Operation | Backend | Target | `operator new` | The C library's own allocations",
        "",
    ]
    for row in rows:
        lines.append("| `%s` | `%s` | %s | %s | %s" % row)
    lines.append("|===")
    return "\n".join(lines) + "\n"


def splice(page_text, table):
    begin = "// tag::table[]\n"
    end = "// end::table[]\n"
    head, rest = page_text.split(begin)
    _, tail = rest.split(end)
    return head + begin + table + end + tail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lane", action="append", default=[], metavar="TARGET=DIR")
    ap.add_argument("--data", required=True)
    ap.add_argument("--page", required=True)
    ap.add_argument("--render-only", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    data_path = pathlib.Path(args.data)
    page_path = pathlib.Path(args.page)
    if not (args.render_only or args.check):
        lanes = [tuple(lane.split("=", 1)) for lane in args.lane]
        outputs = outputs_of(lanes)
        check_release(outputs)
        data_path.write_text(json.dumps(collect(outputs), indent=2) + "\n")
    data = json.loads(data_path.read_text())
    check_data(data_path, data)
    page = page_path.read_text()
    new = splice(page, render(data))
    if args.check:
        if new != page:
            print("doc/allocation.adoc differs from doc/measurements.allocation.json")
            return 1
        return 0
    page_path.write_text(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
