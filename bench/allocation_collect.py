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
"""

import argparse
import datetime
import json
import pathlib
import platform
import sys

TARGETS = ["native", "wasip2", "wasip3", "emscripten"]
KEPT = {"argon2id", "scrypt", "sodium_init", "hkdf", "pbkdf2"}


def parse(path):
    """The records of one output file, as dictionaries."""
    cases = []
    for line in path.read_text().splitlines():
        if not line.startswith("record "):
            continue
        fields = dict(token.split("=", 1) for token in line.split()[1:])
        cases.append(fields)
    return cases


def collect(lanes):
    cases = []
    counted = {}
    for target, directory in lanes:
        for output in sorted(pathlib.Path(directory).rglob("allocation*.output")):
            if "no_exceptions" in output.name:
                continue
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
        data_path.write_text(json.dumps(collect(lanes), indent=2) + "\n")
    data = json.loads(data_path.read_text())
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
