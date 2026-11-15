#!/usr/bin/env python3
# Copyright (c) 2026 WebCpp.org
#
# Distributed under the Boost Software License, Version 1.0. (See
# accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt)

"""Measures bench/pbkdf2_sha512.cpp on each target and renders its data.

    collect.py --exe native=<path> --exe wasip2=<path> ... --invocations 5 \
        --data doc/measurements.throughput.json --page doc/performance.adoc

Each case (a variant on a target) is run INVOCATIONS times, round-robin over the
cases so that a change of load on the shared machine falls on all of them alike;
each invocation derives the key three times and reports its median. The data
holds, per case, every invocation's median, their median, and the minimum and
maximum of every single run. A time never fails this script: only a wrong key,
or a program that does not run, does. `--render-only` rewrites the page from
the data.
"""

import argparse
import datetime
import json
import os
import platform
import subprocess
import sys

LAUNCHERS = {
    "native": [],
    "wasip2": ["tools/boost/asio-wasip2/run.sh"],
    "wasip3": ["tools/boost/asio-wasip3/run.sh"],
    "emscripten": ["node"],
}
TARGETS = ["native", "wasip2", "wasip3", "emscripten"]
VARIANTS = ["hash2", "openssl", "sodium-hmac"]
LABELS = {
    "hash2": "backends::hash2",
    "openssl": "backends::openssl",
    "sodium-hmac": "libsodium HMAC-SHA-512 in PBKDF2's loop",
}


def median(values):
    values = sorted(values)
    n = len(values)
    return values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2


def tool_version(command):
    try:
        out = subprocess.run(command, capture_output=True, text=True, check=False)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except (OSError, IndexError):
        return "unknown"


def sysctl(name):
    try:
        out = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True)
        return out.stdout.strip()
    except OSError:
        return ""


def machine():
    return {
        "cpu": sysctl("machdep.cpu.brand_string") or platform.processor(),
        "cores": os.cpu_count(),
        "memory_gib": int(sysctl("hw.memsize") or 0) // 2**30,
        "os": f"{platform.system()} {platform.release()}",
        "wasmtime": tool_version(["wasmtime", "--version"]),
        "node": tool_version(["node", "--version"]),
    }


def run_case(target, exe, variant):
    command = LAUNCHERS[target] + [exe, variant, "--runs", "3"]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        sys.exit(f"{target} {variant}: exit {done.returncode}\n{done.stdout}{done.stderr}")
    return json.loads(done.stdout.strip().splitlines()[-1])


def has_variant(target, exe, variant):
    command = LAUNCHERS[target] + [exe, variant, "--runs", "1"]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    return done.returncode != 2


def measure(exes, invocations):
    cases = {}
    for target, exe in exes.items():
        for variant in VARIANTS:
            if has_variant(target, exe, variant):
                cases[(target, variant)] = {"exe": exe, "results": []}
    loads = [os.getloadavg()]
    for _ in range(invocations):
        for (target, variant), case in cases.items():
            case["results"].append(run_case(target, case["exe"], variant))
    loads.append(os.getloadavg())
    out = []
    for (target, variant), case in cases.items():
        results = case["results"]
        for r in results:
            if not r["key_correct"]:
                sys.exit(f"{target} {variant}: a wrong key")
        medians = [r["median_ms"] for r in results]
        runs = [t for r in results for t in r["runs_ms"]]
        out.append(
            {
                "backend": variant,
                "target": target,
                "compiler": results[0]["compiler"],
                "iterations": results[0]["iterations"],
                "derived_bytes": 64,
                "invocations": len(results),
                "runs_per_invocation": len(results[0]["runs_ms"]),
                "invocation_medians_ms": medians,
                "median_ms": median(medians),
                "min_ms": min(runs),
                "max_ms": max(runs),
                "key_correct": True,
            }
        )
    return {
        "measurement": "pbkdf2-hmac-sha-512, 1,000,000 iterations, 64 bytes",
        "date": datetime.date.today().isoformat(),
        "machine": machine(),
        "load_average_before_after": [list(loads[0]), list(loads[1])],
        "shared_and_loaded": True,
        "note": "Measured on a shared machine under heavy load from many concurrent builds: "
        "read the spread, not a single figure. A time is a measurement, never a pass or fail.",
        "build": "variant=release optimization=speed",
        "cases": out,
    }


def fmt_load(load):
    return "/".join(f"{x:.0f}" for x in load)


def render(data, page):
    machine_info = data["machine"]
    cases = {(c["backend"], c["target"]): c for c in data["cases"]}
    lines = [
        "// Copyright (c) 2026 WebCpp.org",
        "//",
        "// Distributed under the Boost Software License, Version 1.0. (See",
        "// accompanying file LICENSE_1_0.txt or copy at",
        "// https://www.boost.org/LICENSE_1_0.txt)",
        "",
        "// Generated by bench/collect.py from doc/measurements.throughput.json: do not edit.",
        "",
        "[#hash-performance]",
        "== PBKDF2-HMAC-SHA-512 throughput",
        "",
        "How long each backend takes to derive 64 bytes by PBKDF2-HMAC-SHA-512 at 1,000,000",
        "iterations, on each target where the backend exists. The figure that matters to a",
        "person choosing a backend is how many password guesses an attacker (or a login) can",
        "afford per second, which is the reciprocal of these times.",
        "",
        f"Measured on {data['date']} on {machine_info['cpu']}, {machine_info['cores']} cores,",
        f"{machine_info['memory_gib']} GiB, {machine_info['os']}; WebAssembly under",
        f"{machine_info['wasmtime']} (wasip2, wasip3) and node {machine_info['node']}",
        f"(Emscripten); built with {data['build']}.",
        "",
        "WARNING: the machine was shared and loaded (many builds ran at once; load averages",
        f"{fmt_load(data['load_average_before_after'][0])} before and "
        f"{fmt_load(data['load_average_before_after'][1])}",
        f"after, on {machine_info['cores']} cores). Each case is the median of its invocations' medians, with the",
        "fastest and slowest single run beside it: the spread is the honest part of the table.",
        "",
        '[cols="2,1,1,1,1,3",options="header"]',
        "|===",
        "| Backend | Target | Median (ms) | Fastest run (ms) | Slowest run (ms) | Compiler",
    ]
    for variant in VARIANTS:
        for target in TARGETS:
            c = cases.get((variant, target))
            if c is None:
                continue
            lines += [
                "",
                f"| {LABELS[variant]}",
                f"| {target}",
                f"| {c['median_ms']:.0f}",
                f"| {c['min_ms']:.0f}",
                f"| {c['max_ms']:.0f}",
                f"| {c['compiler']}",
            ]
    lines += [
        "|===",
        "",
        "Every case derived the independent value (Python's hashlib.pbkdf2_hmac) on every run;",
        "backends::openssl does not exist on Emscripten; libsodium has no PBKDF2, so its row",
        "measures its HMAC-SHA-512 in PBKDF2's loop, written in the benchmark and never part of",
        "the library.",
        "",
    ]
    with open(page, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--exe", action="append", default=[], metavar="TARGET=PATH")
    parser.add_argument("--invocations", type=int, default=5)
    parser.add_argument("--data", required=True)
    parser.add_argument("--page", required=True)
    parser.add_argument("--render-only", action="store_true")
    args = parser.parse_args()
    if args.render_only:
        with open(args.data, encoding="utf-8") as f:
            data = json.load(f)
    else:
        exes = dict(item.split("=", 1) for item in args.exe)
        data = measure(exes, args.invocations)
        with open(args.data, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
    render(data, args.page)


if __name__ == "__main__":
    main()
