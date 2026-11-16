#!/usr/bin/env python3
# Copyright (c) 2026 WebCpp.org
#
# Distributed under the Boost Software License, Version 1.0. (See
# accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt)

"""Measures bench/pbkdf2_sha512.cpp on each target and renders its data.

    collect.py --exe native=<path> --exe wasip2=<path> ... --invocations 5 \
        --data doc/measurements.throughput.json --page doc/performance.adoc

Run from the superproject's root (the launchers' paths, tools/boost/asio-wasip2/run.sh and
its wasip3 twin, are relative to it), with the programs bench/Jamfile builds at
variant=release optimization=speed; --data and --page are relative to the same root, as
libs/hash/doc/... .

The table is built only from release builds: a program whose build directory, b2's
bench/<toolset>/<variant>/..., is not variant=release, or does not say, is refused before
anything runs, and `--render-only` refuses data whose build is not BUILD.

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
from pathlib import Path

# What the table is built from, and only from: bench/Jamfile's pbkdf2_sha512, at variant=release.
BUILD = "variant=release optimization=speed"
RELEASE_ONLY = (
    "the table is built only from release builds: bench/Jamfile's pbkdf2_sha512 at " + BUILD
)

LAUNCHERS = {
    "native": [],
    "wasip2": ["tools/boost/asio-wasip2/run.sh"],
    "wasip3": ["tools/boost/asio-wasip3/run.sh"],
    "emscripten": ["node"],
}
TARGETS = ["native", "wasip2", "wasip3", "emscripten"]
# Per variant (the program's argument): the library backend it measures, or None for the
# benchmark's own loop, and the implementation, which is the column of the page.
OPERATION = "pbkdf2"
HMAC = "hmac_sha2_512"
BACKENDS = {"hash2": "hash2", "openssl": "openssl", "sodium-hmac": None}
IMPLEMENTATIONS = {
    "hash2": "backends::hash2",
    "openssl": "backends::openssl",
    "sodium-hmac": "sodium crypto_auth_hmacsha512 loop",
}
VARIANTS = list(BACKENDS)


def variant_of(exe):
    """The variant b2 built exe at, as its build directory names it, bench/<toolset>/<variant>/...;
    None when its path does not say."""
    parts = Path(exe).resolve().parts
    if "bench" not in parts:
        return None
    last = len(parts) - 1 - parts[::-1].index("bench")
    after = parts[last + 1:]
    return after[1] if len(after) > 2 else None


def check_release(exes):
    """Exits naming each program not built at variant=release, before anything runs."""
    others = []
    for target, exe in exes.items():
        variant = variant_of(exe)
        if variant is None:
            others.append(f"{target}={exe} is not in b2's bench/<toolset>/<variant>/..., so its "
                          "variant cannot be read")
        elif variant != "release":
            others.append(f"{target}={exe} was built at variant={variant}")
    if others:
        sys.exit("collect.py: " + ", ".join(others) + ": " + RELEASE_ONLY)


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


def variants_of(target, exe):
    """The variants the program was built with, which it lists without deriving a key."""
    command = LAUNCHERS[target] + [exe, "--list"]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        sys.exit(f"{target}: --list exit {done.returncode}\n{done.stdout}{done.stderr}")
    return done.stdout.split()


def measure(exes, invocations):
    cases = {}
    for target, exe in exes.items():
        for variant in variants_of(target, exe):
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
                "operation": OPERATION,
                "hmac": HMAC,
                "target": target,
                "backend": BACKENDS[variant],
                "implementation": IMPLEMENTATIONS[variant],
                "variant": variant,
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
    cores = os.cpu_count() or 1
    peak = max(loads[0][0], loads[1][0])
    return {
        "measurement": "pbkdf2-hmac-sha-512, 1,000,000 iterations, 64 bytes",
        "date": datetime.date.today().isoformat(),
        "machine": machine(),
        "load_average_before_after": [list(loads[0]), list(loads[1])],
        "loaded": peak > cores,
        "loaded_rule": "the larger of the two 1-minute load averages exceeds the core count",
        "build": BUILD,
        "cases": out,
    }


def fmt_load(load):
    return "/".join(f"{x:.0f}" for x in load)


def render(data, page):
    machine_info = data["machine"]
    cases = {(c["variant"], c["target"]): c for c in data["cases"]}
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
        "Each case is the median of its invocations' medians, with the fastest and slowest",
        "single run beside it: the spread is part of the result.",
        "",
    ]
    if data["loaded"]:
        load = data["load_average_before_after"]
        lines += [
            "WARNING: the machine was shared and loaded while this was measured (many builds",
            f"ran at once; 1, 5 and 15 minute load averages {fmt_load(load[0])} before and",
            f"{fmt_load(load[1])} after, on {machine_info['cores']} cores; rule: "
            f"{data['loaded_rule']}).",
            "Read the spread, not a single figure.",
            "",
        ]
    lines += [
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
                f"| {c['implementation']}",
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
    parser = argparse.ArgumentParser(description="Measures bench/pbkdf2_sha512.cpp on each target.")
    parser.add_argument("--exe", action="append", default=[], metavar="TARGET=PATH")
    parser.add_argument("--invocations", type=int, default=5)
    parser.add_argument("--data", required=True)
    parser.add_argument("--page", required=True)
    parser.add_argument("--render-only", action="store_true")
    args = parser.parse_args()
    if args.render_only:
        with open(args.data, encoding="utf-8") as f:
            data = json.load(f)
        if data.get("build") != BUILD:
            sys.exit(f"collect.py: {args.data} was measured with build {data.get('build')}, not "
                     f"{BUILD}: {RELEASE_ONLY}")
    else:
        exes = dict(item.split("=", 1) for item in args.exe)
        check_release(exes)
        data = measure(exes, args.invocations)
        with open(args.data, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
    render(data, args.page)


if __name__ == "__main__":
    main()
