#!/usr/bin/env python3
# Copyright (c) 2026 WebCpp.org
#
# Distributed under the Boost Software License, Version 1.0. (See
# accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt)

"""Measures bench/pbkdf2_sha512.cpp on each target and bench/timing.cpp natively, and renders
their data.

    collect.py --exe native=<path> --exe wasip2=<path> ... --invocations 5 \
        --timing <path> \
        --data doc/measurements.throughput.json --page doc/performance.adoc

Run from the superproject's root (the launchers' paths, tools/boost/asio-wasip2/run.sh and
its wasip3 twin, are relative to it), with the programs bench/Jamfile builds at
variant=release optimization=speed (`b2 libs/hash/bench//pbkdf2_sha512` on each target and
`b2 libs/hash/bench//timing` natively); --data and --page are relative to the same root, as
libs/hash/doc/... . `--timing` alone, without `--exe`, measures the guard and keeps the data's
throughput; `--exe` alone measures the throughput and keeps the data's guard.

The page is built only from release builds: a program whose build directory, b2's
bench/<toolset>/<variant>/..., is not variant=release, or does not say, is refused before
anything runs, and `--render-only` refuses data whose build, or whose guard's build, is not
BUILD.

Each case (a variant on a target) is run INVOCATIONS times, round-robin over the
cases so that a change of load on the shared machine falls on all of them alike;
each invocation derives the key three times and reports its median. The data
holds, per case, every invocation's median, their median, and the minimum and
maximum of every single run. A time never fails this script: only a wrong key,
or a program that does not run, does. `--render-only` rewrites the page from
the data.

The timing guard's cost (webcpp::secure::timing_guard, secure's guard, which every keyed function
holds and which sets 64-bit ARM's DIT where the CPU has it) is `timing --measure`'s one line:
whether the guard sets DIT on this machine, and the nanoseconds a guard adds to a call entered from
a thread whose DIT is clear, from one where it is already set, and a disengaged guard's (an unkeyed
call of a function keyed by its arguments), each the median of five runs of 10^7 guards minus an
empty loop's, with the fastest and slowest run. The data keeps it under "timing_guard" with the
date, the machine and the load (every date of the data is UTC's); the page renders it as a
paragraph and a table after the throughput. A line or a "timing_guard" that is not the form this
script writes (an older program's, a key missing or of another type) is refused with a message
naming what is wrong, before anything is written. `--provisional` marks the guard's figures as
provisional, measured on a shared, loaded machine and to be measured again in a final pass on a
quiet one, which the page says; measuring the guard without it clears the mark. `--exe` alone
keeps the data's guard when the data is what this script writes, and otherwise replaces the data,
saying the guard was not kept.
"""

import argparse
import datetime
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

# What the page is built from, and only from: bench/Jamfile's pbkdf2_sha512 and timing, at
# variant=release.
BUILD = "variant=release optimization=speed"
RELEASE_ONLY = (
    "the page is built only from release builds: bench/Jamfile's pbkdf2_sha512 and timing at "
    + BUILD
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
    """Exits naming each program not built at variant=release, before anything runs; exes maps
    a target, or "timing" for the guard's program, to its path."""
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
        "date": utc_today(),
        "machine": machine(),
        "load_average_before_after": [list(loads[0]), list(loads[1])],
        "loaded": peak > cores,
        "loaded_rule": "the larger of the two 1-minute load averages exceeds the core count",
        "build": BUILD,
        "cases": out,
    }


NUMBER = (int, float)
# bench/timing.cpp's line, and the "timing_guard" this script writes from it: each key's type, or
# the shape of a nested object.
TIMING_LINE_SHAPE = {"dit": bool, "clear": NUMBER, "set": NUMBER, "disengaged": NUMBER,
                     "clear_fastest": NUMBER, "clear_slowest": NUMBER, "set_fastest": NUMBER,
                     "set_slowest": NUMBER, "disengaged_fastest": NUMBER,
                     "disengaged_slowest": NUMBER, "iterations": int, "runs": int,
                     "target": str, "compiler": str}
TIMING_SHAPE = {"date": str, "build": str, "target": str, "compiler": str, "iterations": int,
                "runs": int, "dit": bool, "provisional": bool,
                "machine": {"cpu": str, "architecture": str, "cores": int, "os": str},
                "load_average_before_after": [[NUMBER]],
                **{f"{part}{spread}_ns": NUMBER for part in ("clear", "set", "disengaged")
                   for spread in ("", "_fastest", "_slowest")}}


def wrong(value, shape, where):
    """The first place in value that shape requires and value lacks or holds otherwise, named as
    a path from where; None when value has the shape. A one-element list is a non-empty list of
    that shape; a bool is never a number."""
    if isinstance(shape, dict):
        if not isinstance(value, dict):
            return f"{where} (not an object)"
        for key, inner in shape.items():
            if key not in value:
                return f"{where}.{key} (missing)"
            found = wrong(value[key], inner, f"{where}.{key}")
            if found is not None:
                return found
        return None
    if isinstance(shape, list):
        if not isinstance(value, list) or not value:
            return f"{where} (not a list, or empty)"
        return next((found for index, item in enumerate(value)
                     if (found := wrong(item, shape[0], f"{where}[{index}]")) is not None), None)
    types = shape if isinstance(shape, tuple) else (shape,)
    if isinstance(value, bool) and bool not in types:
        return where
    return None if isinstance(value, types) else where


def utc_today():
    """Today's date in UTC, the date every measurement of the page states."""
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def measure_timing(exe, provisional):
    """The guard's cost, timing --measure's line, natively, with when, where and under what load
    it was measured; exits naming what is wrong when the program fails or its line is not the
    form this script reads."""
    command = [exe, "--measure"]
    loads = [os.getloadavg()]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    loads.append(os.getloadavg())
    if done.returncode != 0:
        sys.exit(f"collect.py: timing --measure: exit {done.returncode}\n"
                 f"{done.stdout}{done.stderr}")
    lines = done.stdout.strip().splitlines()
    try:
        line = json.loads(lines[-1]) if lines else None
    except ValueError:
        line = None
    found = wrong(line, TIMING_LINE_SHAPE, "line") if line is not None else "line (not JSON)"
    # TIMING_LINE_SHAPE is an object's, so wrong finds nothing only in a dict; the isinstance
    # states that to the type checker.
    if found is not None or not isinstance(line, dict):
        printed = lines[-1] if lines else ""
        sys.exit(f"collect.py: timing --measure printed {printed!r}, which is not the form "
                 f"collect.py reads: {found} is wrong; build bench/Jamfile's timing again from "
                 "this tree")
    return {
        "measurement": "the nanoseconds webcpp::secure::timing_guard adds to a call, "
                       "bench/timing.cpp",
        "date": utc_today(),
        "machine": {
            "cpu": sysctl("machdep.cpu.brand_string") or platform.processor() or platform.machine(),
            "architecture": platform.machine(),
            "cores": os.cpu_count() or 1,
            "os": f"{platform.system()} {platform.release()}",
        },
        "load_average_before_after": [list(loads[0]), list(loads[1])],
        "build": BUILD,
        "target": line["target"],
        "compiler": line["compiler"],
        "iterations": line["iterations"],
        "runs": line["runs"],
        "dit": line["dit"],
        **{f"{part}{spread}_ns": line[f"{part}{spread}"]
           for part in ("clear", "set", "disengaged") for spread in ("", "_fastest", "_slowest")},
        "provisional": provisional,
    }


def fmt_load(load):
    return "/".join(f"{x:.0f}" for x in load)


def fmt_ns(value):
    """Nanoseconds as the page shows them: one decimal, a figure that rounds to zero or below it
    shown as 0.0, the empty loop's noise."""
    return "0.0" if round(value, 1) <= 0 else f"{value:.1f}"


# What the page says above the guard's table when its figures are provisional (--provisional).
PROVISIONAL = (
    "NOTE: these figures are provisional. They were measured on a shared machine under load "
    "(the load averages above), and are measured again in a final measurement pass on a quiet "
    "machine, once the work in progress has merged; read them as an upper bound."
)


def render_timing(timing):
    """The guard's paragraph and table, from the data's "timing_guard", or the line saying it is
    not measured yet."""
    lines = [
        "[#hash-performance-timing]",
        "=== The timing guard's cost",
        "",
        "Every keyed function (a MAC, a key derivation, a password hash, a keyed mode of",
        "BLAKE2b or BLAKE3) runs inside `webcpp::secure::timing_guard`, webcpp::secure's",
        "guard, which on 64-bit ARM under macOS, iOS, Linux, Android and Windows, where the",
        "CPU has FEAT_DIT, sets DIT (data-independent timing) for the call and restores the",
        "thread's state after it (<<hash-backends-dit>>): one `mrs`, and where DIT was clear,",
        "two `msr` each followed by an `isb`. Elsewhere (x86, WebAssembly, ARM64EC) it",
        "executes no instruction. A function keyed by its arguments, called without a key,",
        "holds a disengaged guard, which reads its flag and does nothing else.",
        "",
    ]
    if timing is None:
        return lines + ["Not measured yet.", ""]
    machine_info = timing["machine"]
    sets = ("The guard sets DIT on this machine." if timing["dit"] else
            "The guard does not set DIT on this machine (no FEAT_DIT, or a target it does not "
            "cover): every row is the loop's noise.")
    load = timing["load_average_before_after"]
    lines += [
        f"Measured natively on {timing['date']} (UTC) on {machine_info['cpu']}",
        f"({machine_info['architecture']}), {machine_info['os']}, built with {timing['build']}",
        f"by {timing['compiler']} (bench/timing.cpp): each row is the median of",
        f"{timing['runs']} runs of {timing['iterations']:,} guards around a store, with the",
        "fastest and slowest run beside it, each minus the median of the same loop without the",
        "guard, in nanoseconds per call; a figure that rounds to zero or below, the loop's",
        "noise, shows as 0.0.",
        f"{sets} The machine's 1, 5 and 15 minute load averages were {fmt_load(load[0])}",
        f"before and {fmt_load(load[1])} after, on {machine_info['cores']} cores.",
        "",
    ]
    if timing["provisional"]:
        lines += [PROVISIONAL, ""]
    rows = (
        ("clear", "clear, as a program that sets nothing has it",
         "reads DIT, sets it, and clears it on the way out"),
        ("set", "already set, by the program or by an outer guard",
         "reads DIT and leaves it set"),
        ("disengaged", "any: a function keyed by its arguments, called without a key",
         "reads its flag and does nothing else"),
    )
    lines += [
        '[cols="2,4,1,1,1",options="header"]',
        "|===",
        "| The thread's DIT on entry | What the guard does | Median (ns) | Fastest (ns) "
        "| Slowest (ns)",
    ]
    for part, entry, does in rows:
        lines += [
            "",
            f"| {entry}",
            f"| {does}",
            f"| {fmt_ns(timing[part + '_ns'])}",
            f"| {fmt_ns(timing[part + '_fastest_ns'])}",
            f"| {fmt_ns(timing[part + '_slowest_ns'])}",
        ]
    lines += ["|===", ""]
    return lines


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
        "== Performance",
        "",
        "PBKDF2-HMAC-SHA-512's throughput per backend, and what the timing guard adds to a",
        "keyed call, each measured from release builds.",
        "",
        "[#hash-performance-pbkdf2]",
        "=== PBKDF2-HMAC-SHA-512 throughput",
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
    lines += render_timing(data.get("timing_guard"))
    with open(page, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def release_data(path):
    """The data at path and None, or None and what is wrong with it: it cannot be read, or it, or
    its guard's measurement, was not built at BUILD or is not the form this script writes."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as error:
        return None, (f"{path} cannot be read ({error}); --timing alone and --render-only read "
                      "the data that --exe wrote")
    if not isinstance(data, dict) or data.get("build") != BUILD:
        build = data.get("build") if isinstance(data, dict) else None
        return None, f"{path} was measured with build {build}, not {BUILD}: {RELEASE_ONLY}"
    timing = data.get("timing_guard")
    if timing is not None:
        if not isinstance(timing, dict) or timing.get("build") != BUILD:
            build = timing.get("build") if isinstance(timing, dict) else None
            return None, (f"{path}'s timing guard was measured with build {build}, not {BUILD}: "
                          f"{RELEASE_ONLY}")
        found = wrong(timing, TIMING_SHAPE, "data.timing_guard")
        if found is not None:
            return None, (f"{path} is not the data collect.py writes: {found} is wrong; measure "
                          "the guard again with --timing")
    return data, None


def read_release_data(path):
    """The data at path; exits naming what is wrong with it (release_data)."""
    data, fault = release_data(path)
    if data is None:
        sys.exit(f"collect.py: {fault}")
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Measures bench/pbkdf2_sha512.cpp on each target and bench/timing.cpp.")
    parser.add_argument("--exe", action="append", default=[], metavar="TARGET=PATH")
    parser.add_argument("--invocations", type=int, default=5)
    parser.add_argument("--data", required=True)
    parser.add_argument("--page", required=True)
    parser.add_argument("--timing", metavar="PATH",
                        help="bench/Jamfile's timing at variant=release, run natively")
    parser.add_argument("--provisional", action="store_true",
                        help="with --timing: mark the guard's figures as measured under load, to "
                             "be measured again")
    parser.add_argument("--render-only", action="store_true")
    args = parser.parse_args()
    if args.provisional and args.timing is None:
        sys.exit("collect.py: --provisional marks the guard's figures: give it with --timing")
    if args.render_only:
        data = read_release_data(args.data)
    else:
        exes = dict(item.split("=", 1) for item in args.exe)
        if not exes and args.timing is None:
            sys.exit("collect.py: nothing to measure: give --exe, --timing or --render-only")
        check_release({**exes, **({"timing": args.timing} if args.timing else {})})
        if exes:
            data = measure(exes, args.invocations)
            # The guard's cost is kept until it is measured again; data this script cannot keep
            # is replaced by the new throughput, without a guard, and says so.
            if args.timing is None and Path(args.data).exists():
                kept, fault = release_data(args.data)
                if fault is not None:
                    print(f"collect.py: the guard is not kept: {fault}", file=sys.stderr)
                elif kept is not None and kept.get("timing_guard") is not None:
                    data["timing_guard"] = kept["timing_guard"]
        elif Path(args.data).exists():
            data = read_release_data(args.data)
        else:
            sys.exit(f"collect.py: {args.data} does not exist; --timing alone keeps the data's "
                     "throughput, which --exe writes")
        if args.timing is not None:
            data["timing_guard"] = measure_timing(args.timing, args.provisional)
        with open(args.data, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
    render(data, args.page)


if __name__ == "__main__":
    main()
