"""Inject a labelled, synthetic intrusion scenario into the LANL auth dataset.

The input format is one successful authentication per line: time,user,computer.
The implementation is streaming: even the full dataset is never loaded into RAM.
"""

from __future__ import annotations

import argparse
import bz2
import csv
import heapq
import json
import os
import random
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, TextIO


PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
OUTPUT_DIR = PROJECT_DIR / "output"
SUPPORTED_INPUT_SUFFIXES = {".bz2", ".txt", ".csv"}


@dataclass(frozen=True, order=True)
class AuthEvent:
    timestamp: int
    user: str
    computer: str
    phase: str = ""
    reason: str = ""


@dataclass
class DatasetStats:
    records: int
    first_timestamp: int
    last_timestamp: int
    user_counts: Counter[str]
    computer_counts: Counter[str]
    user_computers: dict[str, set[str]]
    user_first_timestamp: dict[str, int]
    user_last_timestamp: dict[str, int]


def open_text(path: Path, mode: str, compresslevel: int = 9) -> TextIO:
    """Open plain text or bzip2 based on the file suffix."""
    if path.suffix.lower() == ".bz2":
        return bz2.open(
            path, mode + "t", encoding="utf-8", newline="", compresslevel=compresslevel
        )
    return path.open(mode, encoding="utf-8", newline="")


def parse_record(line: str, line_number: int) -> tuple[int, str, str]:
    parts = line.rstrip("\r\n").split(",")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid record at line {line_number}: expected 3 comma-separated fields"
        )
    try:
        timestamp = int(parts[0])
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp at line {line_number}: {parts[0]!r}") from exc
    return timestamp, parts[1], parts[2]


def scan_dataset(path: Path, progress_every: int) -> DatasetStats:
    users: Counter[str] = Counter()
    computers: Counter[str] = Counter()
    user_computers: dict[str, set[str]] = {}
    user_first_timestamp: dict[str, int] = {}
    user_last_timestamp: dict[str, int] = {}
    records = 0
    first_timestamp: int | None = None
    last_timestamp = -1

    with open_text(path, "r") as source:
        for records, line in enumerate(source, 1):
            timestamp, user, computer = parse_record(line, records)
            # There are only thousands of identifiers but tens of millions of
            # records. Interning keeps the per-user relationship map compact.
            user = sys.intern(user)
            computer = sys.intern(computer)
            if timestamp < last_timestamp:
                raise ValueError(
                    f"Input is not sorted: timestamp {timestamp} follows {last_timestamp} "
                    f"at line {records}"
                )
            if first_timestamp is None:
                first_timestamp = timestamp
            last_timestamp = timestamp
            users[user] += 1
            computers[computer] += 1
            user_computers.setdefault(user, set()).add(computer)
            user_first_timestamp.setdefault(user, timestamp)
            user_last_timestamp[user] = timestamp
            if progress_every and records % progress_every == 0:
                print(f"[scan] {records:,} records", file=sys.stderr)

    if records == 0 or first_timestamp is None:
        raise ValueError("Input dataset is empty")
    return DatasetStats(
        records,
        first_timestamp,
        last_timestamp,
        users,
        computers,
        user_computers,
        user_first_timestamp,
        user_last_timestamp,
    )


def ranked_names(counter: Counter[str], *, most_common: bool) -> list[str]:
    """Return deterministic frequency ordering (identifier breaks ties)."""
    return [
        name
        for name, _ in sorted(
            counter.items(), key=lambda item: ((-item[1] if most_common else item[1]), item[0])
        )
    ]


def spread(start: int, end: int, count: int) -> list[int]:
    if count <= 0:
        return []
    if count == 1:
        return [start]
    width = max(0, end - start)
    return [start + (width * index // (count - 1)) for index in range(count)]


def select_narrow_accounts(stats: DatasetStats, count: int) -> list[str]:
    """Choose active, long-lived accounts with narrow normal host profiles."""
    midpoint_time = stats.first_timestamp + (
        stats.last_timestamp - stats.first_timestamp
    ) // 2
    minimum_events = max(20, stats.records // 100_000)

    def candidates(max_hosts: int) -> list[str]:
        return [
            user
            for user, count in stats.user_counts.items()
            if count >= minimum_events
            and 2 <= len(stats.user_computers[user]) <= max_hosts
            and stats.user_first_timestamp[user] < midpoint_time
            and stats.user_last_timestamp[user] > midpoint_time
        ]

    pool = candidates(8) or candidates(15)
    ordered = sorted(
        pool,
        key=lambda user: (
            abs(len(stats.user_computers[user]) - 3),
            -stats.user_counts[user],
            user,
        ),
    )
    for user in ranked_names(stats.user_counts, most_common=True):
        if user not in ordered:
            ordered.append(user)
        if len(ordered) >= count:
            break
    return ordered[:count]


def build_scenario(
    anchor: int,
    last_timestamp: int,
    stats: DatasetStats,
    seed: int,
    intensity: int,
    requested_duration: int,
    requested_automation_duration: int,
    automation_interval: int,
    automation_period: int,
    automation_hosts_per_burst: int,
) -> tuple[list[AuthEvent], dict[str, object]]:
    """Create takeover -> lateral movement -> escalation -> automation."""
    if len(stats.user_counts) < 4 or len(stats.computer_counts) < 12:
        raise ValueError("Dataset needs at least 4 users and 12 computers for this scenario")

    rng = random.Random(seed)
    central_hosts = ranked_names(stats.computer_counts, most_common=True)
    rare_hosts = ranked_names(stats.computer_counts, most_common=False)

    narrow_accounts = select_narrow_accounts(stats, 4)
    victim = narrow_accounts[0]
    secondary_users = narrow_accounts[1:4]
    victim_normal_hosts = stats.user_computers[victim]
    rare_hosts = [host for host in rare_hosts if host not in victim_normal_hosts]
    lateral_count = min(len(rare_hosts), 60 + 30 * intensity)
    lateral_hosts = rare_hosts[:lateral_count]
    high_value_hosts = [host for host in central_hosts if host not in lateral_hosts][:5]
    if len(high_value_hosts) < 5:
        high_value_hosts.extend(
            host for host in central_hosts if host not in high_value_hosts
        )
        high_value_hosts = high_value_hosts[:5]
    pivot = lateral_hosts[0]

    available = last_timestamp - anchor
    if available < 24:
        raise ValueError("Not enough timestamp range after the midpoint to inject the scenario")
    # Leave at least one second for the persistence campaign on short fixtures.
    intrusion_duration = min(requested_duration, available - 1)
    intrusion_duration = max(12, intrusion_duration)

    phase1_start = anchor + max(1, intrusion_duration * 2 // 100)
    phase2_start = anchor + intrusion_duration * 25 // 100
    phase2_end = anchor + intrusion_duration * 55 // 100
    phase3_start = anchor + intrusion_duration * 68 // 100
    phase3_end = anchor + intrusion_duration * 95 // 100

    events: list[AuthEvent] = []
    takeover_hosts = lateral_hosts[: min(len(lateral_hosts), 24 + 12 * intensity)]
    # The first malicious second is intentionally unmistakable: one account
    # with a historically narrow profile authenticates to dozens of new hosts.
    for host in takeover_hosts:
        events.append(
            AuthEvent(
                phase1_start,
                victim,
                host,
                "account_takeover",
                "victim simultaneously authenticates to many previously unseen hosts",
            )
        )

    phase2_times = spread(phase2_start, phase2_end, len(lateral_hosts) * 2)
    shuffled_hosts = lateral_hosts[:]
    rng.shuffle(shuffled_hosts)
    for index, timestamp in enumerate(phase2_times):
        events.append(
            AuthEvent(
                timestamp,
                victim,
                shuffled_hosts[index % len(shuffled_hosts)],
                "lateral_movement",
                "compromised account fans out across many endpoints",
            )
        )

    escalation_pairs: list[tuple[str, str, str]] = []
    for host in high_value_hosts:
        escalation_pairs.append((victim, host, "victim reaches a high-frequency target"))
    for user in secondary_users:
        escalation_pairs.append((user, pivot, "newly compromised account appears on pivot"))
        for host in high_value_hosts:
            escalation_pairs.append((user, host, "credential hopping to high-frequency target"))
        for host in lateral_hosts[: 4 + intensity * 2]:
            escalation_pairs.append((user, host, "secondary account joins endpoint fan-out"))

    for timestamp, (user, host, reason) in zip(
        spread(phase3_start, phase3_end, len(escalation_pairs)), escalation_pairs
    ):
        events.append(AuthEvent(timestamp, user, host, "privilege_escalation", reason))

    # Phase 4: a newly compromised account is used by automation. Exact timing
    # and simultaneous logons make this deliberately easy to discover through
    # periodicity and per-second fan-out analysis.
    automated_user = secondary_users[0]
    automation_pool = list(dict.fromkeys(lateral_hosts + high_value_hosts))
    automated_hosts = automation_pool[: min(automation_hosts_per_burst, len(automation_pool))]
    automation_start = anchor + intrusion_duration
    burst_times: list[int] = []
    automation_windows = 0
    window_start = automation_start
    while window_start < last_timestamp:
        window_end = min(window_start + requested_automation_duration, last_timestamp)
        window_bursts = list(
            range(window_start + automation_interval, window_end + 1, automation_interval)
        )
        if window_bursts:
            burst_times.extend(window_bursts)
            automation_windows += 1
        window_start += automation_period
    for timestamp in burst_times:
        for host in automated_hosts:
            events.append(
                AuthEvent(
                    timestamp,
                    automated_user,
                    host,
                    "automated_spread",
                    "periodic simultaneous authentication burst",
                )
            )

    events.sort(key=lambda event: (event.timestamp, event.user, event.computer))
    metadata: dict[str, object] = {
        "seed": seed,
        "victim_user": victim,
        "victim_baseline_event_count": stats.user_counts[victim],
        "victim_baseline_computers": sorted(victim_normal_hosts),
        "takeover_burst_size": len(takeover_hosts),
        "secondary_compromised_users": secondary_users,
        "pivot_computer": pivot,
        "high_value_computers": high_value_hosts,
        "lateral_computers": lateral_hosts,
        "automated_user": automated_user,
        "automated_computers": automated_hosts,
        "scenario_anchor": anchor,
        "intrusion_duration_seconds": intrusion_duration,
        "automation_window_duration_seconds": requested_automation_duration,
        "automation_interval_seconds": automation_interval,
        "automation_period_seconds": automation_period,
        "automation_campaign_start": automation_start,
        "automation_campaign_end": last_timestamp,
        "automation_campaign_duration_seconds": last_timestamp - automation_start,
        "automated_hosts_per_burst": len(automated_hosts),
        "automated_windows": automation_windows,
        "automated_bursts": len(burst_times),
        "last_injected_timestamp": events[-1].timestamp,
        "scenario_duration_seconds": last_timestamp - anchor,
        "injected_events": len(events),
    }
    return events, metadata


def write_ground_truth(path: Path, events: Iterable[AuthEvent]) -> None:
    with path.open("w", encoding="utf-8", newline="") as target:
        writer = csv.writer(target)
        writer.writerow(["time", "user", "computer", "phase", "reason"])
        for event in events:
            writer.writerow(
                [event.timestamp, event.user, event.computer, event.phase, event.reason]
            )


def inject_dataset(
    source_path: Path,
    output_path: Path,
    ground_truth_path: Path,
    metadata_path: Path,
    stats: DatasetStats,
    seed: int,
    intensity: int,
    duration: int,
    automation_duration: int,
    automation_interval: int,
    automation_period: int,
    automation_hosts: int,
    compresslevel: int,
    progress_every: int,
) -> dict[str, object]:
    midpoint = stats.records // 2
    # Keep the original suffix last so open_text applies the requested codec.
    output_tmp = output_path.with_name(
        output_path.stem + ".part" + output_path.suffix
    )
    last_written_timestamp = -1
    scenario_events: list[AuthEvent] | None = None
    scenario_metadata: dict[str, object] | None = None
    pending: list[AuthEvent] = []

    try:
        with open_text(source_path, "r") as source, open_text(
            output_tmp, "w", compresslevel
        ) as target:
            for line_number, line in enumerate(source, 1):
                timestamp, _, _ = parse_record(line, line_number)

                if scenario_events is None and line_number == midpoint + 1:
                    scenario_events, scenario_metadata = build_scenario(
                        timestamp,
                        stats.last_timestamp,
                        stats,
                        seed,
                        intensity,
                        duration,
                        automation_duration,
                        automation_interval,
                        automation_period,
                        automation_hosts,
                    )
                    pending = scenario_events[:]
                    heapq.heapify(pending)

                while pending and pending[0].timestamp <= timestamp:
                    event = heapq.heappop(pending)
                    target.write(f"{event.timestamp},{event.user},{event.computer}\n")
                    last_written_timestamp = event.timestamp

                target.write(line if line.endswith(("\n", "\r")) else line + "\n")
                last_written_timestamp = timestamp
                if progress_every and line_number % progress_every == 0:
                    print(f"[write] {line_number:,}/{stats.records:,} records", file=sys.stderr)

            while pending:
                event = heapq.heappop(pending)
                if event.timestamp < last_written_timestamp:
                    raise RuntimeError("Internal error: scenario event order was not preserved")
                target.write(f"{event.timestamp},{event.user},{event.computer}\n")
                last_written_timestamp = event.timestamp

        if scenario_events is None or scenario_metadata is None:
            raise RuntimeError("Could not anchor the scenario at the dataset midpoint")

        os.replace(output_tmp, output_path)
        write_ground_truth(ground_truth_path, scenario_events)
        metadata: dict[str, object] = {
            "input": str(source_path.resolve()),
            "output": str(output_path.resolve()),
            "original_records": stats.records,
            "unchanged_prefix_records": midpoint,
            "first_timestamp": stats.first_timestamp,
            "last_timestamp": stats.last_timestamp,
            **scenario_metadata,
        }
        metadata_path.write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        return metadata
    except BaseException:
        if output_tmp.exists():
            output_tmp.unlink()
        raise


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def discover_input(data_dir: Path) -> Path:
    """Select the only supported dataset file in data_dir."""
    if not data_dir.is_dir():
        raise ValueError(f"input directory does not exist: {data_dir}")
    candidates = sorted(
        path
        for path in data_dir.iterdir()
        if path.is_file() and path.suffix.lower() in SUPPORTED_INPUT_SUFFIXES
    )
    if not candidates:
        raise ValueError(
            f"no .bz2, .txt or .csv dataset found in input directory: {data_dir}"
        )
    if len(candidates) > 1:
        names = ", ".join(path.name for path in candidates)
        raise ValueError(
            f"multiple datasets found in {data_dir}: {names}; pass the input filename explicitly"
        )
    return candidates[0].resolve()


def resolve_in_directory(value: Path, directory: Path) -> Path:
    """Resolve an absolute path as-is, otherwise treat it as a name in directory."""
    return (value if value.is_absolute() else directory / value).resolve()


def default_output_name(source: Path) -> str:
    return source.stem + "-modified" + source.suffix


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inject an obvious, labelled intrusion scenario into LANL auth logs."
    )
    parser.add_argument(
        "input",
        type=Path,
        nargs="?",
        help="input filename in data/ (default: auto-detect the only dataset there)",
    )
    parser.add_argument(
        "output",
        type=Path,
        nargs="?",
        help="output filename in output/ (default: <input>-modified)",
    )
    parser.add_argument(
        "--ground-truth", type=Path, help="CSV path (default: <output>.ground_truth.csv)"
    )
    parser.add_argument(
        "--metadata", type=Path, help="JSON path (default: <output>.metadata.json)"
    )
    parser.add_argument("--seed", type=int, default=20261113)
    parser.add_argument(
        "--intensity", type=int, choices=range(1, 6), default=2, metavar="1..5",
        help="fan-out size; 2 is intentionally easy to spot",
    )
    parser.add_argument(
        "--duration", type=positive_int, default=6 * 60 * 60, metavar="SECONDS",
        help="takeover/lateral/escalation duration (default: 21600, i.e. 6 hours)",
    )
    parser.add_argument(
        "--automation-duration",
        type=positive_int,
        default=3 * 60 * 60,
        metavar="SECONDS",
        help="automated-spread duration after the intrusion (default: 10800, i.e. 3 hours)",
    )
    parser.add_argument(
        "--automation-interval",
        type=positive_int,
        default=5 * 60,
        metavar="SECONDS",
        help="seconds between simultaneous authentication bursts (default: 300)",
    )
    parser.add_argument(
        "--automation-period",
        type=positive_int,
        default=24 * 60 * 60,
        metavar="SECONDS",
        help="time between starts of automated windows (default: 86400, i.e. daily)",
    )
    parser.add_argument(
        "--automation-hosts",
        type=positive_int,
        default=18,
        metavar="N",
        help="number of computers in every automated burst (default: 18)",
    )
    parser.add_argument("--compresslevel", type=int, choices=range(1, 10), default=9)
    parser.add_argument(
        "--progress-every", type=int, default=5_000_000, metavar="N",
        help="print progress every N input records; 0 disables it",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.automation_interval > args.automation_duration:
        print(
            "error: automation interval cannot be longer than its daily window",
            file=sys.stderr,
        )
        return 2
    if args.automation_duration > args.automation_period:
        print(
            "error: automation window cannot be longer than the period between windows",
            file=sys.stderr,
        )
        return 2
    try:
        source = (
            discover_input(DATA_DIR)
            if args.input is None
            else resolve_in_directory(args.input, DATA_DIR)
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output = (
        resolve_in_directory(args.output, OUTPUT_DIR)
        if args.output is not None
        else (OUTPUT_DIR / default_output_name(source)).resolve()
    )
    ground_truth = (
        resolve_in_directory(args.ground_truth, OUTPUT_DIR)
        if args.ground_truth is not None
        else Path(str(output) + ".ground_truth.csv")
    )
    metadata = (
        resolve_in_directory(args.metadata, OUTPUT_DIR)
        if args.metadata is not None
        else Path(str(output) + ".metadata.json")
    )

    if not source.is_file():
        print(f"error: input does not exist or is not a file: {source}", file=sys.stderr)
        return 2
    if source == output:
        print("error: input and output must be different files", file=sys.stderr)
        return 2
    destinations = [output, ground_truth, metadata]
    if len(set(destinations)) != len(destinations):
        print("error: output, ground-truth and metadata paths must differ", file=sys.stderr)
        return 2
    existing = [path for path in destinations if path.exists()]
    if existing:
        print(
            "error: refusing to overwrite existing file(s): "
            + ", ".join(str(path) for path in existing), file=sys.stderr,
        )
        return 2
    for path in destinations:
        path.parent.mkdir(parents=True, exist_ok=True)

    try:
        print("Scanning input (pass 1/2)...", file=sys.stderr)
        stats = scan_dataset(source, args.progress_every)
        print(
            f"Found {stats.records:,} records, {len(stats.user_counts):,} users and "
            f"{len(stats.computer_counts):,} computers.", file=sys.stderr,
        )
        print("Writing modified dataset (pass 2/2)...", file=sys.stderr)
        result = inject_dataset(
            source, output, ground_truth, metadata, stats, args.seed, args.intensity,
            args.duration, args.automation_duration, args.automation_interval,
            args.automation_period, args.automation_hosts, args.compresslevel,
            args.progress_every,
        )
    except (OSError, EOFError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        f"Done: injected {result['injected_events']} events after "
        f"{result['unchanged_prefix_records']:,} unchanged records.\n"
        f"Dataset: {output}\nGround truth: {ground_truth}\nMetadata: {metadata}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
