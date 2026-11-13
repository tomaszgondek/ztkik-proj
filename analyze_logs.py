"""Streaming anomaly analysis and self-contained HTML reporting for LANL auth logs.

This script intentionally does not read generator metadata or ground truth.  It
uses only the three public fields available to the analysing team:

    time,user,computer
"""

from __future__ import annotations

import argparse
import bz2
import heapq
import html
import json
import math
import os
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO


PROJECT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_DIR / "output"
SUPPORTED_SUFFIXES = {".bz2", ".txt", ".csv"}


@dataclass
class OnlineStats:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    @property
    def stddev(self) -> float:
        return math.sqrt(self.m2 / (self.count - 1)) if self.count > 1 else 0.0


@dataclass
class BurstStats:
    count: int = 0
    max_hosts: int = 0
    first_timestamp: int | None = None
    last_timestamp: int | None = None
    intervals: Counter[int] = field(default_factory=Counter)


@dataclass
class AnalysisResult:
    source: Path
    records: int
    first_timestamp: int
    last_timestamp: int
    user_count: int
    computer_count: int
    hourly: list[tuple[int, int, int]]
    anomalies: list[dict[str, object]]
    burst_stats: dict[str, BurstStats]
    burst_hour_counts: Counter[int]
    burst_edge_counts: Counter[tuple[str, str]]
    burst_samples: list[tuple[int, str, int, float]]
    total_bursts: int


def open_text(path: Path) -> TextIO:
    if path.suffix.lower() == ".bz2":
        return bz2.open(path, "rt", encoding="utf-8", newline="")
    return path.open("r", encoding="utf-8", newline="")


def parse_record(line: str, line_number: int) -> tuple[int, str, str]:
    parts = line.rstrip("\r\n").split(",")
    if len(parts) != 3:
        raise ValueError(
            f"invalid record at line {line_number}: expected time,user,computer"
        )
    try:
        timestamp = int(parts[0])
    except ValueError as exc:
        raise ValueError(f"invalid timestamp at line {line_number}: {parts[0]!r}") from exc
    return timestamp, parts[1], parts[2]


def discover_input(directory: Path) -> Path:
    candidates = sorted(
        path
        for path in directory.iterdir()
        if path.is_file()
        and path.suffix.lower() in SUPPORTED_SUFFIXES
        and "ground_truth" not in path.name
        and "metadata" not in path.name
    )
    modified = [path for path in candidates if "modified" in path.stem.lower()]
    if len(modified) == 1:
        return modified[0].resolve()
    if len(candidates) == 1:
        return candidates[0].resolve()
    if not candidates:
        raise ValueError(f"no modified .bz2, .txt or .csv log found in {directory}")
    raise ValueError(
        "multiple candidate logs found in output; pass the input filename explicitly: "
        + ", ".join(path.name for path in candidates)
    )


def resolve_in_output(value: Path) -> Path:
    return (value if value.is_absolute() else OUTPUT_DIR / value).resolve()


def keep_top(
    heap: list[tuple[float, int, dict[str, object]]],
    score: float,
    sequence: int,
    value: dict[str, object],
    limit: int,
) -> None:
    item = (score, sequence, value)
    if len(heap) < limit:
        heapq.heappush(heap, item)
    elif score > heap[0][0]:
        heapq.heapreplace(heap, item)


def analyze(
    source: Path,
    *,
    hour_seconds: int,
    min_burst_hosts: int,
    min_hourly_hosts: int,
    top_anomalies: int,
    max_burst_samples: int,
    progress_every: int,
) -> AnalysisResult:
    records = 0
    first_timestamp: int | None = None
    last_timestamp = -1
    computers: set[str] = set()
    baselines: dict[str, OnlineStats] = defaultdict(OnlineStats)

    current_hour: int | None = None
    hour_events = 0
    hour_users: dict[str, set[str]] = defaultdict(set)
    hourly: list[tuple[int, int, int]] = []
    anomaly_heap: list[tuple[float, int, dict[str, object]]] = []
    anomaly_sequence = 0

    current_timestamp: int | None = None
    timestamp_users: dict[str, set[str]] = defaultdict(set)
    burst_stats: dict[str, BurstStats] = defaultdict(BurstStats)
    burst_hour_counts: Counter[int] = Counter()
    burst_edge_counts: Counter[tuple[str, str]] = Counter()
    burst_samples: deque[tuple[int, str, int, float]] = deque(maxlen=max_burst_samples)
    total_bursts = 0

    def flush_timestamp() -> None:
        nonlocal total_bursts
        if current_timestamp is None:
            return
        for user, hosts in timestamp_users.items():
            if len(hosts) < min_burst_hosts:
                continue
            total_bursts += 1
            stats = burst_stats[user]
            stats.count += 1
            stats.max_hosts = max(stats.max_hosts, len(hosts))
            if stats.first_timestamp is None:
                stats.first_timestamp = current_timestamp
            if stats.last_timestamp is not None:
                stats.intervals[current_timestamp - stats.last_timestamp] += 1
            stats.last_timestamp = current_timestamp
            burst_hour_counts[(current_timestamp // hour_seconds) * hour_seconds] += 1
            baseline = baselines[user]
            relative_score = len(hosts) / max(1.0, baseline.mean) if baseline.count >= 6 else float(len(hosts))
            burst_samples.append((current_timestamp, user, len(hosts), relative_score))
            for host in hosts:
                burst_edge_counts[(user, host)] += 1
        timestamp_users.clear()

    def flush_hour() -> None:
        nonlocal anomaly_sequence
        if current_hour is None:
            return
        max_fanout = max((len(hosts) for hosts in hour_users.values()), default=0)
        hourly.append((current_hour, hour_events, max_fanout))
        for user, hosts in hour_users.items():
            fanout = len(hosts)
            baseline = baselines[user]
            deviation = max(baseline.stddev, 1.0)
            z_score = (fanout - baseline.mean) / deviation if baseline.count else 0.0
            # High absolute fan-out remains visible before enough history exists;
            # otherwise the user's own active-hour baseline drives the score.
            score = max(fanout / 2.0, z_score + math.log2(fanout + 1))
            is_candidate = fanout >= min_hourly_hosts and (
                fanout >= min_hourly_hosts * 3
                or (baseline.count >= 6 and z_score >= 3.0)
            )
            if is_candidate:
                anomaly_sequence += 1
                keep_top(
                    anomaly_heap,
                    score,
                    anomaly_sequence,
                    {
                        "timestamp": current_hour,
                        "user": user,
                        "unique_hosts": fanout,
                        "baseline_mean": baseline.mean,
                        "z_score": z_score,
                        "hosts": sorted(hosts)[:60],
                        "score": score,
                    },
                    top_anomalies,
                )
            baseline.update(float(fanout))
        hour_users.clear()

    with open_text(source) as handle:
        for records, line in enumerate(handle, 1):
            timestamp, user, computer = parse_record(line, records)
            if timestamp < last_timestamp:
                raise ValueError(
                    f"input is not time-sorted at line {records}: {timestamp} < {last_timestamp}"
                )
            if first_timestamp is None:
                first_timestamp = timestamp
            last_timestamp = timestamp
            computers.add(computer)

            if current_timestamp is None:
                current_timestamp = timestamp
            elif timestamp != current_timestamp:
                flush_timestamp()
                current_timestamp = timestamp
            timestamp_users[user].add(computer)

            event_hour = (timestamp // hour_seconds) * hour_seconds
            if current_hour is None:
                current_hour = event_hour
            elif event_hour != current_hour:
                flush_hour()
                current_hour = event_hour
                hour_events = 0
            hour_events += 1
            hour_users[user].add(computer)

            if progress_every and records % progress_every == 0:
                print(f"[analysis] {records:,} records", file=sys.stderr)

    if records == 0 or first_timestamp is None:
        raise ValueError("input dataset is empty")
    flush_timestamp()
    flush_hour()

    anomalies = [item[2] for item in sorted(anomaly_heap, reverse=True)]
    return AnalysisResult(
        source=source,
        records=records,
        first_timestamp=first_timestamp,
        last_timestamp=last_timestamp,
        user_count=len(baselines),
        computer_count=len(computers),
        hourly=hourly,
        anomalies=anomalies,
        burst_stats=dict(burst_stats),
        burst_hour_counts=burst_hour_counts,
        burst_edge_counts=burst_edge_counts,
        burst_samples=list(burst_samples),
        total_bursts=total_bursts,
    )


def format_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days:
        return f"{days} d {hours:02}:{minutes:02}:{seconds:02}"
    return f"{hours:02}:{minutes:02}:{seconds:02}"


def format_offset(timestamp: int) -> str:
    days, remainder = divmod(timestamp, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"D+{days} {hours:02}:{minutes:02}:{seconds:02}"


def downsample(points: list[tuple[int, int]], limit: int = 700) -> list[tuple[int, int]]:
    if len(points) <= limit:
        return points
    result: list[tuple[int, int]] = []
    step = len(points) / limit
    for index in range(limit):
        start = int(index * step)
        end = max(start + 1, int((index + 1) * step))
        chunk = points[start:end]
        result.append((chunk[len(chunk) // 2][0], max(value for _, value in chunk)))
    return result


def line_chart(
    points: list[tuple[int, int]], title: str, y_label: str, color: str = "var(--blue)"
) -> str:
    points = downsample(points)
    width, height = 1000, 290
    left, right, top, bottom = 76, 24, 30, 54
    plot_w, plot_h = width - left - right, height - top - bottom
    if not points:
        return f"<h3>{html.escape(title)}</h3><p>Brak danych.</p>"
    x_min, x_max = points[0][0], points[-1][0]
    y_max = max(value for _, value in points) or 1

    def x_pos(value: int) -> float:
        return left + (value - x_min) / max(1, x_max - x_min) * plot_w

    def y_pos(value: int) -> float:
        return top + plot_h - value / y_max * plot_h

    polyline = " ".join(f"{x_pos(x):.1f},{y_pos(y):.1f}" for x, y in points)
    grid = []
    for index in range(5):
        value = round(y_max * index / 4)
        y = y_pos(value)
        grid.append(
            f'<line x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}" '
            f'class="grid"/><text x="{left-10}" y="{y+4:.1f}" text-anchor="end">{value:,}</text>'
        )
    return f"""
    <section class="chart-section">
      <h3>{html.escape(title)}</h3>
      <svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}">
        <title>{html.escape(title)}</title>
        {''.join(grid)}
        <line x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}" class="axis"/>
        <line x1="{left}" y1="{top+plot_h}" x2="{width-right}" y2="{top+plot_h}" class="axis"/>
        <polyline points="{polyline}" fill="none" stroke="{color}" stroke-width="2"/>
        <text x="{left}" y="{height-18}">{html.escape(format_offset(x_min))}</text>
        <text x="{width-right}" y="{height-18}" text-anchor="end">{html.escape(format_offset(x_max))}</text>
        <text x="18" y="{top+plot_h/2}" transform="rotate(-90 18 {top+plot_h/2})" text-anchor="middle">{html.escape(y_label)}</text>
      </svg>
    </section>"""


def anomaly_bar_chart(anomalies: list[dict[str, object]], limit: int = 12) -> str:
    rows = anomalies[:limit]
    if not rows:
        return "<section><h3>Największe skoki fan-out</h3><p>Nie wykryto.</p></section>"
    width, left, right, row_h = 1000, 270, 40, 36
    height = 60 + len(rows) * row_h
    maximum = max(int(row["unique_hosts"]) for row in rows)
    elements = []
    for index, row in enumerate(rows):
        y = 38 + index * row_h
        value = int(row["unique_hosts"])
        bar_w = (width - left - right) * value / max(1, maximum)
        label = f"{row['user']} · {format_offset(int(row['timestamp']))}"
        elements.append(
            f'<text x="{left-12}" y="{y+16}" text-anchor="end">{html.escape(label)}</text>'
            f'<rect x="{left}" y="{y}" width="{bar_w:.1f}" height="22" rx="4" fill="var(--orange)">'
            f'<title>{html.escape(label)}: {value} unikalnych hostów</title></rect>'
            f'<text x="{left+bar_w+8:.1f}" y="{y+16}">{value}</text>'
        )
    return f"""
    <section class="chart-section">
      <h3>Największe godzinowe skoki fan-out</h3>
      <svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="Ranking godzinowych skoków liczby hostów">
        <title>Największe godzinowe skoki fan-out</title>{''.join(elements)}
      </svg>
    </section>"""


def periodic_findings(result: AnalysisResult) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for user, stats in result.burst_stats.items():
        if not stats.intervals:
            continue
        interval, repetitions = stats.intervals.most_common(1)[0]
        confidence = repetitions / max(1, stats.count - 1)
        if repetitions >= 3:
            findings.append(
                {
                    "user": user,
                    "bursts": stats.count,
                    "max_hosts": stats.max_hosts,
                    "interval": interval,
                    "repetitions": repetitions,
                    "confidence": confidence,
                    "first_timestamp": stats.first_timestamp,
                }
            )
    return sorted(
        findings,
        key=lambda item: (int(item["repetitions"]), float(item["confidence"]), int(item["bursts"])),
        reverse=True,
    )


def build_demo_result() -> AnalysisResult:
    """Create representative aggregates for previewing the report layout."""
    days = 30
    anchor = 15 * 86400
    hourly: list[tuple[int, int, int]] = []
    burst_hours: Counter[int] = Counter()
    for hour_index in range(days * 24):
        timestamp = hour_index * 3600
        hour_of_day = hour_index % 24
        business_load = 48_000 if 7 <= hour_of_day <= 18 else 19_000
        volume = business_load + round(3500 * math.sin(hour_index / 5.0))
        fanout = 7 + (hour_index % 4)
        if anchor + 3600 <= timestamp <= anchor + 4 * 3600:
            fanout = 36
        hourly.append((timestamp, volume, fanout))

    automated_user = "U2042"
    automated_hosts = [f"C{8000 + index}" for index in range(18)]
    burst_edge_counts: Counter[tuple[str, str]] = Counter(
        {(automated_user, host): 540 for host in automated_hosts}
    )
    burst_samples: list[tuple[int, str, int, float]] = []
    for day in range(15):
        window_start = anchor + 6 * 3600 + day * 86400
        for burst in range(36):
            timestamp = window_start + (burst + 1) * 300
            burst_samples.append((timestamp, automated_user, 18, 6.4))
            burst_hours[(timestamp // 3600) * 3600] += 1

    stats = BurstStats(
        count=540,
        max_hosts=18,
        first_timestamp=burst_samples[0][0],
        last_timestamp=burst_samples[-1][0],
        intervals=Counter({300: 525, 75900: 14}),
    )
    anomalies: list[dict[str, object]] = [
        {
            "timestamp": anchor + 2 * 3600,
            "user": "U100",
            "unique_hosts": 36,
            "baseline_mean": 3.2,
            "z_score": 21.4,
            "hosts": [f"C{7000 + index}" for index in range(36)],
            "score": 26.6,
        },
        {
            "timestamp": anchor + 6 * 3600,
            "user": automated_user,
            "unique_hosts": 18,
            "baseline_mean": 2.8,
            "z_score": 14.9,
            "hosts": automated_hosts,
            "score": 19.1,
        },
        {
            "timestamp": anchor + 4 * 3600,
            "user": "U311",
            "unique_hosts": 14,
            "baseline_mean": 2.1,
            "z_score": 10.8,
            "hosts": [f"C{8000 + index}" for index in range(14)],
            "score": 14.7,
        },
    ]
    return AnalysisResult(
        source=Path("<synthetic report preview — no ground truth>"),
        records=sum(count for _, count, _ in hourly) + 540 * 18,
        first_timestamp=0,
        last_timestamp=days * 86400 - 1,
        user_count=11_362,
        computer_count=22_284,
        hourly=hourly,
        anomalies=anomalies,
        burst_stats={automated_user: stats},
        burst_hour_counts=burst_hours,
        burst_edge_counts=burst_edge_counts,
        burst_samples=burst_samples,
        total_bursts=540,
    )


def network_graph(result: AnalysisResult, periodic: list[dict[str, object]]) -> str:
    suspicious_users: list[str] = []
    for finding in periodic[:6]:
        user = str(finding["user"])
        if user not in suspicious_users:
            suspicious_users.append(user)
    for anomaly in result.anomalies:
        user = str(anomaly["user"])
        if user not in suspicious_users:
            suspicious_users.append(user)
        if len(suspicious_users) == 6:
            break
    if not suspicious_users:
        return "<section><h3>Graf podejrzanych uwierzytelnień</h3><p>Brak krawędzi spełniających progi.</p></section>"

    per_user: dict[str, list[tuple[str, int]]] = {}
    selected_hosts: Counter[str] = Counter()
    for user in suspicious_users:
        edges = [
            (host, count)
            for (edge_user, host), count in result.burst_edge_counts.items()
            if edge_user == user
        ]
        edges.sort(key=lambda item: (-item[1], item[0]))
        per_user[user] = edges[:12]
        for host, count in edges[:12]:
            selected_hosts[host] += count
    hosts = [host for host, _ in selected_hosts.most_common(30)]
    if not hosts:
        # Fall back to hosts retained with hourly fan-out anomalies.
        hosts = list(
            dict.fromkeys(
                str(host)
                for anomaly in result.anomalies
                for host in list(anomaly["hosts"])[:8]
            )
        )[:30]

    width = 1000
    height = max(420, 80 + max(len(suspicious_users), len(hosts)) * 28)
    user_y = {
        user: 55 + index * (height - 110) / max(1, len(suspicious_users) - 1)
        for index, user in enumerate(suspicious_users)
    }
    host_y = {
        host: 55 + index * (height - 110) / max(1, len(hosts) - 1)
        for index, host in enumerate(hosts)
    }
    edges_svg: list[str] = []
    max_edge = max(result.burst_edge_counts.values(), default=1)
    for user in suspicious_users:
        for host, count in per_user.get(user, []):
            if host not in host_y:
                continue
            stroke_width = 1 + 5 * math.sqrt(count / max_edge)
            edges_svg.append(
                f'<line x1="220" y1="{user_y[user]:.1f}" x2="780" y2="{host_y[host]:.1f}" '
                f'stroke="var(--border)" stroke-width="{stroke_width:.1f}" opacity="0.65">'
                f'<title>{html.escape(user)} → {html.escape(host)}: {count} wykrytych serii</title></line>'
            )
    user_nodes = "".join(
        f'<circle cx="190" cy="{y:.1f}" r="9" fill="var(--orange)"/>'
        f'<text x="174" y="{y+4:.1f}" text-anchor="end">{html.escape(user)}</text>'
        for user, y in user_y.items()
    )
    host_nodes = "".join(
        f'<circle cx="810" cy="{y:.1f}" r="7" fill="var(--blue)"/>'
        f'<text x="826" y="{y+4:.1f}">{html.escape(host)}</text>'
        for host, y in host_y.items()
    )
    return f"""
    <section class="chart-section">
      <h3>Graf podejrzanych uwierzytelnień</h3>
      <p class="muted">Grubość krawędzi odpowiada liczbie równoczesnych serii. Pomarańczowe węzły to konta, niebieskie — komputery.</p>
      <svg class="network" viewBox="0 0 {width} {height}" role="img" aria-label="Graf podejrzanych relacji użytkownik-komputer">
        <title>Graf podejrzanych relacji użytkownik-komputer</title>
        {''.join(edges_svg)}{user_nodes}{host_nodes}
      </svg>
    </section>"""


def findings_table(periodic: list[dict[str, object]]) -> str:
    if not periodic:
        return "<p>Nie wykryto użytkownika z co najmniej trzema powtarzalnymi odstępami.</p>"
    rows = []
    for finding in periodic[:20]:
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(str(finding['user']))}</code></td>"
            f"<td class=\"num\">{int(finding['bursts']):,}</td>"
            f"<td class=\"num\">{int(finding['max_hosts']):,}</td>"
            f"<td class=\"num\">{html.escape(format_offset(int(finding['first_timestamp'])))}</td>"
            f"<td class=\"num\">{format_duration(int(finding['interval']))}</td>"
            f"<td class=\"num\">{int(finding['repetitions']):,}</td>"
            f"<td class=\"num\">{float(finding['confidence']):.0%}</td>"
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table><thead><tr><th>Użytkownik</th>'
        '<th>Serie</th><th>Maks. hostów naraz</th><th>Pierwsza seria</th><th>Dominujący interwał</th>'
        '<th>Powtórzenia</th><th>Udział</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div>"
    )


def burst_markers_table(result: AnalysisResult, limit: int = 20) -> str:
    """Show exact high-relative-change timestamps as candidate incident onsets."""
    observations = sorted(
        result.burst_samples,
        key=lambda item: (item[3], item[2], -item[0]),
        reverse=True,
    )[:limit]
    if not observations:
        return "<p>Nie wykryto równoczesnych serii spełniających próg.</p>"
    rows = []
    for timestamp, user, host_count, relative_score in observations:
        rows.append(
            "<tr>"
            f"<td class=\"num\">{html.escape(format_offset(timestamp))}</td>"
            f"<td><code>{html.escape(user)}</code></td>"
            f"<td class=\"num\">{host_count:,}</td>"
            f"<td class=\"num\">{relative_score:.1f}×</td>"
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table><thead><tr><th>Dokładny czas</th>'
        '<th>Użytkownik</th><th>Hosty w tej samej sekundzie</th>'
        '<th>Względem wcześniejszego profilu</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div>"
    )


def render_report(result: AnalysisResult, report_path: Path, min_burst_hosts: int) -> None:
    periodic = periodic_findings(result)
    automation = periodic[0] if periodic else None
    verdict = (
        f"Wykryto silnie okresowe, równoczesne logowania konta "
        f"<code>{html.escape(str(automation['user']))}</code>: dominujący odstęp "
        f"{html.escape(format_duration(int(automation['interval'])))} wystąpił "
        f"{int(automation['repetitions']):,} razy, a pierwsza seria wystąpiła "
        f"{html.escape(format_offset(int(automation['first_timestamp'])))}. "
        f"Zachowanie jest zgodne z automatyzacją "
        f"lub utrwalonym zadaniem po kompromitacji."
        if automation
        else "Nie wykryto jednoznacznej okresowości przy obecnych progach."
    )
    hourly_events = [(hour, count) for hour, count, _ in result.hourly]
    hourly_fanout = [(hour, fanout) for hour, _, fanout in result.hourly]
    burst_hours = [(hour, result.burst_hour_counts.get(hour, 0)) for hour, _, _ in result.hourly]

    report = f"""<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Raport analizy uwierzytelnień LANL</title>
  <style>
    :root {{ --bg:#f5f7fb; --panel:#fff; --text:#172033; --muted:#64748b; --border:#d9e1ec; --blue:#2563eb; --orange:#ea580c; --red:#dc2626; --green:#15803d; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.5 Inter,Segoe UI,Arial,sans-serif; }}
    main {{ max-width:1180px; margin:0 auto; padding:32px 22px 60px; }}
    h1 {{ margin:0 0 6px; font-size:30px; }} h2 {{ margin:32px 0 12px; }} h3 {{ margin:0 0 8px; }}
    p {{ margin:6px 0; }} .muted {{ color:var(--muted); }} code {{ background:#eef2f7; padding:2px 5px; border-radius:4px; }}
    .hero {{ background:#14213d; color:#fff; padding:26px; border-radius:14px; }} .hero .muted {{ color:#cbd5e1; }}
    .verdict {{ margin-top:18px; padding:16px 18px; border-left:5px solid var(--orange); background:#fff7ed; color:#7c2d12; border-radius:6px; }}
    .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin:18px 0; }}
    .stat {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:15px; }}
    .stat .value {{ display:block; margin-top:4px; font-size:24px; font-weight:600; }}
    .chart-section {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:18px; margin:14px 0; }}
    .chart,.network {{ width:100%; height:auto; display:block; }} svg text {{ fill:var(--muted); font-size:12px; }}
    .grid {{ stroke:var(--border); stroke-width:1; }} .axis {{ stroke:var(--muted); stroke-width:1; }}
    .table-wrap {{ overflow-x:auto; background:var(--panel); border:1px solid var(--border); border-radius:10px; }}
    table {{ width:100%; border-collapse:collapse; }} th,td {{ padding:10px 12px; border-bottom:1px solid var(--border); text-align:left; }}
    th {{ color:var(--muted); font-weight:600; }} td.num,th.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
    .method {{ background:var(--panel); border:1px solid var(--border); padding:18px; border-radius:10px; }}
    @media (prefers-color-scheme:dark) {{
      :root {{ --bg:#0f172a; --panel:#172033; --text:#e5edf8; --muted:#a6b3c5; --border:#34435a; --blue:#60a5fa; --orange:#fb923c; }}
      .hero {{ background:#172033; border:1px solid var(--border); }} .verdict {{ background:#422006; color:#fed7aa; }} code {{ background:#263248; }}
    }}
  </style>
</head>
<body><main>
  <header class="hero">
    <h1>Raport analizy uwierzytelnień</h1>
    <p class="muted">Źródło: {html.escape(str(result.source))}</p>
    <p>Analiza behawioralna wykonana wyłącznie na polach <code>time,user,computer</code>.</p>
  </header>
  <div class="verdict"><strong>Ocena:</strong> {verdict}</div>
  <section class="stats">
    <div class="stat"><span class="muted">Rekordy</span><span class="value">{result.records:,}</span></div>
    <div class="stat"><span class="muted">Użytkownicy</span><span class="value">{result.user_count:,}</span></div>
    <div class="stat"><span class="muted">Komputery</span><span class="value">{result.computer_count:,}</span></div>
    <div class="stat"><span class="muted">Równoczesne serie ≥ {min_burst_hosts}</span><span class="value">{result.total_bursts:,}</span></div>
    <div class="stat"><span class="muted">Kandydaci okresowi</span><span class="value">{len(periodic):,}</span></div>
    <div class="stat"><span class="muted">Zakres czasu</span><span class="value">{html.escape(format_duration(result.last_timestamp-result.first_timestamp))}</span></div>
  </section>

  <h2>Oś czasu</h2>
  {line_chart(hourly_events, 'Wolumen uwierzytelnień na godzinę', 'zdarzenia / godz.')}
  {line_chart(hourly_fanout, 'Największy fan-out użytkownika w każdej godzinie', 'unikalne hosty', 'var(--orange)')}
  {line_chart(burst_hours, 'Równoczesne serie logowań na godzinę', 'serie / godz.', 'var(--red)')}

  <h2>Najważniejsze anomalie</h2>
  <h3>Dokładne kandydaty początku incydentu</h3>
  {burst_markers_table(result)}
  {anomaly_bar_chart(result.anomalies)}
  <h3>Okresowość równoczesnych logowań</h3>
  {findings_table(periodic)}

  <h2>Relacje kont i komputerów</h2>
  {network_graph(result, periodic)}

  <h2>Metoda i ograniczenia</h2>
  <div class="method">
    <p><strong>Fan-out:</strong> liczba unikalnych komputerów odwiedzonych przez użytkownika w godzinie, porównana z jego wcześniejszymi aktywnymi godzinami.</p>
    <p><strong>Równoczesna seria:</strong> co najmniej {min_burst_hosts} różnych komputerów dla tego samego użytkownika i timestampu.</p>
    <p><strong>Okresowość:</strong> dominująca różnica czasu pomiędzy kolejnymi seriami tego samego użytkownika.</p>
    <p class="muted">Zbiór zawiera wyłącznie udane uwierzytelnienia. Raport wskazuje anomalie statystyczne, a nie dowodzi wykonania poleceń, złośliwego oprogramowania ani rzeczywistej zmiany uprawnień.</p>
  </div>
</main></body></html>
"""
    temporary = report_path.with_name(report_path.name + ".part")
    temporary.write_text(report, encoding="utf-8")
    os.replace(temporary, report_path)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyse LANL authentication logs and create a standalone HTML report."
    )
    parser.add_argument(
        "input", type=Path, nargs="?",
        help="modified log filename in output/ (default: auto-detect)",
    )
    parser.add_argument(
        "report", type=Path, nargs="?", default=Path("analysis-report.html"),
        help="HTML report filename in output/ (default: analysis-report.html)",
    )
    parser.add_argument("--hour-seconds", type=positive_int, default=3600)
    parser.add_argument("--min-burst-hosts", type=positive_int, default=10)
    parser.add_argument("--min-hourly-hosts", type=positive_int, default=8)
    parser.add_argument("--top-anomalies", type=positive_int, default=80)
    parser.add_argument("--max-burst-samples", type=positive_int, default=100_000)
    parser.add_argument("--progress-every", type=int, default=5_000_000)
    parser.add_argument("--force", action="store_true", help="overwrite an existing report")
    parser.add_argument(
        "--demo", action="store_true",
        help="create a representative report preview without reading a dataset",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = resolve_in_output(args.report)
    if report.exists() and not args.force:
        print(f"error: report already exists (use --force): {report}", file=sys.stderr)
        return 2
    report.parent.mkdir(parents=True, exist_ok=True)

    if args.demo:
        result = build_demo_result()
        render_report(result, report, args.min_burst_hosts)
        print(f"Demo report: {report}", file=sys.stderr)
        return 0

    try:
        source = discover_input(OUTPUT_DIR) if args.input is None else resolve_in_output(args.input)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not source.is_file():
        print(f"error: input does not exist: {source}", file=sys.stderr)
        return 2

    try:
        print(f"Analysing {source}...", file=sys.stderr)
        result = analyze(
            source,
            hour_seconds=args.hour_seconds,
            min_burst_hosts=args.min_burst_hosts,
            min_hourly_hosts=args.min_hourly_hosts,
            top_anomalies=args.top_anomalies,
            max_burst_samples=args.max_burst_samples,
            progress_every=args.progress_every,
        )
        render_report(result, report, args.min_burst_hosts)
    except (OSError, EOFError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    periodic = periodic_findings(result)
    print(
        f"Done: {result.records:,} records, {result.total_bursts:,} simultaneous bursts, "
        f"{len(periodic):,} periodic candidates.\nReport: {report}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
