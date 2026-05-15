import time
import os
import re
from datetime import datetime
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich import box
from rich.console import Group

SNORT_ALERT_LOG = r"C:\Snort\log\alert.ids"
OUTPUT_LOG      = r"C:\snort\logs\central_monitor.log"
REFRESH_SECONDS = 2

console = Console()

SEVERITY = {
    "ICMP flood DoS detected":   ("CRITICAL", "red"),
    "TCP SYN flood detected":    ("CRITICAL", "red"),
    "SSH brute force attempt":   ("HIGH",     "yellow"),
    "SSH connection attempt":    ("HIGH",     "yellow"),
    "FTP brute force attempt":   ("HIGH",     "yellow"),
    "NMAP SYN scan detected":    ("MEDIUM",   "cyan"),
    "HTTP port scan detected":   ("MEDIUM",   "cyan"),
}

def get_severity(msg):
    for keyword, (level, color) in SEVERITY.items():
        if keyword.lower() in msg.lower():
            return level, color
    return "LOW", "white"

def parse_alert(line):
    pattern = r'(\d+/\d+-[\d:]+\.\d+)\s+\[\*\*\]\s+\[.*?\]\s+(.*?)\s+\[\*\*\].*?(\d+\.\d+\.\d+\.\d+).*?->\s*(\d+\.\d+\.\d+\.\d+)'
    match = re.search(pattern, line)
    if match:
        level, color = get_severity(match.group(2))
        return {
            "timestamp": match.group(1),
            "message":   match.group(2).strip(),
            "src_ip":    match.group(3),
            "dst_ip":    match.group(4),
            "severity":  level,
            "color":     color,
        }
    return None

def build_dashboard(alerts, stats, attack_counts):
    header = Panel(
        f"[bold]NIDS Central Monitor[/bold] — IoT Network (192.168.243.0/24)\n"
        f"[dim]Session started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
        f"Monitoring: {SNORT_ALERT_LOG}[/dim]",
        style="bold blue"
    )

    summary_table = Table(box=box.SIMPLE, show_header=False, expand=True)
    summary_table.add_column(justify="center")
    summary_table.add_column(justify="center")
    summary_table.add_column(justify="center")
    summary_table.add_column(justify="center")
    summary_table.add_column(justify="center")
    summary_table.add_row(
        f"[red]CRITICAL\n{stats.get('CRITICAL', 0)}[/red]",
        f"[yellow]HIGH\n{stats.get('HIGH', 0)}[/yellow]",
        f"[cyan]MEDIUM\n{stats.get('MEDIUM', 0)}[/cyan]",
        f"[white]LOW\n{stats.get('LOW', 0)}[/white]",
        f"[bold]TOTAL\n{sum(stats.values())}[/bold]",
    )
    summary = Panel(summary_table, title="Alert Summary", border_style="blue")

    breakdown = Table(title="Attack Breakdown", box=box.SIMPLE_HEAVY, expand=True)
    breakdown.add_column("Attack Type", style="dim")
    breakdown.add_column("Count", justify="right")
    breakdown.add_column("Bar", min_width=20)

    max_count = max(attack_counts.values(), default=1)
    colors = {
        "ICMP flood DoS detected":   "red",
        "TCP SYN flood detected":    "red",
        "SSH brute force attempt":   "yellow",
        "SSH connection attempt":    "yellow",
        "FTP brute force attempt":   "yellow",
        "NMAP SYN scan detected":    "cyan",
        "HTTP port scan detected":   "cyan",
    }
    for attack, count in sorted(attack_counts.items(), key=lambda x: -x[1]):
        bar_len = int((count / max_count) * 20)
        bar = "█" * bar_len
        color = colors.get(attack, "white")
        breakdown.add_row(attack, str(count), f"[{color}]{bar}[/{color}]")

    feed = Table(title="Live Alert Feed", box=box.SIMPLE_HEAVY, expand=True)
    feed.add_column("Severity",  min_width=10)
    feed.add_column("Time",      min_width=18)
    feed.add_column("Alert",     min_width=28)
    feed.add_column("Source IP", min_width=16)
    feed.add_column("Target IP", min_width=16)

    for alert in alerts[-15:]:
        c = alert["color"]
        feed.add_row(
            f"[{c}]{alert['severity']}[/{c}]",
            alert["timestamp"],
            f"[{c}]{alert['message']}[/{c}]",
            alert["src_ip"],
            alert["dst_ip"],
        )

    return Group(header, summary, breakdown, feed)

def monitor():
    alerts        = []
    stats         = defaultdict(int)
    attack_counts = defaultdict(int)
    processed     = 0
    last_size     = 0

    os.makedirs(os.path.dirname(OUTPUT_LOG), exist_ok=True)

    with open(OUTPUT_LOG, "a") as f:
        f.write(f"\n{'*'*60}\nSession started: {datetime.now()}\n{'*'*60}\n")

    with Live(console=console, refresh_per_second=1, screen=True) as live:
        while True:
            try:
                if not os.path.exists(SNORT_ALERT_LOG):
                    live.update(Panel("[yellow]Waiting for Snort alert log...[/yellow]"))
                    time.sleep(REFRESH_SECONDS)
                    continue

                current_size = os.path.getsize(SNORT_ALERT_LOG)

                if current_size > last_size:
                    with open(SNORT_ALERT_LOG, "r") as f:
                        lines = f.readlines()

                    for line in lines[processed:]:
                        alert = parse_alert(line)
                        if alert:
                            alerts.append(alert)
                            stats[alert["severity"]] += 1
                            attack_counts[alert["message"]] += 1
                            with open(OUTPUT_LOG, "a") as f:
                                f.write(
                                    f"[{alert['severity']}] {alert['timestamp']} | "
                                    f"{alert['message']} | "
                                    f"{alert['src_ip']} -> {alert['dst_ip']}\n"
                                )

                    processed = len(lines)
                    last_size = current_size

                live.update(build_dashboard(alerts, stats, attack_counts))

            except KeyboardInterrupt:
                break
            except Exception as e:
                live.update(Panel(f"[red]Error: {e}[/red]"))

            time.sleep(REFRESH_SECONDS)

    console.print("\n[bold]Monitor stopped.[/bold]")
    for level, count in stats.items():
        console.print(f"  {level}: {count}")

if __name__ == "__main__":
    monitor()