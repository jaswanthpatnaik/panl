import os
import sys
import json
import argparse
import webbrowser
import threading
import subprocess

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from panl.modules.engine import analyze_file

console = Console()

def analyze_file_with_progress(filepath, vt_api_key=None):
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task(description="Initializing Analysis...", total=None)
        
        def update_progress(desc):
            progress.update(task, description=f"{desc}...")
            
        return analyze_file(filepath, vt_api_key, progress_callback=update_progress)

def print_pretty_report(r):
    # Header
    console.print(Panel(f"[bold cyan]PNAL Intelligence Report: {r['filename']}[/]\n[dim]SHA256: {r['sha256']}[/]", border_style="cyan"))

    # Risk Score Circle (Simulated)
    score = r['risk_score']['score']
    severity = r['risk_score']['severity']
    color = "red" if severity == "Unsafe" else "yellow" if severity == "High" else "green"
    console.print(f"\n[bold]OVERALL RISK SCORE:[/] [{color}]{score}[/] [bold]({severity.upper()})[/]\n")

    # Threat Analysis Table
    table = Table(title="Forensic Threat Breakdown", box=None)
    table.add_column("Finding", style="magenta")
    table.add_column("Potential Action / Significance", style="white")

    for f in r['behavior']['detailed_findings']:
        table.add_row(f['why'], ", ".join(f['actions']))
    
    if r.get('vt_results') and not r['vt_results'].get('error'):
        table.add_row("VirusTotal Intelligence", f"[bold red]{r['vt_results']['malicious']}[/] / {r['vt_results']['total']} detections found.")

    console.print(table)

    # Secondary Data Grid
    grid = Table.grid(expand=True)
    grid.add_column(style="dim")
    grid.add_column(style="bold")

    # Offline Scan
    off = r['offline_scan']
    off_status = f"[bold red]MATCHED {len(off['yara_matches'])} RULES[/]" if off['yara_matches'] else "[green]No Matches[/]"
    console.print(f"\n[bold cyan]Offline Intelligence:[/] {off_status}")
    if off.get('clamav_results') and "Detected" in off['clamav_results']:
        console.print(f"  [red]![/] ClamAV: {off['clamav_results']}")

    # IOCs
    iocs = r['iocs']
    if iocs['urls'] or iocs['ips']:
        console.print(f"\n[bold cyan]Extracted IOCs:[/]")
        for url in iocs['urls'][:3]: console.print(f"  [dim]URL:[/] {url['value']}")
        for ip in iocs['ips'][:3]: console.print(f"  [dim]IP: [/] {ip['value']}")

    console.print("\n[dim]Use 'panl dashboard' for the full interactive forensic experience.[/]\n")

def main():
    parser = argparse.ArgumentParser(
        prog='pnal',
        description='PNAL: Proactive Network & Analysis Laboratory',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a PDF file")
    analyze_parser.add_argument("file", help="Path to PDF file")
    analyze_parser.add_argument("--vt-key", help="VirusTotal API Key")
    analyze_parser.add_argument("--json", action="store_true", help="Output raw JSON data")

    subparsers.add_parser("dashboard", help="Start the web dashboard")
    args = parser.parse_args()

    if args.command == "analyze":
        results = analyze_file_with_progress(args.file, vt_api_key=args.vt_key)
        if results:
            if args.json:
                print(json.dumps(results, indent=4))
            else:
                print_pretty_report(results)
    elif args.command == "dashboard":
        from panl.web import start_web
        url = "http://127.0.0.1:5000"
        console.print(f"[bold cyan][*] Launching Intelligence Hub...[/]")
        console.print(f"[dim]If the browser does not open automatically, visit: {url}[/]\n")
        
        # Open browser in a separate thread to not block server start
        def open_browser():
            if sys.platform == "linux" or sys.platform == "linux2":
                subprocess.run(["xdg-open", url], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            else:
                webbrowser.open(url)
        
        threading.Timer(1.5, open_browser).start()
        start_web()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
