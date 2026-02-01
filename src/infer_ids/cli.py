import typer
from rich.panel import Panel
from rich.console import Console

from setup.zeek import process_file
from parse.parse_log import ParseLogs
from config import Config
from core import load_model_package, ensure_features, add_predictions

app = typer.Typer()
console = Console()

@app.command()
def run():

    intro = r"""
    ____      ____                ________  _____
   /  _/___  / __/__  _____      /  _/ __ \/ ___/
   / // __ \/ /_/ _ \/ ___/_____ / // / / /\__ \ 
 _/ // / / / __/  __/ /  /_____// // /_/ /___/ / 
/___/_/ /_/_/  \___/_/        /___/_____//____/  
                                                 
        """

    console.print(intro)

    console.print(
        Panel.fit(
            "[bold cyan]Infer-IDS[/bold cyan]\n\n"
            "A simple machine learning system for detecting\n"
            "malicious DNS and TLS network traffic.\n",
            border_style="bright_blue"
        )
    )

    data_dir = Config.DATA_DIR
    
    console.print(f"[bold]PCAP files should be located in:[/bold] {data_dir}. Please \
                  ensure you have uploaded it here.\n")

    pcap_input = typer.prompt("Enter the PCAP filename (e.g. botnet.pcap)")

    pcap_path = data_dir / pcap_input

    if not pcap_path.exists():
        console.print(f"[red]File not found: {pcap_path}. Exiting...[/red]")
        raise typer.Exit()

    console.print(f"[green]Processing:[/green] {pcap_path.name}...\n")

    parser = ParseLogs()

    with process_file(pcap_path) as log_dir:
        dns_connections, tls_connections = parser.parse_logs(log_dir)

    dns_df = parser.to_dataframe(dns_connections)
    tls_df = parser.to_dataframe(tls_connections)

    console.print("[cyan]Running ML predictions...[/cyan]\n")

    dns_package = load_model_package(Config.MODEL_DIR / "dns_model_package.pkl")
    tls_package = load_model_package(Config.MODEL_DIR / "tls_model_package.pkl")

    dns_df = ensure_features(dns_df, dns_package["features"])
    tls_df = ensure_features(tls_df, tls_package["features"])

    dns_df = add_predictions(dns_df, dns_package)
    tls_df = add_predictions(tls_df, tls_package)

    output_dir = Config.CONFIG_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    dns_out = output_dir / f"{pcap_path.stem}_dns_predictions.csv"
    tls_out = output_dir / f"{pcap_path.stem}_tls_predictions.csv"

    dns_df.to_csv(dns_out, index=False)
    tls_df.to_csv(tls_out, index=False)

    console.print("[bold green]Done![/bold green]\n")
    console.print(f"DNS results saved to:\n  [blue]{dns_out}[/blue]")
    console.print(f"TLS results saved to:\n  [blue]{tls_out}[/blue]\n")
    console.print(f"[bold]Thank you for using Infer-IDS. Goodbye![/bold]\n")

if __name__ == "__main__":
    app()
