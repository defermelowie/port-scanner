use std::error::Error;

use tokio::net::lookup_host;

use clap::{command, Parser};

mod common_ports;
use common_ports::get_common_ports;

mod port;
use port::{scan_targets, Port, Target};

/// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to scan
    #[clap(required = true)]
    address: Vec<String>,

    /// Ports to scan
    #[clap(short, long)]
    ports: Option<Vec<u16>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get arguments
    let args = Args::parse();

    // Get port vector
    let ports_to_scan = match args.ports {
        Some(p) => p
            .iter()
            .map(|nr| Port {
                service: "unknown".to_string(),
                number: *nr,
                is_open: None,
            })
            .collect(),
        None => get_common_ports(1000),
    };

    // Dns lookup
    let mut targets = Vec::new();
    for addr in args.address.iter() {
        let target = format!("{}:0", addr);
        let mut addresses = lookup_host(target).await?;
        while let Some(address) = addresses.next() {
            targets.push(Target {
                address,
                ports: ports_to_scan.to_owned(),
            });
        }
    }

    // Scan targets
    let scan_res = scan_targets(targets).await;

    // Print output
    for target in scan_res.iter() {
        println!("Open tcp ports for {}:", target.address.ip());
        for port in target.ports.iter() {
            if port.is_open.expect("No port scanning result available") {
                println!("  {}\t{}", port.number, port.service);
            }
        }
        print!("{}", '\n');
    }

    // End program
    Ok(())
}
