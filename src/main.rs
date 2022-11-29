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
    port: Option<Vec<u16>>,

    /// Amount of common ports to scan (maximum 5000)
    #[clap(short, long)]
    common: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get arguments
    let args = Args::parse();

    // Get amount of common ports
    let common_port_amount = match args.common {
        Some(amount) => amount,
        None => 1000,
    };

    // Get port vector
    let mut ports_to_scan = match args.port {
        Some(p) => p
            .iter()
            .map(|nr| Port {
                service: "unknown".to_string(),
                number: *nr,
                is_open: None,
            })
            .collect(),
        None => Vec::new(),
    };
    ports_to_scan.append(&mut get_common_ports(common_port_amount).to_owned());

    // Dns lookup
    let mut targets = Vec::new();
    for url in args.address.iter() {
        let target = format!("{}:0", url);
        let mut addresses = lookup_host(target).await?;
        while let Some(address) = addresses.next() {
            targets.push(Target {
                name: url.to_string(),
                address: address,
                ports: ports_to_scan.to_owned(),
            });
        }
    }

    // Scan targets
    let scan_res = scan_targets(targets).await;

    // Print output
    for target in scan_res.iter() {
        println!(
            "Open tcp ports for {} ({}):",
            target.address.ip(),
            target.name
        );
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
