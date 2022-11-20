use std::error::Error;

use tokio::net::lookup_host;

use clap::{command, Parser};

mod common_ports;
use common_ports::get_common_ports;

mod port;
use port::{scan_ports, Port};

/// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to scan
    address: String,

    /// Ports to scan
    #[arg(short, long)]
    ports: Option<Vec<u16>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get arguments
    let args = Args::parse();

    // Dns lookup
    let target = format!("{}:0", args.address);
    let sock_addr = lookup_host(target).await?.next().unwrap();

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

    // Scan ports
    let port_scan_res = scan_ports(sock_addr, ports_to_scan).await;

    // Print output
    println!("Open tcp ports for {}:", sock_addr.ip());
    for port in port_scan_res.iter() {
        if port.is_open.expect("No port scanning result available") {
            println!("  {}\t{}", port.number, port.service);
        }
    }

    // End program
    Ok(())
}
