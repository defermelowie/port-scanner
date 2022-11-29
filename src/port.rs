use std::net::SocketAddr;

use futures::future::join_all;

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Duration;

/// A tcp port with `is_open` flag
#[derive(Debug, Clone, PartialEq)]
pub struct Port {
    pub service: String,
    pub number: u16,
    pub is_open: Option<bool>,
}

/// A target consisting out of:
/// - An address
/// - A vector of ports to scan
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub name: String,
    pub address: SocketAddr,
    pub ports: Vec<Port>,
}

/// Scan ports of multiple targets
pub async fn scan_targets(targets: Vec<Target>) -> Vec<Target> {
    // Define input and output channels
    let (targets_tx, mut targets_rx) = mpsc::channel(targets.len());

    // Spawn scanning tasks
    let mut scan_tasks = Vec::new();
    for target in targets.iter() {
        let targets_tx = targets_tx.clone();
        let mut target = target.to_owned();

        let scan_task = tokio::spawn(async move {
            target.ports = scan_ports(target.address, target.ports).await;
            let _ = targets_tx.send(target).await;
        });
        scan_tasks.push(scan_task);
    }

    // Wait for all tasks to finish & close channel
    join_all(scan_tasks).await;
    targets_rx.close();

    // Collect result
    let mut target_res = Vec::new();
    while let Some(target) = targets_rx.recv().await {
        target_res.push(target);
    }

    // Return ports
    target_res
}

/// Scan multiple ports of a target
async fn scan_ports(target: SocketAddr, ports: Vec<Port>) -> Vec<Port> {
    // Define input and output channels
    let (ports_tx, mut ports_rx) = mpsc::channel(ports.len());

    // Spawn port scan tasks
    let mut scan_tasks = Vec::new();
    for port in ports.iter() {
        let mut address = target;
        address.set_port(port.number);

        let ports_tx = ports_tx.clone();
        let mut port = port.to_owned();
        let scan_task = tokio::spawn(async move {
            port.is_open = Some(scan_port(address).await);
            let _ = ports_tx.send(port).await;
        });
        scan_tasks.push(scan_task);
    }

    // Wait for all tasks to finish & close channel
    join_all(scan_tasks).await;
    ports_rx.close();

    // Collect result
    let mut ports_res = Vec::new();
    while let Some(port) = ports_rx.recv().await {
        ports_res.push(port);
    }

    // Return ports
    ports_res
}

/// Scan a single port of a target
async fn scan_port(target: SocketAddr) -> bool {
    let timeout = Duration::from_secs(3);

    let is_open = matches!(
        tokio::time::timeout(timeout, TcpStream::connect(&target)).await,
        Ok(Ok(_)),
    );
    is_open
}
