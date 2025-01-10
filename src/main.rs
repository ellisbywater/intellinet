use std::collections::HashMap;
use std::env::consts::ARCH;
use std::{fs, thread};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use notify_rust::Notification;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use serde::Deserialize;
use terminal::{Clear, Action};

#[derive(Deserialize)]
struct Config {
    general: GeneralConfig,
    alert: AlertConfig
}


#[derive(Deserialize)]
struct GeneralConfig {
    mode: String,
}

#[derive(Deserialize)]
struct AlertConfig {
    ip: String,
    port: u16
}

struct IpStats {
    sent: u64,
    received: u64
}

fn main() {
    let interface = "eth0";
    let config_content = fs::read_to_string("intellinet.config.toml").unwrap();
    let config = toml::from_str(&config_content).unwrap();

    // Open the capture for the given interface
    let mut cap = pcap::Capture::from_device(interface).unwrap()
        .promisc(true)
        .snaplen(5000)
        .open().unwrap();

    let shared_ip_map = Arc::new(Mutex::new(HashMap::<String, IpStats>::new()));
    let ip_map_for_thread = Arc::clone(&shared_ip_map);

    // Spawn thread to handle display
    thread::spawn(
        move || {
            loop {
                display_summary(&mut ip_map_for_thread.lock().unwrap());
                thread::sleep(Duration::from_millis(500))
            }
        }
    );
    loop {
        if let Ok(packet) = cap.next() {
            println!("Received packet of length {}", packet.header.len());
            if let Some(ethernet_packet) = EthernetPacket::new(&packet.data) {
                println!("Ethernet packet: {:?}", ethernet_packet);
                match ethernet_packet.get_ethertype() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_packet = TcpPacket::new(ethernet_packet.payload());
                        if let Some(tcp_packet) = tcp_packet {
                            println!(
                                "TCP Packet: {}:{} > {}:{}; Seq: {}, Ack: {}",
                                ethernet_packet.get_source(),
                                tcp_packet.get_source(),
                   q             ethernet_packet.get_destination(),
                                tcp_packet.get_destination(),
                                tcp_packet.get_sequence(),
                                tcp_packet.get_acknowledgement()
                            );
                        }
                    },
                    IpNextHeaderProtocols::Udp => {
                        let udp_packet = UdpPacket::new(ethernet_packet.payload());
                        if let Some(udp_packet) = udp_packet {
                            println!(
                                "UDP Packet: {}:{} > {}:{}; Len: {}",
                                ethernet_packet.get_source(),
                                udp_packet.get_source(),
                                ethernet_packet.get_destination(),
                                udp_packet.get_destination(),
                                udp_packet.get_length()
                            );
                        }
                    },
                    _ => {},
                }
            }
        }
    }
}

fn update_ip_stats(ip_map: &mut HashMap<String, IpStats>, ip: String, is_source: bool, packet_size: u32){
    let stats = ip_map.entry(ip).or_insert(IpStats { sent: 0, received: 0});
    if is_source {
        stats.sent += packet_size as u64;
    } else {
        stats.received += packet_size as u64;
    }
}

fn send_alert(ip: &str, port: u16) {
    println!("ALERT! Traffic from IP {} on port {}", ip, port);
    Notification::new()
        .summary("Network Monitoring Alert")
        .body(&format!("Traffic from IP {} on port {}", ip, port))
        .show()
        .unwrap();
}

fn display_summary(ip_map: &mut HashMap<String, IpStats>) {
    let terminal = terminal::stdout();
    terminal.act(Action::ClearTerminal(Clear::All)).unwrap();
    println!("IP Address        | Packets Sent | Packets Received");
    println!("------------------+--------------+-----------------");
    for (ip, stats) in ip_map {
        println!("{:<18} | {:<12} | {}", ip, stats.sent, stats.received);
    }
}