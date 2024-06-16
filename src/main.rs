use anyhow::{Context, Result};
use pnet::{
    packet::{
        icmp::{self, IcmpPacket, IcmpType},
        ip::{self, IpNextHeaderProtocols},
        ipv4::{self, Ipv4Packet},
        Packet,
    },
    transport::{self, ipv4_packet_iter, transport_channel, TransportChannelType},
};
use rand::{seq::IteratorRandom, thread_rng};
use std::{
    env,
    fs::read_to_string,
    net::Ipv4Addr,
    str::FromStr,
    sync::mpsc::{self},
    thread,
    time::Instant,
};

fn icmp_transport_channel(
    buffer_size: usize,
) -> Result<(transport::TransportSender, transport::TransportReceiver), std::io::Error> {
    transport_channel(
        buffer_size,
        TransportChannelType::Layer3(ip::IpNextHeaderProtocols::Icmp),
    )
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let ips = ips_from_csv(&args[1], 100)?;

    let (transport_tx, transport_rx) = icmp_transport_channel(2048).unwrap();
    let (receiver_tx, receiver_rx) = mpsc::channel();
    let (transmiter_tx, transmiter_rx) = mpsc::channel();
    Receiver::spawn(transport_rx, receiver_tx);
    Transmiter::spawn(transport_tx, transmiter_rx);

    Ok(())
}

fn ips_from_csv(path: &str, num: usize) -> Result<Vec<Ipv4Addr>> {
    let mut rng = thread_rng();

    let mut ip_scores: Vec<(u8, Ipv4Addr)> = read_to_string(path)?
        .lines()
        .skip(1)
        .filter_map(|l| {
            let parts: Vec<_> = l.split(',').collect();
            Some((
                u8::from_str(parts[1]).ok()?,
                Ipv4Addr::from_str(parts[0]).ok()?,
            ))
        })
        .collect();
    ip_scores.sort();
    Ok(ip_scores
        .iter()
        .rev()
        .take(1_000_000)
        .map(|i| i.1)
        .choose_multiple(&mut rng, num))
}

struct Receiver;
#[derive(Debug)]
struct ReceiveMsg {
    icmp_type: IcmpType,
    source: Ipv4Addr,
    id: u16,
    at: Instant,
}
impl Receiver {
    fn spawn(
        mut rx_socket: transport::TransportReceiver,
        mut tx_channel: mpsc::Sender<ReceiveMsg>,
    ) {
        thread::spawn(move || {
            let mut packet_iter = ipv4_packet_iter(&mut rx_socket);
            loop {
                packet_iter
                    .next()
                    .context("Fail to receive a package")
                    .and_then(|(packet, _)| receive_packets(&mut tx_channel, packet))
                    .map_err(|e| {
                        log::error!("{:?}", e);
                    })
                    .ok();
            }
        });
    }
}

struct Transmiter;
#[derive(Debug)]
struct TransmiterMsg {
    destination: Ipv4Addr,
    id: u16,
    ttl: u8,
}
impl Transmiter {
    fn spawn(mut tx_socket: transport::TransportSender, rx_channel: mpsc::Receiver<TransmiterMsg>) {
        let mut seq_num = 0;
        thread::spawn(move || loop {
            rx_channel
                .recv()
                .context("Fail to receive")
                .and_then(|msg| {
                    seq_num += 1;
                    send_echo(&mut tx_socket, seq_num, msg.destination, msg.ttl, msg.id)
                })
                .map_err(|e| {
                    log::error!("{:?}", e);
                })
                .ok();
        });
    }
}

fn receive_packets(tx_channel: &mut mpsc::Sender<ReceiveMsg>, packet: Ipv4Packet) -> Result<()> {
    //skip non icmp
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
        return Ok(());
    }

    let icmp_packet = IcmpPacket::new(packet.payload()).context("Fail to decode to ICMP")?;

    let msg = ReceiveMsg {
        icmp_type: icmp_packet.get_icmp_type(),
        source: packet.get_source(),
        id: packet.get_identification(),
        at: Instant::now(),
    };
    log::debug!("{:?}", msg);

    tx_channel
        .send(msg)
        .context("Fail to transmit received package")
}

pub fn send_echo(
    tx: &mut transport::TransportSender,
    sequence_number: u16,
    dst_ip: Ipv4Addr,
    ttl: u8,
    id: u16,
) -> Result<()> {
    const ICMP_LEN: usize = icmp::echo_request::MutableEchoRequestPacket::minimum_packet_size();
    const IP_LEN: usize = ipv4::MutableIpv4Packet::minimum_packet_size() + ICMP_LEN;
    const IP_HEADER_LEN: usize = ipv4::MutableIpv4Packet::minimum_packet_size() / 4;

    // Construct the IP packet
    let mut ip_buffer = [0; IP_LEN];
    let mut ip_packet: ipv4::MutableIpv4Packet =
        ipv4::MutableIpv4Packet::new(&mut ip_buffer).context("failt to create ipv4 package")?;

    ip_packet.set_version(4);
    ip_packet.set_header_length(IP_HEADER_LEN as u8);
    ip_packet.set_total_length(IP_LEN as u16);
    ip_packet.set_identification(id);
    ip_packet.set_flags(ipv4::Ipv4Flags::DontFragment);
    ip_packet.set_ttl(ttl);
    ip_packet.set_next_level_protocol(ip::IpNextHeaderProtocols::Icmp);
    ip_packet.set_source(Ipv4Addr::UNSPECIFIED);
    ip_packet.set_destination(dst_ip);

    // Construct the ICMP packet
    let mut icmp_buffer = vec![0; ICMP_LEN];
    let mut icmp_packet: icmp::echo_request::MutableEchoRequestPacket =
        icmp::echo_request::MutableEchoRequestPacket::new(&mut icmp_buffer)
            .context("fail create echo request packet")?;

    icmp_packet.set_icmp_type(icmp::IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(icmp::echo_request::IcmpCodes::NoCode);
    icmp_packet.set_identifier(id);
    icmp_packet.set_sequence_number(sequence_number);

    icmp_packet.set_checksum(pnet::util::checksum(icmp_packet.packet(), 1));

    ip_packet.set_payload(icmp_packet.packet());

    tx.send_to(ip_packet, dst_ip.into())?;
    Ok(())
}
