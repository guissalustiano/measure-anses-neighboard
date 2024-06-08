use std::net::Ipv4Addr;

use pnet::{
    packet::{icmp, ip, ipv4, Packet},
    transport::{ipv4_packet_iter, transport_channel, TransportChannelType, TransportSender},
    util::checksum,
};

use anyhow::{Context, Result};

pub fn send_echo(
    tx: &mut TransportSender,
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

    icmp_packet.set_checksum(checksum(icmp_packet.packet(), 1));

    ip_packet.set_payload(icmp_packet.packet());

    tx.send_to(ip_packet, dst_ip.into())?;

    Ok(())
}

fn main() -> Result<()> {
    let icmp = TransportChannelType::Layer3(ip::IpNextHeaderProtocols::Icmp);
    let (mut tx, mut rx) = transport_channel(2048, icmp)?;

    for ttl in 0..32 {
        send_echo(&mut tx, 1, Ipv4Addr::new(200, 147, 35, 149), ttl, 42)?;
    }

    let mut rx_iter = ipv4_packet_iter(&mut rx);
    loop {
        let (res_ip_pkg, res_ip_addr) = rx_iter.next()?;
        let res_icmp_pkg = icmp::IcmpPacket::new(res_ip_pkg.payload()).context("Fail to decode")?;

        if res_icmp_pkg.get_icmp_type() != icmp::IcmpType(11) {
            continue;
        }

        println!("{res_ip_addr} -> {res_icmp_pkg:?}");
    }
}
