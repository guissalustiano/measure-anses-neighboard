use anyhow::Result;
use pnet::{
    packet::{
        icmp::{IcmpPacket, IcmpType},
        ip::{self, IpNextHeaderProtocols},
        ipv4, Packet,
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
    time::{Duration, Instant},
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
    Receiver::spawn(transport_rx, receiver_tx);

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
    seq_num: u16,
    at: Instant,
}
impl Receiver {
    fn spawn(mut rx_socket: transport::TransportReceiver, tx_channel: mpsc::Sender<ReceiveMsg>) {
        thread::spawn(move || {
            let mut packet_iter = ipv4_packet_iter(&mut rx_socket);
            loop {
                if let Some((packet, _)) = packet_iter
                    .next_with_timeout(Duration::from_secs(30))
                    .ok()
                    .flatten()
                {
                    //skip non icmp
                    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                        break;
                    }
                    let Some(packet) = ipv4::Ipv4Packet::new(packet.payload()) else {
                        log::error!("Fail to decode to IPV4");
                        break;
                    };

                    let Some(icmp_packet) = IcmpPacket::new(packet.payload()) else {
                        log::error!("Fail to decode to ICMP");
                        break;
                    };

                    let msg = ReceiveMsg {
                        icmp_type: icmp_packet.get_icmp_type(),
                        source: packet.get_source(),
                        id: packet.get_identification(),
                        seq_num: 0,
                        at: Instant::now(),
                    };
                    log::debug!("{:?}", msg);

                    if let Err(e) = tx_channel.send(msg) {
                        log::error!("{:?}", e);
                    }
                }
            }
        });
    }
}
