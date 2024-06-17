use anyhow::{anyhow, bail, Context, Error, Result};
use pnet::{
    packet::{
        icmp::{self, IcmpPacket, IcmpType, IcmpTypes},
        ip::{self, IpNextHeaderProtocols},
        ipv4::{self, Ipv4Packet},
        Packet,
    },
    transport::{self, ipv4_packet_iter, transport_channel, TransportChannelType},
};
use rand::{seq::IteratorRandom, thread_rng};
use std::{
    collections::{BTreeMap, VecDeque},
    env,
    fs::read_to_string,
    net::Ipv4Addr,
    ops::Add,
    str::FromStr,
    sync::mpsc,
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

const MAX_PARALLEL_TRACEROUTES: usize = 16;
const HARD_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_HOPS: Ttl = Ttl(32);
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let ips: VecDeque<_> = ips_from_csv(&args[1], 100)?.into();

    let (transport_tx, transport_rx) = icmp_transport_channel(2048).unwrap();
    let (receiver_tx, receiver_rx) = mpsc::channel();
    let (transmiter_tx, transmiter_rx) = mpsc::channel();
    Receiver::spawn(transport_rx, receiver_tx);
    Transmiter::spawn(transport_tx, transmiter_rx);
    Controller::<MAX_PARALLEL_TRACEROUTES>::new(ips, transmiter_tx, receiver_rx)
        .spawn()
        .unwrap();

    Ok(())
}

#[derive(Debug)]
struct DataRow {
    destination: Ipv4Addr,
    ttl: Ttl,
    ip: Ipv4Addr,
    duration: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Ttl(u8);
impl Add<u8> for Ttl {
    type Output = Self;

    fn add(self, rhs: u8) -> Self::Output {
        Self(self.0 + rhs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Id(u16);

#[derive(Debug, Clone, Copy)]
struct Metadata {
    destination: Ipv4Addr,
    ttl: Ttl,
    at: Instant,
}
struct Controller<const N: usize> {
    queue: VecDeque<Ipv4Addr>,
    ttl_store: BTreeMap<Ipv4Addr, Ttl>,
    id_register: BTreeMap<u16, Metadata>,
    id: u16,
    tx: mpsc::Sender<TransmiterMsg>,
    rx: mpsc::Receiver<ReceiveMsg>,
}

impl<const N: usize> Controller<N> {
    fn new(
        ips: VecDeque<Ipv4Addr>,
        tx: mpsc::Sender<TransmiterMsg>,
        rx: mpsc::Receiver<ReceiveMsg>,
    ) -> Self {
        Self {
            queue: ips,
            ttl_store: BTreeMap::new(),
            id_register: BTreeMap::new(),
            id: 404,
            tx,
            rx,
        }
    }

    fn clean_register(&mut self) {
        let now = Instant::now();
        self.id_register.retain(|_, m| now - m.at < HARD_TIMEOUT);
    }

    fn get_unique_id(&mut self) -> Result<u16> {
        for offset in 0..u16::MAX {
            let id = self.id.saturating_add(offset);
            if !self.id_register.contains_key(&id) {
                self.id = id + 1;
                return Ok(id);
            }
        }

        // Try again after clean
        self.clean_register();
        for offset in 0..u16::MAX {
            let id = self.id.saturating_add(offset);
            if !self.id_register.contains_key(&id) {
                self.id = id + 1;
                return Ok(id);
            }
        }
        bail!("All ids are in use");
    }

    fn request(&mut self, m: Metadata) -> Result<()> {
        let id = self.get_unique_id()?;
        self.id_register.insert(id, m);
        self.tx
            .send(TransmiterMsg {
                destination: m.destination,
                id: Id(id),
                ttl: m.ttl,
            })
            .context("Fail to send the request")
    }

    fn end(&mut self, ip: Ipv4Addr) -> Result<Option<Ttl>> {
        self.ttl_store.remove(&ip);
        self.start_new_traceroute()
    }

    fn request_next_hop(&mut self, ip: Ipv4Addr) -> Result<Option<Ttl>> {
        let ttl = if let Some(ttl) = self.ttl_store.get(&ip) {
            *ttl + 1
        } else {
            Ttl(0)
        };

        if ttl > MAX_HOPS {
            log::info!("Max hops {}", ip);
            self.end(ip);
            return Ok(None);
        }

        self.ttl_store.insert(ip, ttl);
        self.request(Metadata {
            destination: ip,
            ttl,
            at: Instant::now(),
        })?;

        Ok(Some(ttl))
    }

    fn start_new_traceroute(&mut self) -> Result<Option<Ttl>> {
        let Some(ip) = self.queue.pop_front() else {
            return Ok(None);
        };

        self.request_next_hop(ip)
    }

    fn handle_response(&mut self, rcv: ReceiveMsg) -> Result<DataRow> {
        let Some(m) = self.id_register.get(&rcv.id.0).cloned() else {
            bail!("Can't find the pkg id {:?}", rcv.id)
        };
        self.id_register.remove(&rcv.id.0);

        let data = DataRow {
            destination: m.destination,
            ttl: m.ttl,
            ip: rcv.source,
            duration: rcv.at - m.at,
        };

        let is_end = match rcv.icmp_type {
            IcmpTypes::TimeExceeded => false,
            IcmpTypes::DestinationUnreachable | IcmpTypes::EchoReply => true,
            _ => bail!("Invalid icmp_type"),
        };

        if is_end {
            self.end(m.destination)?;
        } else {
            self.request_next_hop(m.destination)?;
        }

        Ok(data)
    }

    fn spawn(&mut self) -> Result<()> {
        (0..MAX_PARALLEL_TRACEROUTES)
            .into_iter()
            .try_for_each(|_| {
                self.start_new_traceroute()?;
                Ok::<_, Error>(())
            })?;

        loop {
            let response = self.rx.recv_timeout(Duration::from_secs(120))?;
            self.handle_response(response)
                .map(|data| {
                    // TODO: save in csv
                    println!("{:?}", data);
                })
                .map_err(|e| {
                    log::error!("Error handle response {}", e);
                })
                .ok();
            // TODO: check for soft timeouts
        }
    }
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
    id: Id,
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
    id: Id,
    ttl: Ttl,
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
                    send_echo(
                        &mut tx_socket,
                        seq_num,
                        msg.destination,
                        msg.ttl.0,
                        msg.id.0,
                    )
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
        id: Id(packet.get_identification()),
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
