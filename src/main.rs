use std::{
    fmt::{Display, Write},
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use pnet::{
    packet::{
        icmp,
        ip::{self, IpNextHeaderProtocols},
        ipv4, Packet,
    },
    transport::{
        ipv4_packet_iter, transport_channel, TransportChannelType, TransportReceiver,
        TransportSender,
    },
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

struct HopInfo {
    since: Instant,
    retry: usize,
    id: u16,
}

struct TraceRoute {
    target: Ipv4Addr,
    hops: Vec<Option<Ipv4Addr>>,
    hopinfo: HopInfo,
}

impl Display for TraceRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //f.write_fmt("[{}] {}", self.target, self.hops);
        f.write_fmt(format_args!("[{}] {{ ", self.target))?;
        for h in &self.hops {
            match h {
                Some(ip) => f.write_fmt(format_args!(" -> {}", &ip.to_string()))?,
                None => f.write_str(" -> *")?,
            };
        }
        f.write_char('}')?;
        Ok(())
    }
}

struct TraceConfig {
    max_hops: u8,
    max_traces_outgoing: usize,
    retry_duration: Duration,
    retry_times: usize,
}

struct Tracer {
    config: TraceConfig,
    todo: Vec<Ipv4Addr>,
    outgoing: Vec<TraceRoute>,
    done: Vec<TraceRoute>,
    ts: TransportSender,
    tr: TransportReceiver,
    last_sent_id: u16,
}

impl Tracer {
    fn new(todo: Vec<Ipv4Addr>, config: TraceConfig) -> Result<Self> {
        let icmp = TransportChannelType::Layer3(ip::IpNextHeaderProtocols::Icmp);
        let (ts, tr) = transport_channel(2048, icmp)?;

        Ok(Self {
            config,
            todo,
            outgoing: vec![],
            done: vec![],
            ts,
            tr,
            last_sent_id: 0,
        })
    }

    fn trace_all(&mut self) -> Result<()> {
        let mut packet_iter = ipv4_packet_iter(&mut self.tr);
        while !(self.todo.is_empty() && self.outgoing.is_empty()) {
            // send echos until max_outgoing
            while !self.todo.is_empty() && self.outgoing.len() < self.config.max_traces_outgoing {
                let next_trace_target = self.todo.pop().expect("not empty");
                self.last_sent_id += 1;
                send_echo(&mut self.ts, 1, next_trace_target, 1, self.last_sent_id)?;
                self.outgoing.push(TraceRoute {
                    target: next_trace_target,
                    hops: vec![],
                    hopinfo: HopInfo {
                        retry: 0,
                        since: Instant::now(),
                        id: self.last_sent_id,
                    },
                })
            }

            let (oldest_time, oldest_idx) = self
                .outgoing
                .iter()
                .enumerate()
                .map(|(idx, info)| (info.hopinfo.since, idx))
                .min()
                .expect("not empty");
            let elapsed = Instant::now().duration_since(oldest_time);
            let wait_time = self.config.retry_duration.checked_sub(elapsed);
            if let Some((packet, _)) = wait_time
                .map(|t| packet_iter.next_with_timeout(t).ok())
                .flatten()
                .flatten()
            {
                let received_ip_addr = packet.get_source();
                if packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                    continue;
                }
                let packet = icmp::IcmpPacket::new(packet.payload()).context("Failed to decode")?;
                match packet.get_icmp_type() {
                    icmp::IcmpTypes::TimeExceeded => {
                        let packet = icmp::time_exceeded::TimeExceededPacket::new(packet.packet())
                            .context("Failed to decode")?;
                        let packet = ipv4::Ipv4Packet::new(packet.payload()).context("valid")?;

                        let id = packet.get_identification();
                        for trace in &mut self.outgoing {
                            if id == trace.hopinfo.id {
                                println!(
                                    "[{}] hop\t{}:\t{} (ID={id})",
                                    trace.target,
                                    1 + trace.hops.len(),
                                    received_ip_addr,
                                );
                                trace.hops.push(Some(received_ip_addr));
                                self.last_sent_id += 1;

                                send_echo(
                                    &mut self.ts,
                                    1,
                                    trace.target,
                                    1 + trace.hops.len() as u8,
                                    self.last_sent_id,
                                )?;
                                trace.hopinfo = HopInfo {
                                    since: Instant::now(),
                                    retry: 0,
                                    id: self.last_sent_id,
                                };
                                break;
                            }
                        }
                    }
                    icmp::IcmpTypes::EchoReply => {
                        if let Some((idx, _)) = self
                            .outgoing
                            .iter()
                            .enumerate()
                            .find(|(_, trace)| trace.target == received_ip_addr)
                        {
                            let mut done = self.outgoing.swap_remove(idx);
                            done.hops.push(Some(received_ip_addr));
                            println!("[{}]: DONE -> {:?}", done.target, done.hops);
                            self.done.push(done);
                        }
                    }
                    //icmp::IcmpTypes::TimeExceeded => continue,
                    //icmp::IcmpTypes::DestinationUnreachable => continue,
                    _ => {}
                }
            } else {
                let oldest = &mut self.outgoing[oldest_idx];
                if oldest.hopinfo.retry < self.config.retry_times {
                    send_echo(
                        &mut self.ts,
                        1,
                        oldest.target,
                        1 + oldest.hops.len() as u8,
                        oldest.hopinfo.id,
                    )?;
                    oldest.hopinfo.retry += 1;
                    oldest.hopinfo.since = Instant::now();
                    println!(
                        "[{}] hop\t{}:\t RETRY {}",
                        oldest.target,
                        1 + oldest.hops.len(),
                        oldest.hopinfo.retry
                    );
                } else if (oldest.hops.len() as u8) < self.config.max_hops - 1 {
                    println!("[{}] hop\t{}:\t *", oldest.target, 1 + oldest.hops.len());

                    oldest.hops.push(None);
                    self.last_sent_id += 1;

                    send_echo(
                        &mut self.ts,
                        1,
                        oldest.target,
                        oldest.hops.len() as u8,
                        self.last_sent_id,
                    )?;
                    oldest.hopinfo = HopInfo {
                        since: Instant::now(),
                        retry: 0,
                        id: self.last_sent_id,
                    }
                } else {
                    let oldest = self.outgoing.swap_remove(oldest_idx);
                    println!("[{}] MAX_HOPS_REACHED {:?}", oldest.target, oldest.hops);
                }
            }
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let ips = vec![
        Ipv4Addr::new(142, 250, 179, 195),
        Ipv4Addr::new(200, 147, 35, 149),
        Ipv4Addr::new(142, 251, 36, 3),
        Ipv4Addr::new(142, 250, 179, 163),
    ];
    let mut tracer = Tracer::new(
        ips,
        TraceConfig {
            max_hops: 32,
            max_traces_outgoing: 2,
            retry_times: 2,
            retry_duration: Duration::new(1, 0),
        },
    )?;

    tracer.trace_all()?;

    println!("ROUTES:");
    for route in tracer.done {
        println!("{route}");
    }
    Ok(())
}

fn _old_traceroute(dest_ip: Ipv4Addr) -> Result<()> {
    let icmp = TransportChannelType::Layer3(ip::IpNextHeaderProtocols::Icmp);
    let (mut tx, _) = transport_channel(2048, icmp)?;
    let (_, mut rx) = transport_channel(2048, icmp)?;

    let mut send_echo = |ttl| send_echo(&mut tx, 1, dest_ip, ttl, 42);

    let mut last_ttl = 1;
    send_echo(last_ttl)?;
    let mut rx_iter = ipv4_packet_iter(&mut rx);

    loop {
        let (res_ip_packet, res_ip_addr) = match rx_iter.next_with_timeout(Duration::new(1, 0))? {
            Some(r) => r,
            _ => {
                println!("hop {last_ttl}:\t*");
                last_ttl += 1;
                send_echo(last_ttl)?;
                continue;
            }
        };

        let res_icmp_pkg =
            icmp::IcmpPacket::new(res_ip_packet.payload()).context("Failed to decode")?;

        println!("hop {last_ttl}:\t{res_ip_addr}");
        if res_icmp_pkg.get_icmp_type() != icmp::IcmpType(11) {
            // todo: check source ip to make sure we are really done
            println!("DONE {}", (res_ip_addr == dest_ip));
            break;
        }
        last_ttl += 1;
        send_echo(last_ttl)?;
    }

    Ok(())
}
