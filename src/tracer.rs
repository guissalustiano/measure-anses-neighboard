use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::Packet;
use pnet::packet::{icmp, ip::IpNextHeaderProtocols};
use pnet::transport::TransportChannelType;
use std::iter;
use std::sync::mpsc::{Receiver, Sender};
use std::{
    fmt::Display,
    net::Ipv4Addr,
    sync::mpsc::channel,
    thread,
    time::{Duration, Instant},
};

use pnet::{
    packet::{icmp::IcmpType, ip, ipv4},
    transport::{ipv4_packet_iter, transport_channel, TransportReceiver, TransportSender},
};

use crate::echo::send_echo;

use anyhow::Result;

struct TraceReply {
    id: Option<u16>,
    ip: Ipv4Addr,
    icmp_type: IcmpType,
    since: Instant,
}

struct HopInfo {
    since: Instant,
    retry: usize,
    id: u16,
}

pub struct Hop {
    pub ip: Ipv4Addr,
    pub rtd: Duration,
}
impl Display for Hop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{} ({}ms)", self.ip, self.rtd.as_millis()))?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum TraceState {
    InProgress,
    Reached,
    TimedOut,
    Unreachable,
}

pub struct TraceRoute {
    pub target: Ipv4Addr,
    pub hops: Vec<Option<Hop>>,
    hopinfo: HopInfo,
    state: TraceState,
}

impl Display for TraceRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{} ({:?})", self.target, self.state))?;
        for h in &self.hops {
            match h {
                Some(ip) => f.write_fmt(format_args!(", {}", &ip.to_string()))?,
                None => f.write_str(", *")?,
            };
        }
        Ok(())
    }
}

pub struct TraceConfig {
    pub max_hops: u8,
    pub max_traces_outgoing: usize,
    pub timeout_duration: Duration,
    pub retry_times: usize,
}

pub struct Tracer {
    config: TraceConfig,
    todo: Vec<Ipv4Addr>,
    outgoing: Vec<TraceRoute>,
    last_sent_id: u16,
}

impl Tracer {
    pub fn new(todo: Vec<Ipv4Addr>, config: TraceConfig) -> Result<Self> {
        Ok(Self {
            config,
            todo,
            outgoing: vec![],
            last_sent_id: 0,
        })
    }

    fn start_trace(&mut self, ts: &mut TransportSender, id: u16, target: Ipv4Addr, ttl: u8) {
        let _ = send_echo(ts, id, target, ttl, id);
        self.outgoing.push(TraceRoute {
            target,
            hops: vec![],
            hopinfo: HopInfo {
                retry: 0,
                since: Instant::now(),
                id,
            },
            state: TraceState::InProgress,
        })
    }

    fn start_new_tracerouts(&mut self, ts: &mut TransportSender) {
        while !self.todo.is_empty() && self.outgoing.len() < self.config.max_traces_outgoing {
            let next_trace_target = self.todo.pop().expect("not empty");
            self.last_sent_id += 1;
            self.start_trace(ts, self.last_sent_id, next_trace_target, 1)
        }
    }

    fn duration_until_oldest_trace_timeout(&self) -> Option<(Option<Duration>, usize)> {
        self.outgoing
            .iter()
            .enumerate()
            .map(|(idx, info)| (info.hopinfo.since, idx))
            .min()
            .map(|(oldest_time, idx)| {
                (
                    self.config
                        .timeout_duration
                        .checked_sub(Instant::now().duration_since(oldest_time)),
                    idx,
                )
            })
    }

    fn handle_timeout(
        &mut self,
        ts: &mut TransportSender,
        oldest_idx: usize,
        output: &Sender<TraceRoute>,
    ) {
        //print!(".");
        let oldest = &mut self.outgoing[oldest_idx];
        if oldest.hopinfo.retry < self.config.retry_times {
            let _ = send_echo(
                ts,
                oldest.hopinfo.id,
                oldest.target,
                1 + oldest.hops.len() as u8,
                oldest.hopinfo.id,
            );
            oldest.hopinfo.retry += 1;
            oldest.hopinfo.since = Instant::now();
        } else if (oldest.hops.len() as u8) < self.config.max_hops - 1 {
            oldest.hops.push(None);
            self.last_sent_id += 1;
            let _ = send_echo(
                ts,
                oldest.hopinfo.id,
                oldest.target,
                1 + oldest.hops.len() as u8,
                self.last_sent_id,
            );
            oldest.hopinfo = HopInfo {
                since: Instant::now(),
                retry: 0,
                id: self.last_sent_id,
            };
        } else {
            let mut trace = self.outgoing.swap_remove(oldest_idx);
            trace.state = TraceState::TimedOut;
            let _ = output.send(trace);
        }
    }

    fn handle_reply(
        &mut self,
        ts: &mut TransportSender,
        trace_reply: TraceReply,
        output: &Sender<TraceRoute>,
    ) {
        //print!("#");
        if let Some((idx, trace)) = self.outgoing.iter_mut().enumerate().find(|(_, trace)| {
            (trace_reply.id.is_some() && trace.hopinfo.id == trace_reply.id.unwrap())
                || trace_reply.ip == trace.target
        }) {
            trace.hops.push(Some(Hop {
                ip: trace_reply.ip,
                rtd: trace_reply
                    .since
                    .saturating_duration_since(trace.hopinfo.since),
            }));
            match trace_reply.icmp_type {
                IcmpTypes::EchoReply => {
                    let mut trace = self.outgoing.swap_remove(idx);
                    trace.state = TraceState::Reached;
                    let _ = output.send(trace);
                }
                IcmpTypes::DestinationUnreachable => {
                    let mut trace = self.outgoing.swap_remove(idx);
                    trace.state = TraceState::Unreachable;
                    let _ = output.send(trace);
                }

                IcmpTypes::TimeExceeded => {
                    if (trace.hops.len() as u8) < self.config.max_hops - 1 {
                        self.last_sent_id += 1;
                        let _ = send_echo(
                            ts,
                            self.last_sent_id,
                            trace.target,
                            1 + trace.hops.len() as u8,
                            self.last_sent_id,
                        );
                        trace.hopinfo = HopInfo {
                            since: Instant::now(),
                            retry: 0,
                            id: self.last_sent_id,
                        };
                        return;
                    } else {
                        let mut trace = self.outgoing.swap_remove(idx);
                        trace.state = TraceState::TimedOut;
                        let _ = output.send(trace);
                    }
                }
                _ => todo!(),
            };
        }   else {
            println!("SHOULD NOT BE REACHED");
        }
    }

    pub fn trace_all(&mut self, output: Sender<TraceRoute>) {
        let icmp = TransportChannelType::Layer3(ip::IpNextHeaderProtocols::Icmp);
        let (mut ts, tr) = transport_channel(2048, icmp).unwrap();

        let (signal_done, is_done) = channel();
        let (received_packet_sender, received_packet_receiver) = channel();

        thread::scope(move |s| {
            // receive packet thread
            s.spawn(move || {
                receive_packets(tr, received_packet_sender, is_done);
            });
            while !(self.todo.is_empty() && self.outgoing.is_empty()) {
                // send echos until max_outgoing
                self.start_new_tracerouts(&mut ts);

                let (wait_time, oldest_idx) = self
                    .duration_until_oldest_trace_timeout()
                    .expect("not empty");

                if let Some(r) = wait_time
                    .map(|t| received_packet_receiver.recv_timeout(t).ok())
                    .flatten()
                {
                    for r in iter::once(r).chain(received_packet_receiver.try_iter()) {
                        self.handle_reply(&mut ts, r, &output)
                    }
                } else {
                    self.handle_timeout(&mut ts, oldest_idx, &output);
                    continue;
                };
            }

            let _ = signal_done.send(());
        });
    }
}

fn receive_packets(
    mut tr: TransportReceiver,
    received_packet_sender: Sender<TraceReply>,
    is_done: Receiver<()>,
) {
    let mut packet_iter = ipv4_packet_iter(&mut tr);
    while !is_done.try_recv().is_ok() {
        if let Some((packet, _)) = packet_iter
            .next_with_timeout(Duration::new(1, 0))
            .ok()
            .flatten()
        {
            //skip non icmp
            if packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                //println!(",");
                break;
            }

            let icmp_packet = IcmpPacket::new(packet.payload()).unwrap();
            let id = match icmp_packet.get_icmp_type() {
                IcmpTypes::TimeExceeded => Some(
                    ipv4::Ipv4Packet::new(
                        icmp::time_exceeded::TimeExceededPacket::new(icmp_packet.packet())
                            .unwrap()
                            .payload(),
                    )
                    .unwrap()
                    .get_identification(),
                ),
                IcmpTypes::DestinationUnreachable => Some(
                    ipv4::Ipv4Packet::new(
                        icmp::destination_unreachable::DestinationUnreachablePacket::new(
                            icmp_packet.packet(),
                        )
                        .unwrap()
                        .payload(),
                    )
                    .unwrap()
                    .get_identification(),
                ),
                _ => None,
            };
            let _ = received_packet_sender.send(TraceReply {
                ip: packet.get_source(),
                id,
                icmp_type: icmp_packet.get_icmp_type(),
                since: Instant::now(),
            });
        }
    }
}
