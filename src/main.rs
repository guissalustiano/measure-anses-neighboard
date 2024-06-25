use anyhow::{bail, Context, Result};
use pnet::{
    packet::{
        icmp::{self, IcmpPacket},
        ip::{self, IpNextHeaderProtocols},
        ipv4::{self, Ipv4Packet},
        Packet,
    },
    transport::{self, ipv4_packet_iter, transport_channel, TransportChannelType, TransportSender},
};
use rand::Rng;
use serde_with::{serde_as, TimestampMilliSeconds};
use std::{
    collections::{BTreeSet, VecDeque},
    fs,
    net::Ipv4Addr,
    str::FromStr,
    sync::mpsc,
    thread,
    time::{Duration, SystemTime},
};

use rand_pcg::Pcg64;
use rand_seeder::Seeder;

use indicatif::ProgressBar;

const MAX_PARALLEL_TRACEROUTES: usize = 128;
const HARD_TIMEOUT: Duration = Duration::from_secs(30);
const SOFT_TIMEOUT: Duration = Duration::from_secs(1);
const MIN_TIME_BETWEEN_PACKAGES: Duration = Duration::from_secs(30);
const MAX_HOPS: u8 = 24;
const FILENAME: &str = "data.csv";
const SEED: u16 = 404;

// SendCommand -> WaitCommand -> DataRecord
// send_queue -> wait_queue -> write
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SendCommand {
    destination: Ipv4Addr,
    ttl: u8,
}
type SendQueue = VecDeque<SendCommand>;

#[derive(Debug, Clone, Copy, PartialEq)]
struct WaitCommand {
    destination: Ipv4Addr,
    ttl: u8,
    id: u16,
    send_at: SystemTime,
}
type WaitQueue = VecDeque<WaitCommand>;

#[serde_as]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DataRow {
    destination: Ipv4Addr,
    ttl: u8,
    id: u16,
    ip: Ipv4Addr,
    #[serde_as(as = "TimestampMilliSeconds<i64>")]
    send_at: SystemTime,
    #[serde_as(as = "TimestampMilliSeconds<i64>")]
    received_at: SystemTime,
    terminator: bool,
}

fn setup_log() -> Result<()> {
    fern::Dispatch::new()
        // Perform allocation-free log formatting
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {} {}] {}",
                humantime::format_rfc3339(std::time::SystemTime::now()),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .chain(fern::log_file("output.log")?)
        // .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

fn load_ips() -> Result<Vec<Ipv4Addr>> {
    use rand::seq::SliceRandom;

    let mut rng: Pcg64 = Seeder::from(SEED).make_rng();
    let mut ips = include_str!("ips.csv")
        .lines()
        .map(Ipv4Addr::from_str)
        .collect::<Result<Vec<_>, _>>()?;

    ips.shuffle(&mut rng);

    Ok(ips)
}

// generate batchs of commands
fn generate_send_queue(ips: Vec<Ipv4Addr>) -> SendQueue {
    let ratio = MIN_TIME_BETWEEN_PACKAGES.as_millis() / SOFT_TIMEOUT.as_millis();
    log::info!("{ratio}");
    ips.chunks(MAX_PARALLEL_TRACEROUTES * ratio as usize)
        .flat_map(|ip_windows| {
            (1..=MAX_HOPS).flat_map(|ttl| {
                ip_windows
                    .iter()
                    .map(move |&destination| SendCommand { destination, ttl })
            })
        })
        .collect()
}

fn spawn_writter(filename: &'static str) -> mpsc::Sender<DataRow> {
    let (tx, rx) = mpsc::channel::<DataRow>();
    thread::spawn(move || {
        let file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(filename)
            .expect("Can't create a file");

        let mut wtr = csv::Writer::from_writer(file);
        /*
        if let Err(e) = wtr.write_record(&[
            "destination",
            "ttl",
            "ip",
            "send_at",
            "received_at",
            "id",
            "unreachable",
        ]) {
            log::error!("Fail to write to a file: {e:?}");
        }
        */

        loop {
            let Ok(row) = rx.recv() else {
                log::error!("Fail to receive data");
                continue;
            };

            log::debug!("Writing: {row:?}");
            if let Err(e) = wtr.serialize(row) {
                log::error!("Fail to write to a file: {e:?}");
            };
            if let Err(e) = wtr.flush() {
                log::error!("Fail to flush to a file: {e:?}");
            };
        }
    });
    return tx;
}

fn main() -> Result<()> {
    setup_log()?;

    log::info!("Shuffluing ips");
    let ips = load_ips()?;

    log::info!("Starting queues");
    let mut send_queue = generate_send_queue(ips);
    let mut wait_queue: WaitQueue = VecDeque::with_capacity(MAX_PARALLEL_TRACEROUTES);

    let total_len = send_queue.len();
    let pb = ProgressBar::new(total_len as u64);

    remove_already_runned(&mut send_queue, FILENAME);

    let writter = spawn_writter(FILENAME);
    let (mut icmp_tx, mut icmp_rx) = icmp_transport_channel(1 << 12).unwrap();

    let mut packet_iter = ipv4_packet_iter(&mut icmp_rx);
    loop {
        log::info!("send: {}, wait: {}", send_queue.len(), wait_queue.len());
        match packet_iter.next_with_timeout(Duration::from_millis(200))? {
            Some((pkg, _)) => match handle_packets(pkg, &mut wait_queue) {
                Ok(data) => {
                    if let Err(e) = writter.send(data) {
                        log::error!("Fail to write down received pakages: {e}");
                    }
                    if data.terminator {
                        send_queue
                            .retain(|q| q.destination != data.destination || q.ttl < data.ttl);
                        if let Err(e) =
                            fill_wait_queue(&mut icmp_tx, &mut send_queue, &mut wait_queue)
                        {
                            log::warn!("Fail to send new pakages: {e}")
                        }
                    }
                }
                Err(e) => {
                    log::error!("Fail to receive pakages: {e}");
                }
            },
            None => {
                if let Err(e) = fill_wait_queue(&mut icmp_tx, &mut send_queue, &mut wait_queue) {
                    log::warn!("Fail to send new pakages: {e}")
                }
                clean_wait_queue(&mut wait_queue);

                let len = send_queue.len() + wait_queue.len();
                pb.set_position((total_len - len) as u64);
                if len == 0 {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn remove_already_runned(send_queue: &mut SendQueue, filename: &str) {
    let Ok(file) = fs::OpenOptions::new().read(true).open(filename) else {
        return;
    };

    let rdr = csv::Reader::from_reader(file);
    let already_runned: BTreeSet<_> = rdr
        .into_deserialize()
        .filter_map(|r| match r {
            Ok(r) => Some(r),
            Err(e) => {
                log::warn!("Fail on parse {e:?}");
                None
            }
        })
        .map(|r: DataRow| SendCommand {
            destination: r.destination,
            ttl: r.ttl,
        })
        .collect();

    send_queue.retain(|sc| !already_runned.contains(sc))
}

fn fill_wait_queue(
    icmp_tx: &mut TransportSender,
    send_queue: &mut SendQueue,
    wait_queue: &mut WaitQueue,
) -> Result<()> {
    let deadline = SystemTime::now() - SOFT_TIMEOUT;
    let not_delayed = wait_queue
        .iter()
        .filter(|w| w.send_at >= deadline)
        .collect::<Vec<_>>()
        .len();
    let missing_values = MAX_PARALLEL_TRACEROUTES - not_delayed;
    log::debug!("Sending {missing_values} new packages");
    (0..missing_values).try_for_each(|_| {
        let cmd = send_queue.front().context("Send queue is empty")?;
        let id = generate_unique_id(wait_queue)?;
        let res = send_echo(icmp_tx, id, *cmd)?;

        // only remove from queue if its works
        send_queue.pop_front();
        wait_queue.push_back(res);
        Ok::<_, anyhow::Error>(())
    })
}

fn clean_wait_queue(wait_queue: &mut WaitQueue) {
    let deadline = SystemTime::now() - HARD_TIMEOUT;
    wait_queue.retain(|w| w.send_at >= deadline)
}

fn generate_unique_id(wait_queue: &VecDeque<WaitCommand>) -> Result<u16> {
    let id = wait_queue
        .iter()
        .max_by_key(|w| w.send_at)
        .map(|w| w.id + 1)
        .unwrap_or_else(|| {
            let mut rng: Pcg64 = Seeder::from(SEED).make_rng();
            rng.gen()
        });

    if wait_queue.iter().any(|w| w.id == id) {
        bail!("Out of ids");
    }
    Ok(id)
}

fn icmp_transport_channel(
    buffer_size: usize,
) -> Result<(transport::TransportSender, transport::TransportReceiver), std::io::Error> {
    transport_channel(
        buffer_size,
        TransportChannelType::Layer3(ip::IpNextHeaderProtocols::Icmp),
    )
}

fn send_echo(icmp_tx: &mut TransportSender, id: u16, cmd: SendCommand) -> Result<WaitCommand> {
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
    ip_packet.set_ttl(cmd.ttl);
    ip_packet.set_next_level_protocol(ip::IpNextHeaderProtocols::Icmp);
    ip_packet.set_source(Ipv4Addr::UNSPECIFIED);
    ip_packet.set_destination(cmd.destination);

    // Construct the ICMP packet
    let mut icmp_buffer = vec![0; ICMP_LEN];
    let mut icmp_packet: icmp::echo_request::MutableEchoRequestPacket =
        icmp::echo_request::MutableEchoRequestPacket::new(&mut icmp_buffer)
            .context("fail create echo request packet")?;

    icmp_packet.set_icmp_type(icmp::IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(icmp::echo_request::IcmpCodes::NoCode);
    icmp_packet.set_identifier(id);
    icmp_packet.set_sequence_number(2);

    icmp_packet.set_checksum(pnet::util::checksum(icmp_packet.packet(), 1));

    ip_packet.set_payload(icmp_packet.packet());

    log::debug!(
        "Sending pkg {id} with ttl {} to {}",
        cmd.ttl,
        cmd.destination
    );

    let now = SystemTime::now();
    icmp_tx.send_to(ip_packet, cmd.destination.into())?;
    Ok(WaitCommand {
        destination: cmd.destination,
        ttl: cmd.ttl,
        id,
        send_at: now,
    })
}

fn handle_packets(packet: Ipv4Packet, wait_queue: &mut WaitQueue) -> Result<DataRow> {
    let now = SystemTime::now();

    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
        bail!("Receive a non ICMP package")
    }

    let source = packet.get_source();
    let packet = IcmpPacket::new(packet.payload()).context("Fail to decode to ICMP")?;

    let (id, terminator) = match packet.get_icmp_type() {
        icmp::IcmpTypes::EchoReply => {
            let packet = icmp::echo_reply::EchoReplyPacket::new(packet.packet())
                .context("Fail to parce Icmp Echo Reply")?;
            (packet.get_identifier(), true)
        }
        icmp::IcmpTypes::TimeExceeded => {
            let packet = icmp::time_exceeded::TimeExceededPacket::new(packet.packet())
                .context("Fail to parce Icmp Time Exceeded")?;

            let packet = ipv4::Ipv4Packet::new(packet.payload())
                .context("Fail to parce Icmp Time Exceeded")?;
            (packet.get_identification(), false)
        }
        icmp::IcmpTypes::DestinationUnreachable => {
            let packet =
                icmp::destination_unreachable::DestinationUnreachablePacket::new(packet.packet())
                    .context("Fail to parce Icmp Time Exceeded")?;

            let packet = ipv4::Ipv4Packet::new(packet.payload())
                .context("Fail to parce Icmp Time Exceeded")?;

            (packet.get_identification(), true)
        }
        t => {
            bail!("Invalid ICMP Type: {t:?}");
        }
    };
    log::debug!("Received pkg from {source} with id {id}");

    let wait_cmd_index = wait_queue
        .iter()
        .position(|w| w.id == id)
        .context("Package not found")?;

    let wait_cmd = wait_queue.get(wait_cmd_index).copied().context("wft?")?;
    wait_queue.remove(wait_cmd_index);

    Ok(DataRow {
        destination: wait_cmd.destination,
        ttl: wait_cmd.ttl,
        id,
        ip: source,
        send_at: now,
        received_at: wait_cmd.send_at,
        terminator,
    })
}
