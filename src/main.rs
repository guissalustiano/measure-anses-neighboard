mod echo;
mod tracer;

use crate::tracer::TraceConfig;
use anyhow::Result;
use rand::{seq::IteratorRandom, thread_rng};
use std::{
    env,
    fs::{read_to_string, File},
    io::Write,
    net::Ipv4Addr,
    str::FromStr,
    sync::mpsc::channel,
    thread,
    time::Duration,
};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let ips = ips_from_csv(&args[1], 100)?;
    let ips_len = ips.len();

    let mut tracer = tracer::Tracer::new(
        ips,
        TraceConfig {
            max_hops: 30,
            max_traces_outgoing: 4,
            retry_times: 0,
            timeout_duration: Duration::new(1, 0),
        },
    )?;
    let mut output = File::create("output.txt")?;
    thread::scope(move |s| -> Result<()> {
        let (sender, receiver) = channel();

        s.spawn(move || {
            tracer.trace_all(sender);
        });

        for (idx, traceroute) in receiver.iter().enumerate() {
            println!("[{}/{}]{traceroute}", 1 + idx, ips_len);
            output.write_fmt(format_args!("{traceroute}\n"))?;
        }
        Ok(())
    })
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

fn _get_ips(path: &str, num: usize) -> Result<Vec<Ipv4Addr>> {
    let mut rng = thread_rng();

    Ok(read_to_string(path)?
        .lines()
        .skip(1)
        .take(1_000_000)
        .filter_map(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            let block = u64::from_str_radix(parts[0], 16).ok()?;
            let octet = u8::from_str_radix(parts[1].split(',').next()?, 16).ok()?;

            Some(Ipv4Addr::new(
                ((block >> 24) & 0xff) as u8,
                ((block >> 16) & 0xff) as u8,
                ((block >> 8) & 0xff) as u8,
                octet,
            ))
        })
        .choose_multiple(&mut rng, num))
}
