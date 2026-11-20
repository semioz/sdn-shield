use std::collections::BTreeMap;
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rovs_openflow::FlowStatsEntry;

use crate::control::{connect, stats};
use crate::{COOKIE, Result};

#[derive(Debug, Default)]
struct Window {
    packets: u64,
    bytes: u64,
    packets_per_second: f64,
    bytes_per_second: f64,
    compared: usize,
    new: usize,
    reset: usize,
    unsupported: usize,
    expired: usize,
    source_packets: BTreeMap<Ipv4Addr, u64>,
}

impl Window {
    fn exceeds(&self, packet_limit: f64, byte_limit: f64) -> bool {
        self.packets_per_second > packet_limit || self.bytes_per_second > byte_limit
    }

    fn source_entropy_bits(&self) -> Option<f64> {
        let total: f64 = self
            .source_packets
            .values()
            .map(|&count| count as f64)
            .sum();

        if total == 0.0 {
            return None;
        }

        let entropy = self
            .source_packets
            .values()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let probability = count as f64 / total;
                -probability * probability.log2()
            })
            .sum();

        Some(entropy)
    }
}

fn index(entries: &[FlowStatsEntry]) -> Result<BTreeMap<String, &FlowStatsEntry>> {
    let mut indexed = BTreeMap::new();
    for entry in entries {
        if entry.cookie != COOKIE || entry.table_id != 0 || entry.priority != 1 {
            continue;
        }
        if entry.match_fields.eth_dst.is_none()
            || entry.match_fields.eth_src.is_none()
            || !entry
                .match_fields
                .in_port
                .is_some_and(|port| port > 0 && port < 0xffff_ff00)
            || entry.duration_nsec >= 1_000_000_000
        {
            return Err("invalid forwarding flow identity or duration".into());
        }
        if indexed
            .insert(entry.match_fields.to_string(), entry)
            .is_some()
        {
            return Err("duplicate forwarding flow in statistics snapshot".into());
        }
    }
    Ok(indexed)
}

// shortcut: snapshot gaps omit new/reset/expired flow traffic; add lifecycle accounting before claiming full coverage.
fn measure(
    previous: &[FlowStatsEntry],
    current: &[FlowStatsEntry],
    elapsed: Duration,
) -> Result<BTreeMap<[u8; 6], Window>> {
    if elapsed.is_zero() {
        return Err("invalid zero measurement interval".into());
    }
    let previous = index(previous)?;
    let current = index(current)?;
    let mut windows: BTreeMap<[u8; 6], Window> = BTreeMap::new();
    for (key, entry) in &current {
        let window = windows
            .entry(entry.match_fields.eth_dst.unwrap())
            .or_default();
        let old = previous.get(key);
        if entry.packet_count == u64::MAX
            || entry.byte_count == u64::MAX
            || old.is_some_and(|old| old.packet_count == u64::MAX || old.byte_count == u64::MAX)
        {
            window.unsupported += 1;
            continue;
        }
        let Some(old) = old else {
            window.new += 1;

            if let Some(source_ip) = entry.match_fields.ipv4_src {
                window.source_packets.insert(source_ip, entry.packet_count);
            }

            continue;
        };
        if entry.packet_count < old.packet_count
            || entry.byte_count < old.byte_count
            || (entry.duration_sec, entry.duration_nsec) < (old.duration_sec, old.duration_nsec)
        {
            window.reset += 1;
            continue;
        }
        let packet_delta = entry.packet_count - old.packet_count;

        window.packets = window
            .packets
            .checked_add(packet_delta)
            .ok_or("aggregate packet counter overflow")?;

        window.bytes = window
            .bytes
            .checked_add(entry.byte_count - old.byte_count)
            .ok_or("aggregate byte counter overflow")?;

        if let Some(source_ip) = entry.match_fields.ipv4_src {
            let source_packets = window.source_packets.entry(source_ip).or_default();

            *source_packets = source_packets
                .checked_add(packet_delta)
                .ok_or("source IP packet counter overflow")?;
        }

        window.compared += 1;
    }
    for (key, entry) in &previous {
        if !current.contains_key(key) {
            windows
                .entry(entry.match_fields.eth_dst.unwrap())
                .or_default()
                .expired += 1;
        }
    }
    for window in windows.values_mut() {
        window.packets_per_second = window.packets as f64 / elapsed.as_secs_f64();
        window.bytes_per_second = window.bytes as f64 / elapsed.as_secs_f64();
    }
    Ok(windows)
}

fn limit(value: &str) -> Result<f64> {
    value
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value > 0.0)
        .ok_or_else(|| "invalid threshold: expected a positive finite rate".into())
}

pub fn run(args: &[String]) -> Result<()> {
    let [_, path, interval_ms, windows, packet_limit, byte_limit] = args else {
        return Err("usage: monitor SOCKET INTERVAL_MS WINDOWS PPS_LIMIT BYTE_LIMIT".into());
    };
    let interval_ms = interval_ms
        .parse::<u64>()
        .ok()
        .filter(|value| (1..=60000).contains(value))
        .ok_or("invalid interval: expected 1..60000 milliseconds")?;
    let windows = windows
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or("invalid window count: expected a positive integer")?;
    let packet_limit = limit(packet_limit)?;
    let byte_limit = limit(byte_limit)?;
    let mut stream = connect(path)?;
    let started = Instant::now();
    let mut previous = stats(&mut stream)?;
    let mut previous_at = Instant::now();
    println!(
        "MONITOR_READY interval_ms={interval_ms} windows={windows} pps_limit={packet_limit} bytes_per_second_limit={byte_limit} mitigation=off"
    );
    std::io::stdout().flush()?;
    for number in 1..=windows {
        std::thread::sleep(
            (previous_at + Duration::from_millis(interval_ms))
                .saturating_duration_since(Instant::now()),
        );
        let current = stats(&mut stream)?;
        let observed_at = Instant::now();
        let elapsed = observed_at.duration_since(previous_at);
        let measured = measure(&previous, &current, elapsed)?;
        let observed_seconds = observed_at.duration_since(started).as_secs_f64();
        for (destination, window) in &measured {
            let destination = destination
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            let complete = window.new + window.reset + window.unsupported + window.expired == 0;
            let alarm = window.exceeds(packet_limit, byte_limit);
            let source_count = window
                .source_packets
                .values()
                .filter(|&&packets| packets > 0)
                .count();
            let source_ips = window
                .source_packets
                .iter()
                .filter(|&(_, &packets)| packets > 0)
                .map(|(ip, _)| ip.to_string())
                .collect::<Vec<_>>()
                .join(",");

            let source_entropy = window
                .source_entropy_bits()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "na".to_string());
            println!(
                "SAMPLE window={number} destination={destination} observed_seconds={observed_seconds} elapsed_seconds={} packets={} bytes={} packets_per_second={} bytes_per_second={} source_count={source_count} source_ips={source_ips} source_entropy_bits={source_entropy} compared={} new={} reset={} unsupported={} expired={} complete={} alarm={}",
                elapsed.as_secs_f64(),
                window.packets,
                window.bytes,
                window.packets_per_second,
                window.bytes_per_second,
                window.compared,
                window.new,
                window.reset,
                window.unsupported,
                window.expired,
                u8::from(complete),
                u8::from(alarm)
            );
            if alarm {
                println!(
                    "THRESHOLD_ALARM window={number} destination={destination} observed_seconds={observed_seconds} packets_per_second={} bytes_per_second={} complete={}",
                    window.packets_per_second,
                    window.bytes_per_second,
                    u8::from(complete)
                );
            }
        }
        println!(
            "WINDOW_END window={number} observed_seconds={observed_seconds} elapsed_seconds={} destinations={}",
            elapsed.as_secs_f64(),
            measured.len()
        );
        std::io::stdout().flush()?;
        previous = current;
        previous_at = observed_at;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
