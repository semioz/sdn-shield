use std::net::Ipv4Addr;

use rovs_openflow::Match;

use super::*;
use crate::COOKIE;

const DESTINATION: [u8; 6] = [0, 0, 0, 0, 0, 8];

fn flow(source: u8, packets: u64, bytes: u64, age: u32) -> FlowStatsEntry {
    FlowStatsEntry {
        table_id: 0,
        duration_sec: age,
        duration_nsec: 0,
        priority: 1,
        idle_timeout: 30,
        hard_timeout: 60,
        flags: 0,
        cookie: COOKIE,
        packet_count: packets,
        byte_count: bytes,
        match_fields: Match::new()
            .in_port(u32::from(source))
            .eth_src([0, 0, 0, 0, 0, source])
            .eth_dst(DESTINATION)
            .ipv4_src(Ipv4Addr::new(10, 0, 0, source), 32),
        instructions: Vec::new(),
    }
}

#[test]
fn sums_deltas_per_destination_using_actual_elapsed_time() {
    let before = [flow(1, 100, 10000, 10), flow(2, 500, 50000, 10)];
    let after = [flow(1, 120, 12000, 12), flow(2, 540, 54000, 12)];
    let windows = measure(&before, &after, Duration::from_secs(2)).unwrap();
    let window = &windows[&DESTINATION];
    assert_eq!((window.packets, window.bytes), (60, 6000));
    assert_eq!(
        (window.packets_per_second, window.bytes_per_second),
        (30.0, 3000.0)
    );
    assert_eq!(window.compared, 2);
    assert!(
        !window.exceeds(30.0, 3000.0),
        "equality is not an exceedance"
    );
    assert!(window.exceeds(29.0, 100000.0));
    assert!(window.exceeds(10000.0, 2999.0));
}

#[test]
fn new_flows_are_baselined_not_treated_as_window_traffic() {
    let first = [flow(1, 1000000, 100000000, 100)];
    let windows = measure(&[], &first, Duration::from_secs(1)).unwrap();
    let window = &windows[&DESTINATION];
    assert_eq!((window.new, window.compared, window.packets), (1, 0, 0));
    assert!(!window.exceeds(1.0, 1.0));
    let next = [flow(1, 1000002, 100000200, 101)];
    let windows = measure(&first, &next, Duration::from_secs(1)).unwrap();
    assert_eq!(windows[&DESTINATION].packets_per_second, 2.0);
}

#[test]
fn counter_or_duration_resets_skip_only_the_affected_flow() {
    for reset in [
        flow(1, 1, 100, 12),
        flow(1, 110, 100, 12),
        flow(1, 1000, 100000, 1),
    ] {
        let before = [flow(1, 100, 10000, 10), flow(2, 100, 10000, 10)];
        let after = [reset, flow(2, 120, 12000, 12)];
        let windows = measure(&before, &after, Duration::from_secs(2)).unwrap();
        let window = &windows[&DESTINATION];
        assert_eq!((window.reset, window.compared), (1, 1));
        assert_eq!(window.packets_per_second, 10.0);
        assert!(
            window.exceeds(9.0, 1000000.0),
            "a partial lower bound can still exceed a threshold"
        );
    }
}

#[test]
fn expired_flows_and_unsupported_counters_are_explicit() {
    let before = [flow(1, 100, 10000, 10)];
    let windows = measure(&before, &[], Duration::from_secs(1)).unwrap();
    assert_eq!(windows[&DESTINATION].expired, 1);
    for unsupported in [flow(1, u64::MAX, 10000, 11), flow(1, 100, u64::MAX, 11)] {
        let windows = measure(&before, &[unsupported], Duration::from_secs(1)).unwrap();
        let window = &windows[&DESTINATION];
        assert_eq!((window.unsupported, window.compared), (1, 0));
        assert!(!window.exceeds(1.0, 1.0));
    }
    let before = [flow(1, u64::MAX, u64::MAX, 10)];
    let after = [flow(1, 200, 20000, 11)];
    let windows = measure(&before, &after, Duration::from_secs(1)).unwrap();
    assert_eq!(windows[&DESTINATION].unsupported, 1);
}

#[test]
fn ignores_table_miss_drop_other_tables_and_foreign_rules() {
    let before = [flow(1, 10, 1000, 10)];
    let mut after = vec![flow(1, 12, 1200, 11)];
    for (cookie, priority, table) in [
        (COOKIE, 0, 0),
        (COOKIE + 1, 100, 0),
        (0, 1, 0),
        (COOKIE, 1, 1),
    ] {
        let mut ignored = flow(2, 100000, 10000000, 10);
        ignored.cookie = cookie;
        ignored.priority = priority;
        ignored.table_id = table;
        after.push(ignored);
    }
    let windows = measure(&before, &after, Duration::from_secs(1)).unwrap();
    let window = &windows[&DESTINATION];
    assert_eq!((window.compared, window.new, window.packets), (1, 0, 2));
}

#[test]
fn rejects_duplicate_flows_missing_destinations_and_zero_time() {
    let entry = flow(1, 10, 1000, 10);
    assert!(measure(&[], std::slice::from_ref(&entry), Duration::ZERO).is_err());
    assert!(measure(&[], &[entry.clone(), entry.clone()], Duration::from_secs(1)).is_err());
    let mut invalid = entry;
    invalid.match_fields.eth_dst = None;
    assert!(measure(&[], &[invalid], Duration::from_secs(1)).is_err());
}

#[test]
fn rejects_aggregate_counter_overflow() {
    let before = [flow(1, 0, 0, 10), flow(2, 0, 0, 10)];
    let after = [flow(1, u64::MAX - 1, 10, 11), flow(2, 100, 100, 11)];
    assert!(measure(&before, &after, Duration::from_secs(1)).is_err());
}
#[test]
fn entropy_is_zero_for_one_source_ip() {
    let before = [flow(1, 0, 0, 10)];
    let after = [flow(1, 100, 10000, 11)];

    let windows = measure(&before, &after, Duration::from_secs(1)).unwrap();
    let entropy = windows[&DESTINATION].source_entropy_bits().unwrap();

    assert!((entropy - 0.0).abs() < 1e-9);
}

#[test]
fn entropy_is_one_for_two_equally_active_source_ips() {
    let before = [flow(1, 0, 0, 10), flow(2, 0, 0, 10)];
    let after = [flow(1, 100, 10000, 11), flow(2, 100, 10000, 11)];

    let windows = measure(&before, &after, Duration::from_secs(1)).unwrap();
    let entropy = windows[&DESTINATION].source_entropy_bits().unwrap();

    assert!((entropy - 1.0).abs() < 1e-9);
}

#[test]
fn entropy_is_none_when_there_is_no_source_ip_traffic() {
    let window = Window::default();

    assert_eq!(window.source_entropy_bits(), None);
}
