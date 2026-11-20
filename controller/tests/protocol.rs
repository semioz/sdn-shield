use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[cfg(unix)]
mod management;

struct Controller {
    child: Child,
    address: String,
}

impl Controller {
    fn start() -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_sdn-shield-controller"))
            .arg("127.0.0.1:0")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut controller = Self {
            child,
            address: String::new(),
        };
        let mut line = String::new();
        BufReader::new(controller.child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        controller.address = line
            .trim()
            .strip_prefix("LISTENING ")
            .expect("controller must announce its listening address")
            .to_owned();
        controller
    }

    fn connect(&self) -> TcpStream {
        let mut stream = TcpStream::connect(&self.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.set_nodelay(true).unwrap();
        let (kind, _, _) = receive(&mut stream);
        assert_eq!(kind, 0, "controller must send Hello first");
        stream
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.child.kill();
        self.child.wait().unwrap();
    }
}

fn frame(kind: u8, xid: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![4, kind];
    bytes.extend_from_slice(&u16::try_from(8 + body.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&xid.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn receive(stream: &mut impl Read) -> (u8, u32, Vec<u8>) {
    let mut header = [0; 8];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header[0], 4);
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    assert!(length >= 8);
    let mut body = vec![0; length - 8];
    stream.read_exact(&mut body).unwrap();
    (
        header[1],
        u32::from_be_bytes(header[4..8].try_into().unwrap()),
        body,
    )
}

fn handshake(stream: &mut TcpStream) {
    // Independent wire fixtures verify the library's output, not just round-trips.
    let hello = frame(0, 42, &[]);
    stream.write_all(&hello[..3]).unwrap();
    stream.write_all(&hello[3..]).unwrap();
    let (kind, xid, body) = receive(stream);
    assert_eq!(kind, 5);
    assert!(body.is_empty());
    let mut features = vec![0; 24];
    features[7] = 1;
    features[12] = 1;
    stream.write_all(&frame(6, xid, &features)).unwrap();
    let (kind, _, flow) = receive(stream);
    assert_eq!(kind, 14);
    assert_eq!(&flow[22..24], &[0, 0], "table-miss priority must be zero");
    assert_eq!(&flow[60..64], &0xffff_fffdu32.to_be_bytes());
    assert_eq!(&flow[64..66], &u16::MAX.to_be_bytes());
    let (kind, xid, body) = receive(stream);
    assert_eq!(kind, 20);
    assert!(body.is_empty());
    stream.write_all(&frame(21, xid, &[])).unwrap();
}

fn packet_in(port: u32, source: [u8; 6], destination: [u8; 6]) -> Vec<u8> {
    let mut ethernet = destination.to_vec();
    ethernet.extend_from_slice(&source);
    ethernet.extend_from_slice(&[0x08, 0x00]);
    ethernet.resize(60, 0);

    // Add a valid IPv4 header after the 14-byte Ethernet header.
    ethernet[14] = 0x45; // IPv4, 20-byte header
    ethernet[16..18].copy_from_slice(&46u16.to_be_bytes());
    ethernet[22] = 64; // TTL
    ethernet[23] = 6; // TCP
    ethernet[26..30].copy_from_slice(&[10, 0, 0, 1]);
    ethernet[30..34].copy_from_slice(&[10, 0, 0, 2]);

    let mut body = u32::MAX.to_be_bytes().to_vec();
    body.extend_from_slice(&(ethernet.len() as u16).to_be_bytes());
    body.extend_from_slice(&[0; 10]);
    body.extend_from_slice(&[0, 1, 0, 12, 0x80, 0, 0, 4]);
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&[0; 6]);
    body.extend_from_slice(&ethernet);
    frame(10, 50, &body)
}
#[test]
fn handshake_echo_and_reconnect() {
    let controller = Controller::start();
    let mut stream = controller.connect();
    handshake(&mut stream);
    let payload = b"sdn-shield echo";
    stream.write_all(&frame(2, 123, payload)).unwrap();
    let (kind, xid, body) = receive(&mut stream);
    assert_eq!((kind, xid, body.as_slice()), (3, 123, payload.as_slice()));
    drop(stream);
    handshake(&mut controller.connect());
}

#[test]
fn learns_macs_and_installs_unicast_flows() {
    let controller = Controller::start();
    let mut stream = controller.connect();
    handshake(&mut stream);
    stream
        .write_all(&packet_in(1, [0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 2]))
        .unwrap();
    let (kind, _, packet) = receive(&mut stream);
    assert_eq!(kind, 13);
    assert_eq!(&packet[4..8], &1u32.to_be_bytes());
    assert_eq!(
        &packet[20..24],
        &0xffff_fffbu32.to_be_bytes(),
        "unknown destination must flood"
    );
    assert_eq!(packet.len(), 16 + 16 + 60);
    stream
        .write_all(&packet_in(2, [0, 0, 0, 0, 0, 2], [0, 0, 0, 0, 0, 1]))
        .unwrap();
    let (kind, _, flow) = receive(&mut stream);
    assert_eq!(kind, 14);
    assert_eq!(&flow[22..24], &1u16.to_be_bytes());
    assert_eq!(&flow[18..22], &[0, 30, 0, 60]);
    assert!(
        flow.windows(8)
            .any(|part| part == [0x80, 0, 0, 4, 0, 0, 0, 2])
    );
    let (kind, _, packet) = receive(&mut stream);
    assert_eq!(kind, 13);
    assert_eq!(
        &packet[20..24],
        &1u32.to_be_bytes(),
        "learned destination must use port 1"
    );
}

#[test]
fn rejects_bad_headers_and_recovers() {
    let controller = Controller::start();
    for bytes in [
        vec![4, 0, 0, 7, 0, 0, 0, 0],
        frame(10, 1, &[]),
        vec![1, 0, 0, 8, 0, 0, 0, 0],
    ] {
        let mut stream = controller.connect();
        stream.write_all(&bytes).unwrap();
        assert_eq!(
            stream.read(&mut [0]).unwrap(),
            0,
            "invalid session must close"
        );
    }
    handshake(&mut controller.connect());
}

#[test]
fn rejects_malformed_packet_in() {
    let controller = Controller::start();
    for bytes in [
        frame(10, 1, &[0; 20]),
        packet_in(0, [0; 6], [1; 6]),
        packet_in(1, [1; 6], [0; 6]),
    ] {
        let mut stream = controller.connect();
        handshake(&mut stream);
        stream.write_all(&bytes).unwrap();
        assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    }
    let mut stream = controller.connect();
    handshake(&mut stream);
    let mut truncated = packet_in(1, [0, 0, 0, 0, 0, 1], [0; 6]);
    truncated[12..14].copy_from_slice(&100u16.to_be_bytes());
    stream.write_all(&truncated).unwrap();
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    drop(stream);
    let mut stream = controller.connect();
    handshake(&mut stream);
    let mut vlan = packet_in(1, [0, 0, 0, 0, 0, 1], [0; 6]);
    vlan[54..56].copy_from_slice(&0x8100u16.to_be_bytes());
    stream.write_all(&vlan).unwrap();
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
}

#[test]
fn releases_buffered_packets_without_resending_data() {
    let controller = Controller::start();
    let mut stream = controller.connect();
    handshake(&mut stream);
    let mut packet = packet_in(1, [0, 0, 0, 0, 0, 1], [0xff; 6]);
    packet[8..12].copy_from_slice(&123u32.to_be_bytes());
    stream.write_all(&packet).unwrap();
    let (kind, _, body) = receive(&mut stream);
    assert_eq!(kind, 13);
    assert_eq!(&body[..4], &123u32.to_be_bytes());
    assert_eq!(body.len(), 32);
}

#[test]
fn filters_destinations_on_the_ingress_port() {
    let controller = Controller::start();
    let mut stream = controller.connect();
    handshake(&mut stream);
    stream
        .write_all(&packet_in(1, [0, 0, 0, 0, 0, 1], [0xff; 6]))
        .unwrap();
    assert_eq!(receive(&mut stream).0, 13);
    stream
        .write_all(&packet_in(1, [0, 0, 0, 0, 0, 2], [0, 0, 0, 0, 0, 1]))
        .unwrap();
    stream.write_all(&frame(2, 77, &[])).unwrap();
    assert_eq!(
        receive(&mut stream).0,
        3,
        "same-port traffic must not produce PacketOut or FlowMod"
    );
}

#[test]
fn bounds_mac_learning_memory() {
    let controller = Controller::start();
    let mut stream = controller.connect();
    handshake(&mut stream);
    for index in 0u32..4096 {
        let mut source = [2, 0, 0, 0, 0, 0];
        source[2..].copy_from_slice(&index.to_be_bytes());
        stream.write_all(&packet_in(1, source, [0xff; 6])).unwrap();
        assert_eq!(receive(&mut stream).0, 13);
    }
    stream
        .write_all(&packet_in(1, [4, 0, 0, 0, 0, 1], [0xff; 6]))
        .unwrap();
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    drop(stream);
    handshake(&mut controller.connect());
}
