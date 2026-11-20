use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::Duration;

mod control;
mod monitor;

use rovs_openflow::{
    ActionList, Flow, Header, Match, Message, MessageType, OfError, OutputPort, PacketIn,
    PacketOut, Version,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const COOKIE: u64 = 0x5344_4e00_0000_0001;
const MAX_MACS: usize = 4096;

fn read_message(stream: &mut impl Read) -> Result<Message> {
    let mut bytes = [0; Header::SIZE];
    stream.read_exact(&mut bytes)?;
    let header = Header::decode(&mut bytes.to_vec().into())?;
    if header.version != Version::Of13 || usize::from(header.length) < Header::SIZE {
        return Err("expected an OpenFlow 1.3 frame with length >= 8".into());
    }
    let mut body = vec![0; usize::from(header.length) - Header::SIZE];
    stream.read_exact(&mut body)?;
    Ok(Message {
        header,
        body: body.into(),
    })
}

fn send(stream: &mut impl Write, message: Message) -> Result<()> {
    let length = Header::SIZE + message.body.len();
    if length > usize::from(u16::MAX) || length != usize::from(message.header.length) {
        return Err("OpenFlow message exceeds its declared frame length".into());
    }
    stream.write_all(&message.encode())?;
    Ok(())
}
fn ipv4_addresses(frame: &[u8]) -> Result<Option<(Ipv4Addr, Ipv4Addr)>> {
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    // This packet is not IPv4.
    if ethertype != 0x0800 {
        return Ok(None);
    }

    // An IPv4 header must be at least 20 bytes.
    if frame.len() < 34 {
        return Err("IPv4 packet has an incomplete header".into());
    }

    let version = frame[14] >> 4;
    let header_length = usize::from(frame[14] & 0x0f) * 4;

    if version != 4 || header_length < 20 || frame.len() < 14 + header_length {
        return Err("invalid IPv4 header".into());
    }

    let total_length = usize::from(u16::from_be_bytes([frame[16], frame[17]]));

    if total_length < header_length {
        return Err("invalid IPv4 total length".into());
    }

    let source = Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29]);

    let destination = Ipv4Addr::new(frame[30], frame[31], frame[32], frame[33]);

    Ok(Some((source, destination)))
}
fn forward(
    stream: &mut TcpStream,
    packet: PacketIn,
    xid: u32,
    macs: &mut HashMap<[u8; 6], u32>,
) -> Result<()> {
    let port = packet.in_port();
    if port == 0 || port >= 0xffff_ff00 || packet.data.len() < 14 {
        return Err("PacketIn needs a physical ingress port and an Ethernet header".into());
    }
    if packet.data.len() > usize::from(packet.total_len)
        || (!packet.is_buffered() && packet.data.len() != usize::from(packet.total_len))
    {
        return Err("PacketIn contains inconsistent or truncated unbuffered data".into());
    }
    let destination: [u8; 6] = packet.data[..6].try_into()?;
    let source: [u8; 6] = packet.data[6..12].try_into()?;
    if source[0] & 1 != 0 || source == [0; 6] {
        return Err("Ethernet source must be a nonzero unicast MAC address".into());
    }
    if [0x8100, 0x88a8].contains(&u16::from_be_bytes([packet.data[12], packet.data[13]])) {
        return Err("VLAN-tagged traffic is outside this untagged lab prototype".into());
    }
    let ipv4 = ipv4_addresses(&packet.data)?;
    if !macs.contains_key(&source) && macs.len() >= MAX_MACS {
        return Err("MAC learning table capacity reached".into());
    }
    macs.insert(source, port);
    let output = if destination[0] & 1 == 0 {
        macs.get(&destination).copied()
    } else {
        None
    };
    if output == Some(port) {
        return Ok(());
    }
    if let Some(output) = output {
        let mut match_fields = Match::new()
            .in_port(port)
            .eth_src(source)
            .eth_dst(destination);

        if let Some((ipv4_source, ipv4_destination)) = ipv4 {
            match_fields = match_fields
                .eth_type(0x0800)
                .ipv4_src(ipv4_source, 32)
                .ipv4_dst(ipv4_destination, 32);
        }

        let flow = Flow::add()
            .cookie(COOKIE)
            .priority(1)
            .idle_timeout(30)
            .hard_timeout(60)
            .match_fields(match_fields)
            .actions(ActionList::new().output(output));

        send(stream, flow.to_message(Version::Of13, xid))?;
    }
    let actions = ActionList::new().output(output.map_or(OutputPort::Flood, OutputPort::Port));
    let outgoing = if packet.is_buffered() {
        PacketOut::from_buffer(packet.buffer_id)
    } else {
        PacketOut::new().data(packet.data)
    };
    send(
        stream,
        outgoing
            .in_port(port)
            .actions(actions)
            .to_message(Version::Of13, xid),
    )
}

fn serve(mut stream: TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    send(
        &mut stream,
        Message::new(Version::Of13, MessageType::Hello, 0, Vec::new().into()),
    )?;
    if read_message(&mut stream)?.header.msg_type != MessageType::Hello {
        return Err("expected Hello before other switch messages".into());
    }
    send(
        &mut stream,
        Message::new(
            Version::Of13,
            MessageType::FeaturesRequest,
            1,
            Vec::new().into(),
        ),
    )?;
    let mut configured = false;
    let mut ready = false;
    // shortcut: static, single-switch lab; add MAC aging and move/port-down handling before dynamic topologies.
    let mut macs = HashMap::new();
    loop {
        let message = read_message(&mut stream)?;
        let xid = message.header.xid;
        match message.header.msg_type {
            MessageType::EchoRequest => {
                send(
                    &mut stream,
                    Message::new(Version::Of13, MessageType::EchoReply, xid, message.body),
                )?;
            }
            MessageType::FeaturesReply => {
                if configured
                    || xid != 1
                    || message.body.len() != 24
                    || message.body[12] == 0
                    || message.body[13] != 0
                {
                    return Err(
                        "expected one valid FeaturesReply for the main switch connection".into(),
                    );
                }
                let dpid = u64::from_be_bytes(message.body[..8].try_into()?);
                let miss = Flow::add()
                    .cookie(COOKIE)
                    .actions(ActionList::new().controller(u16::MAX));
                send(&mut stream, miss.to_message(Version::Of13, 2))?;
                send(
                    &mut stream,
                    Message::new(
                        Version::Of13,
                        MessageType::BarrierRequest,
                        3,
                        Vec::new().into(),
                    ),
                )?;
                configured = true;
                eprintln!("SWITCH_FEATURES dpid={dpid:016x} openflow=1.3");
            }
            MessageType::BarrierReply if configured && !ready => {
                if xid != 3 || !message.body.is_empty() {
                    return Err("unexpected setup BarrierReply".into());
                }
                ready = true;
                eprintln!("SWITCH_READY table_miss=controller");
            }
            MessageType::PacketIn if ready => {
                forward(&mut stream, PacketIn::parse(message.body)?, xid, &mut macs)?;
            }
            MessageType::Error => {
                return Err(format!(
                    "switch reported OpenFlow error: {:?}",
                    OfError::parse(&message.body)?
                )
                .into());
            }
            MessageType::PortStatus | MessageType::EchoReply => {}
            _ => {
                return Err(
                    format!("unexpected switch message: {:?}", message.header.msg_type).into(),
                );
            }
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("monitor") {
        return monitor::run(&args);
    }
    if matches!(args.first().map(String::as_str), Some("stats" | "drop")) {
        return control::run(&args);
    }
    if args.len() > 1 {
        return Err("usage: sdn-shield-controller [LISTEN_ADDRESS] | stats SOCKET | drop SOCKET IN_PORT SOURCE_IPV4 DESTINATION_IPV4 SECONDS | monitor SOCKET INTERVAL_MS WINDOWS PPS_LIMIT BYTE_LIMIT".into());
    }
    let address = args.first().map_or("127.0.0.1:6653", String::as_str);
    let listener = TcpListener::bind(address)?;
    println!("LISTENING {}", listener.local_addr()?);
    std::io::stdout().flush()?;
    for stream in listener.incoming() {
        if let Err(error) = serve(stream?) {
            eprintln!("SWITCH_DISCONNECTED {error}");
        }
    }
    Ok(())
}
