use anyhow::Result;
use rand::Rng;
use tun_tap::Iface;
use tun_tap::Mode;

mod utils;

mod ipv4;
use ipv4::IPv4Packet;

mod tcp;
use tcp::{ TcpPacket, TcpFlag, build_tcp_packet };

#[derive(Debug, PartialEq)]
enum State
{
    Closed,
    Listen,
    SynRecvd,
    Estab,
    LastAck,
}

struct Connection
{
    state: State,
    client_seq: u32,
    server_seq: u32,
    client_window: u16,
    packet_queue: Vec<u8>,
}

impl Connection
{
    fn new() -> Connection
    {
        Connection
        {
            state: State::Listen,
            client_seq: 0,
            server_seq: rand::thread_rng().gen(),
            client_window: 0,
            packet_queue: Vec::new(),
        }
    }
}

fn main() -> Result<()>
{
    let mut conn = Connection::new();
    let iface = Iface::new("tun0", Mode::Tun)?;
    let mut buf = [0; 1504];

    loop
    {
        let recv_size = iface.recv(&mut buf)?;

        let proto = u16::from_be_bytes(buf[2..4].try_into()?);        
        if proto != 0x0800 { continue }; // only allow IPv4, https://en.wikipedia.org/wiki/EtherType#Values

        let (ip, data) = IPv4Packet::new(&buf[4..recv_size])?;
        if ip.protocol != 6 { continue }; // only allow TCP, https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Data
        if ip.header_checksum != ip.calc_checksum()
        {
            println!("invalid ip checksum");
            continue;
        }

        let (tcp, data) = TcpPacket::new(data)?;
        if tcp.checksum != tcp.calc_checksum(ip.source_ip, ip.dest_ip, recv_size - 4 - ip.size(), data)
        {
            println!("invalid tcp checksum");
            continue;
        }

        if conn.state != State::Listen
        {
            if tcp.sequence_number != conn.client_seq
            {
                println!("invalid client sequence number {} (should be {})", tcp.sequence_number, conn.client_seq);
                continue;
            }

            conn.client_window = tcp.window_size;
        }

        match conn.state
        {
            State::Listen if tcp.get_flag(TcpFlag::Syn) =>
            {
                println!("got SYN");
    
                conn.state = State::SynRecvd;
                conn.client_seq = tcp.sequence_number.wrapping_add(1);
                
                iface.send(build_tcp_packet(
                    &ip,
                    &tcp,
                    TcpFlag::Syn | TcpFlag::Ack,
                    conn.server_seq,
                    conn.client_seq,
                    &[0; 0],
                ).as_slice()).expect("failed to send SYN-ACK");
            },
            State::SynRecvd if tcp.get_flag(TcpFlag::Ack) =>
            {
                println!("got ACK of SYN, connection established");

                conn.server_seq = conn.server_seq.wrapping_add(1);
                conn.state = State::Estab;
            },
            State::Estab | State::SynRecvd if tcp.get_flag(TcpFlag::Rst) =>
            {
                println!("got RST, connection closed");
                conn.state = State::Closed;
            },
            State::Estab if tcp.get_flag(TcpFlag::Fin) =>
            {
                println!("got FIN");
                conn.state = State::LastAck;
    
                conn.client_seq = tcp.sequence_number.wrapping_add(1);
                
                iface.send(build_tcp_packet(
                    &ip,
                    &tcp,
                    TcpFlag::Fin | TcpFlag::Ack,
                    conn.server_seq,
                    conn.client_seq,
                    &[0; 0],
                ).as_slice()).expect("failed to send FIN-ACK");
            },
            State::LastAck if tcp.get_flag(TcpFlag::Ack) =>
            {
                println!("got ACK of FIN, connection closed");
                conn.state = State::Closed;
            }
            State::Estab =>
            {
                conn.client_seq = conn.client_seq.wrapping_add(data.len() as u32);
                conn.server_seq = tcp.ack_number;
                
                println!("RECV {tcp:?}");
                println!("{data:02X?}");

                match std::str::from_utf8(data).unwrap().trim()
                {
                    _ if data.len() == 0 => { continue; },
                    "fin" =>
                    {
                        conn.state = State::LastAck;

                        iface.send(build_tcp_packet(
                            &ip,
                            &tcp,
                            TcpFlag::Fin | TcpFlag::Ack,
                            conn.server_seq,
                            conn.client_seq,
                            &[0; 0],
                        ).as_slice()).expect("failed to send FIN");
                    },
                    "rst" =>
                    {
                        conn.state = State::Closed;

                        iface.send(build_tcp_packet(
                            &ip,
                            &tcp,
                            TcpFlag::Rst as u8,
                            conn.server_seq,
                            conn.client_seq,
                            &[0; 0],
                        ).as_slice()).expect("failed to send RST");
                    },
                    _ =>
                    {
                        conn.packet_queue.extend(b"response\n");
                    },
                }

                let drain;
                let text: &[u8] = if !conn.packet_queue.is_empty()
                {
                    let size = if conn.packet_queue.len() > conn.client_window.into() { conn.client_window as usize } else { conn.packet_queue.len() };
                    drain = conn.packet_queue.drain(0..size);
                    drain.as_slice()
                }
                else
                {
                    &[0; 0]
                };

                println!("SEND ACK seq={} ack={}", conn.server_seq, conn.client_seq);
                iface.send(build_tcp_packet(
                    &ip,
                    &tcp,
                    TcpFlag::Ack as u8,
                    conn.server_seq,
                    conn.client_seq,
                    text,
                ).as_slice()).expect("failed to send ACK");
            },
            _ =>
            {
                println!("UNKNOWN packet - state={:?} {tcp:?}", conn.state);
            },
        }
    }
}