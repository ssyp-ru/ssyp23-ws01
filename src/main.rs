use std::collections::VecDeque;

use anyhow::Result;
use chrono::Local;
use rand::Rng;
use tun_tap::{ Iface, Mode };

mod utils;

mod ipv4;
use ipv4::IPv4Header;

mod tcp;
use tcp::{ TcpHeader, TcpFlag, build_tcp_packet };

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
    recv_seq: u32,
    send_seq: u32,
    client_window: u16,
    packet_queue: VecDeque<u8>,
}

impl Connection
{
    fn new() -> Connection
    {
        Connection
        {
            state: State::Listen,
            recv_seq: 0,
            send_seq: rand::thread_rng().gen(),
            client_window: 0,
            packet_queue: VecDeque::new(),
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

        let (ip, data) = IPv4Header::new(&buf[4..recv_size])?;
        if ip.protocol != 6 { continue }; // only allow TCP, https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Data
        if ip.header_checksum != ip.calc_checksum()
        {
            println!("invalid ip checksum");
            continue;
        }

        let (tcp, data) = TcpHeader::new(data)?;
        if tcp.checksum != tcp.calc_checksum(ip.source_ip, ip.dest_ip, tcp.size() + data.len(), data)
        {
            println!("invalid tcp checksum");
            continue;
        }

        if conn.state == State::Estab
        {
            // TODO: Should also check that ack is set + acknoledgement number
            if tcp.sequence_number != conn.recv_seq
            {
                println!("invalid client sequence number {} (should be {})", tcp.sequence_number, conn.recv_seq);
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
                conn.recv_seq = tcp.sequence_number.wrapping_add(1);
                
                iface.send(build_tcp_packet(
                    &ip,
                    &tcp,
                    TcpFlag::Syn | TcpFlag::Ack,
                    conn.send_seq,
                    conn.recv_seq,
                    &[0; 0],
                ).as_slice()).expect("failed to send SYN-ACK");
            },
            State::SynRecvd if tcp.get_flag(TcpFlag::Ack) =>
            {
                if tcp.ack_number != conn.send_seq.wrapping_add(1) || tcp.get_flag(TcpFlag::Syn)
                {
                    println!("got invalid ack, sending RST");

                    iface.send(build_tcp_packet(
                        &ip,
                        &tcp,
                        TcpFlag::Rst as u8,
                        tcp.ack_number,
                        tcp.sequence_number + data.len() as u32,
                        &[0; 0],
                    ).as_slice()).expect("failed to send RST");
                    
                    continue;
                }

                println!("got ACK of SYN, connection established");

                conn.send_seq = conn.send_seq.wrapping_add(1);
                conn.state = State::Estab;
            },
            _ if tcp.get_flag(TcpFlag::Rst) =>
            {
                println!("got RST, connection closed");
                conn.state = State::Closed;
            },
            State::Estab if tcp.get_flag(TcpFlag::Fin) =>
            {
                println!("got FIN");
                conn.state = State::LastAck;
    
                conn.recv_seq = tcp.sequence_number.wrapping_add(1);
                
                iface.send(build_tcp_packet(
                    &ip,
                    &tcp,
                    TcpFlag::Fin | TcpFlag::Ack,
                    conn.send_seq,
                    conn.recv_seq,
                    &[0; 0],
                ).as_slice()).expect("failed to send FIN-ACK");
            },
            State::LastAck if tcp.get_flag(TcpFlag::Ack) =>
            {
                println!("got ACK of FIN, connection closed");
                conn.state = State::Closed;
            },
            State::Estab =>
            {
                println!("RECV {tcp:?}");
                println!("{data:02X?}");

                conn.recv_seq = conn.recv_seq.wrapping_add(data.len() as u32);

                if conn.send_seq < tcp.ack_number
                {
                    let amount = tcp.ack_number - conn.send_seq;
                    conn.send_seq = tcp.ack_number;
                    conn.packet_queue.drain(..amount as usize);
                }
                
                match std::str::from_utf8(data).unwrap().trim()
                {
                    _ if data.is_empty() => { continue; },
                    "fin" =>
                    {
                        conn.state = State::LastAck;

                        iface.send(build_tcp_packet(
                            &ip,
                            &tcp,
                            TcpFlag::Fin | TcpFlag::Ack,
                            conn.send_seq,
                            conn.recv_seq,
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
                            conn.send_seq,
                            conn.recv_seq,
                            &[0; 0],
                        ).as_slice()).expect("failed to send RST");

                        continue;
                    },
                    _ =>
                    {
                        let msg = format!("Time: {}", Local::now().format("%H:%M:%S\n"));
                        conn.packet_queue.extend(msg.as_bytes());
                    },
                }

                let text: &[u8] = if !conn.packet_queue.is_empty()
                {
                    let size = std::cmp::min(conn.packet_queue.len(), conn.client_window.into());
                    &conn.packet_queue.make_contiguous()[..size]
                }
                else
                {
                    &[0; 0]
                };

                println!("SEND ACK seq={} ack={}", conn.send_seq, conn.recv_seq);
                iface.send(build_tcp_packet(
                    &ip,
                    &tcp,
                    TcpFlag::Ack as u8,
                    conn.send_seq,
                    conn.recv_seq,
                    text,
                ).as_slice()).expect("failed to send ACK");
            },
            State::Closed if !tcp.get_flag(TcpFlag::Rst) =>
            {
                println!("got a packet in a closed connection, sending RST");

                iface.send(build_tcp_packet(
                    &ip,
                    &tcp,
                    TcpFlag::Rst as u8,
                    if tcp.get_flag(TcpFlag::Ack) { tcp.ack_number } else { 0 },
                    tcp.sequence_number + data.len() as u32,
                    &[0; 0],
                ).as_slice()).expect("failed to send RST");
            },
            _ =>
            {
                println!("UNKNOWN packet - state={:?} {tcp:?}", conn.state);
            },
        }
    }
}