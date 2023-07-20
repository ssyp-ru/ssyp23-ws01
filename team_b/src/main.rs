use std::{
    cmp::min,
    collections::{HashMap, VecDeque},
    os::fd::AsRawFd,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Ok, Result};
use listener::Listener;
use nix::poll::{poll, PollFd, PollFlags};
use rand::Rng;
use tun_tap::{Iface, Mode};

mod utils;
use utils::{wrapping_between, ConnectionId};

mod ipv4;
use ipv4::IPv4Header;

mod tcp;
use tcp::{build_tcp_packet, TcpFlag, TcpHeader};

mod listener;

#[derive(Debug, PartialEq)]
enum State {
    Closed,
    Listen,
    SynRecvd,
    Estab,
    LastAck,
}

#[derive(Debug)]
pub struct Connection {
    state: State,
    server_port: u16,
    client_port: u16,
    server_ip: u32,
    client_ip: u32,
    recv_seq: u32,
    send_seq: u32,
    send_window: u16,
    send_queue: VecDeque<u8>,
    recv_queue: VecDeque<u8>,
}

impl Connection {
    fn new(ip: u32, port: u16) -> Connection {
        Connection {
            state: State::Listen,
            server_port: port,
            client_port: 0,
            server_ip: ip,
            client_ip: 0,
            recv_seq: 0,
            send_seq: rand::thread_rng().gen(),
            send_window: 0,
            send_queue: VecDeque::new(),
            recv_queue: VecDeque::new(),
        }
    }

    fn id(&self) -> ConnectionId {
        ConnectionId {
            ip_src: self.client_ip,
            ip_dst: self.server_ip,
            port_src: self.client_port,
            port_dst: self.server_port,
        }
    }

    fn on_message(
        &mut self,
        data: &[u8],
        ip: &IPv4Header,
        tcp: &TcpHeader,
        iface: &Iface,
    ) -> Result<()> {
        if ip.dest_ip != self.server_ip || tcp.dest_port != self.server_port {
            println!("invalid dest ip or port");
            iface
                .send(
                    build_tcp_packet(
                        &self.id(),
                        TcpFlag::Rst | TcpFlag::Ack,
                        tcp.sequence_number + 1,
                        tcp.sequence_number + 1 + data.len() as u32,
                        &[0; 0],
                    )
                    .as_slice(),
                )
                .expect("failed to send RST");

            return Err(anyhow::Error::msg("invalid dest ip or port"));
        }

        match self.state {
            State::Listen if tcp.get_flag(TcpFlag::Syn) => {
                println!("got SYN");

                self.state = State::SynRecvd;
                self.recv_seq = tcp.sequence_number.wrapping_add(1);
                self.client_ip = ip.source_ip;
                self.client_port = tcp.source_port;

                iface
                    .send(
                        build_tcp_packet(
                            &self.id(),
                            TcpFlag::Syn | TcpFlag::Ack,
                            self.send_seq,
                            self.recv_seq,
                            &[0; 0],
                        )
                        .as_slice(),
                    )
                    .expect("failed to send SYN-ACK");
            }
            State::SynRecvd if tcp.get_flag(TcpFlag::Ack) => {
                if tcp.ack_number != self.send_seq.wrapping_add(1) || tcp.get_flag(TcpFlag::Syn) {
                    println!("got invalid ack, sending RST");

                    self.state = State::Closed;
                    iface
                        .send(
                            build_tcp_packet(
                                &self.id(),
                                TcpFlag::Rst as u8,
                                tcp.ack_number,
                                tcp.sequence_number + data.len() as u32,
                                &[0; 0],
                            )
                            .as_slice(),
                        )
                        .expect("failed to send RST");

                    return Ok(());
                }

                println!("got ACK of SYN, connection established");

                self.send_seq = self.send_seq.wrapping_add(1);
                self.state = State::Estab;
            }
            _ if tcp.get_flag(TcpFlag::Rst) => {
                println!("got RST, connection closed");
                self.state = State::Closed;
            }
            State::Estab if tcp.get_flag(TcpFlag::Fin) => {
                println!("got FIN");
                self.state = State::LastAck;

                self.recv_seq = tcp.sequence_number.wrapping_add(1);

                iface
                    .send(
                        build_tcp_packet(
                            &self.id(),
                            TcpFlag::Fin | TcpFlag::Ack,
                            self.send_seq,
                            self.recv_seq,
                            &[0; 0],
                        )
                        .as_slice(),
                    )
                    .expect("failed to send FIN-ACK");
            }
            State::LastAck if tcp.get_flag(TcpFlag::Ack) => {
                println!("got ACK of FIN, connection closed");
                self.state = State::Closed;
            }
            State::Estab => {
                if !tcp.get_flag(TcpFlag::Ack) {
                    println!("ACK not set");
                    return Ok(());
                }

                if tcp.sequence_number != self.recv_seq
                    || !wrapping_between(
                        self.send_seq,
                        tcp.ack_number,
                        self.send_seq.wrapping_add(self.send_window as u32),
                    )
                {
                    println!("sending an empty packet");

                    iface
                        .send(
                            build_tcp_packet(
                                &self.id(),
                                TcpFlag::Ack as u8,
                                self.send_seq,
                                self.recv_seq,
                                &[0; 0],
                            )
                            .as_slice(),
                        )
                        .expect("failed to send an empty packet");

                    return Ok(());
                }

                println!("RECV {tcp:?}");
                println!("{data:02X?}");

                self.send_window = tcp.window_size;
                self.recv_seq = self.recv_seq.wrapping_add(data.len() as u32);

                if self.send_seq < tcp.ack_number {
                    let amount = tcp.ack_number - self.send_seq;
                    self.send_seq = tcp.ack_number;
                    self.send_queue.drain(..amount as usize);
                }

                self.recv_queue.extend(data);
            }
            State::Closed if !tcp.get_flag(TcpFlag::Rst) => {
                println!("got a packet in a closed connection, sending RST");

                iface
                    .send(
                        build_tcp_packet(
                            &self.id(),
                            TcpFlag::Rst as u8,
                            if tcp.get_flag(TcpFlag::Ack) {
                                tcp.ack_number
                            } else {
                                0
                            },
                            tcp.sequence_number + data.len() as u32,
                            &[0; 0],
                        )
                        .as_slice(),
                    )
                    .expect("failed to send RST");
            }
            _ => {
                println!("UNKNOWN packet - state={:?} {tcp:?}", self.state);
            }
        }

        Ok(())
    }

    fn write_all<T: IntoIterator<Item = u8>>(&mut self, data: T) {
        self.send_queue.extend(data);
    }

    fn read(&mut self, buf: &mut [u8]) -> usize {
        let len = min(buf.len(), self.recv_queue.len());
        buf[..len].copy_from_slice(&self.recv_queue.make_contiguous()[..len]);
        buf[len..].fill(0);
        self.recv_queue.drain(..len);
        len
    }
}

#[derive(Debug)]
pub struct ConnectionHandle {
    mgr: ConnectionManager,
    id: ConnectionId,
}

impl ConnectionHandle {
    pub fn write_all<T: IntoIterator<Item = u8>>(&mut self, data: T) {
        let mut mgr = self.mgr.mgr.lock().unwrap();
        let conn = mgr.conns.get_mut(&self.id).unwrap();

        conn.write_all(data);
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut mgr = self.mgr.mgr.lock().unwrap();
        let conn = mgr.conns.get_mut(&self.id).unwrap();

        conn.read(buf)
    }
}

#[derive(Debug)]
struct Manager {
    conns: HashMap<ConnectionId, Connection>,
    listen: HashMap<(u32, u16), Connection>,
}

#[derive(Debug, Clone)]
pub struct ConnectionManager {
    mgr: Arc<Mutex<Manager>>,
}

impl ConnectionManager {
    pub fn new() -> Result<ConnectionManager> {
        let output = ConnectionManager {
            mgr: Manager::new()?,
        };

        let mut mgr_process = output.clone();
        std::thread::spawn(move || {
            mgr_process.process_connections().unwrap();
        });

        Ok(output)
    }

    pub fn bind(&self, ip_str: &str, port: u16) -> Listener {
        let ip = ip_str
            .split('.')
            .rev()
            .enumerate()
            .map(|(i, p)| p.parse::<u32>().unwrap() << 8 * i)
            .sum();

        let mut mgr = self.mgr.lock().unwrap();
        mgr.listen.insert((ip, port), Connection::new(ip, port));
        drop(mgr);

        Listener::new(ip, port, self.clone())
    }

    fn accept(&self, ip: u32, port: u16) -> Option<ConnectionHandle> {
        let mut mgr = self.mgr.lock().unwrap();
        let Some(conn) = mgr.listen.get(&(ip, port)) else { return None; };

        if conn.state == State::Listen {
            return None;
        }

        let id = conn.id();
        let conn = mgr.listen.remove(&(ip, port)).unwrap();

        mgr.conns.insert(id.clone(), conn);
        mgr.listen.insert((ip, port), Connection::new(ip, port));

        Some(ConnectionHandle {
            mgr: self.clone(),
            id,
        })
    }

    pub fn process_connections(&mut self) -> Result<()> {
        let mut buf = [0; 1504];
        let iface = Iface::new("tun0", Mode::Tun)?;
        let pollfd = PollFd::new(iface.as_raw_fd(), PollFlags::POLLIN);

        loop {
            let mut mgr = self.mgr.lock().unwrap();

            for (id, conn) in mgr.conns.iter_mut() {
                if conn.state == State::Closed {
                    continue;
                }
                if conn.send_queue.is_empty() {
                    continue;
                }

                let size = std::cmp::min(conn.send_queue.len(), conn.send_window.into());
                let text: &[u8] = &conn.send_queue.make_contiguous()[..size];

                iface
                    .send(
                        build_tcp_packet(
                            &id,
                            TcpFlag::Ack as u8,
                            conn.send_seq,
                            conn.recv_seq,
                            text,
                        )
                        .as_slice(),
                    )
                    .expect("failed to send data");
            }

            if poll(&mut [pollfd], 50).unwrap() != 1 {
                drop(mgr);
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            let recv_size = iface.recv(&mut buf)?;

            let proto = u16::from_be_bytes(buf[2..4].try_into()?);
            if proto != 0x0800
            // only allow IPv4, https://en.wikipedia.org/wiki/EtherType#Values
            {
                drop(mgr);
                std::thread::sleep(Duration::from_millis(100));
                continue;
            };

            let (ip, data) = IPv4Header::new(&buf[4..recv_size])?;
            if ip.protocol != 6
            // only allow TCP, https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Data
            {
                drop(mgr);
                std::thread::sleep(Duration::from_millis(100));
                continue;
            };

            if ip.header_checksum != ip.calc_checksum() {
                drop(mgr);
                println!("invalid ip checksum");
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }

            let (tcp, data) = TcpHeader::new(data)?;
            if tcp.checksum
                != tcp.calc_checksum(ip.source_ip, ip.dest_ip, tcp.size() + data.len(), data)
            {
                drop(mgr);
                println!("invalid tcp checksum");
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }

            let id = ConnectionId {
                ip_src: ip.source_ip,
                ip_dst: ip.dest_ip,
                port_src: tcp.source_port,
                port_dst: tcp.dest_port,
            };

            if let Some(conn) = mgr.conns.get_mut(&id) {
                println!("{conn:?}");
                conn.on_message(data, &ip, &tcp, &iface)?;

                drop(mgr);
                std::thread::sleep(Duration::from_millis(100));
                continue;
            };

            let Some(conn) = mgr.listen.get_mut(&(ip.dest_ip, tcp.dest_port)) else
            {
                drop(mgr);
                std::thread::sleep(Duration::from_millis(100));
                continue;
            };

            conn.on_message(data, &ip, &tcp, &iface).unwrap();
            println!("{conn:?}");

            drop(mgr);
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Manager {
    fn new() -> Result<Arc<Mutex<Manager>>> {
        let mgr = Manager {
            conns: HashMap::new(),
            listen: HashMap::new(),
        };

        Ok(Arc::new(Mutex::new(mgr)))
    }
}

fn main() {
    let mgr = ConnectionManager::new().unwrap();
    let mut list = mgr.bind("10.0.0.3", 8080);
    let mut conn = list.accept();

    loop {
        let mut buf = [0; 1024];
        let len = conn.read(&mut buf);
        if len == 0 {
            continue;
        }
        println!("{:?}", std::str::from_utf8(&buf[..len]).unwrap());
    }
}
