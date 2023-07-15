use etherparse::{Icmpv4Header, Icmpv4Type, Ipv4Header, PacketBuilder};
use tun_tap::{Iface, Mode};

use crate::ipv4_header::IPv4Header;

mod ipv4_header;
mod tcp_header;
mod icmp_header;

const ICMP_PROTOCOL_NUMBER: u8 = 0x1;
const IPV4_PROTOCOL_NUMBER: u16 = 0x800;
const ICMP_ECHO_REQUEST_TYPE: u8 = 0x8;
const ICMP_ECHO_REPLY_TYPE: u8 = 0x0;

fn main() {
    let iface = Iface::new("tun1", Mode::Tun).expect("Failed to create a TUN device");

    let mut buffer = vec![0; 1504]; // MTU + 4 for the header

    loop {
        let n = iface.recv(&mut buffer).unwrap();
        let packet = &buffer[..n];

        println!("{:?}", packet);
        let protocol_number = u16::from_be_bytes([packet[2], packet[3]]);
        if protocol_number == IPV4_PROTOCOL_NUMBER {
            let begin = &packet[0..4];
            let ipv4_packet = &packet[4..];
            let header = ipv4_header::parse(&ipv4_packet);
            let header_len = header.ihl as usize * 4;
            println!("{:?}", header);

            if header.protocol == ICMP_PROTOCOL_NUMBER {
                let (icmp_header, payload) =
                    icmp_header::parse(&ipv4_packet[header_len..]);

                if icmp_header.type_ == ICMP_ECHO_REQUEST_TYPE {
                    let new_ipv4_header = &ipv4_packet[header_len..];
                    println!("{:?}", new_ipv4_header);

                    let id_slice = icmp_header.id.to_be_bytes();
                    let seq_slice = icmp_header.seq.to_be_bytes();
                    
                    let mut new_icmp_header = [ICMP_ECHO_REPLY_TYPE, 0, 0, 0, id_slice[0], id_slice[1], seq_slice[0], seq_slice[1]];
                    let icmp_checksum = icmp_header::get_checksum(&new_icmp_header).to_be_bytes();
                    new_icmp_header[2..=3].copy_from_slice(&icmp_checksum);

                    let mut new_packet = [&ipv4_packet[..header_len], &new_icmp_header].concat();

                    new_packet[4] = 0;
                    new_packet[5] = 0;
                    new_packet[10] = 0;
                    new_packet[11] = 0;
                    new_packet[12..=15].copy_from_slice(&header.destination_address.octets());
                    new_packet[16..=19].copy_from_slice(&header.source_address.octets());

                    let builder = PacketBuilder::ipv4(
                        header.destination_address.octets(),
                        header.source_address.octets(),
                        header.time_to_live,
                    )
                    .icmpv4_echo_reply(icmp_header.id, icmp_header.seq);

                    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
                    builder.write(&mut result, &payload).unwrap();

                    println!("{:?}", &[&new_packet[..], payload].concat());
                    println!("-------");
                    println!("{:?}", &new_icmp_header);
                    println!("{:?}", &payload);
                    println!("-------");
                    println!("{:?}", &[&begin, &result[..]].concat());
                    iface.send(&[&begin, &new_packet[..], payload].concat()).unwrap();
                }
            }
        }
    }
}
