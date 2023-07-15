use etherparse::{Icmpv4Header, Icmpv4Type, Ipv4Header, PacketBuilder};
use tun_tap::{Iface, Mode};

mod ipv4_header;
mod tcp_header;

const ICMP_PROTOCOL_NUMBER: u8 = 0x1;
const IPV4_PROTOCOL_NUMBER: u16 = 0x800;

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
            let (header, _) = Ipv4Header::from_slice(&ipv4_packet).unwrap();
            println!("{:?}", header);

            if header.protocol == ICMP_PROTOCOL_NUMBER {
                let (icmp_header, payload) =
                    Icmpv4Header::from_slice(&ipv4_packet[header.header_len()..]).unwrap();

                match icmp_header.icmp_type {
                    Icmpv4Type::EchoRequest(echo_header) => {
                        let builder = PacketBuilder::ipv4(
                            header.destination,
                            header.source,
                            header.time_to_live,
                        )
                        .icmpv4_echo_reply(echo_header.id, echo_header.seq);

                        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
                        builder.write(&mut result, &payload).unwrap();
                        iface.send(&[&begin, &result[..]].concat()).unwrap();
                    }
                    _ => {}
                };
            }
        }
    }
}
