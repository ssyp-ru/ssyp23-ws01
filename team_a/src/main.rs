use tun_tap::{Iface, Mode};

mod ipv4_header;

fn main() {
    let iface = Iface::new("tun0", Mode::Tun).expect("Failed to create a TUN device");
    
    let mut buffer = vec![0; 1504]; // MTU + 4 for the header
    let mut counter = 0;
    loop {
        let n = iface.recv(&mut buffer).unwrap();
        let packet = &buffer[..n];
        
        if packet[2] == 8 && packet[3] == 0 {
            let mut new_buffer: [u8; 20] = [0; 20];
            let ipv4_slice = &packet[4..];
            ipv4_header::pack(&mut new_buffer, ipv4_header::parse(&ipv4_slice));
            println!("{}: got IPv4 package", counter);
            println!("{:?}", ipv4_slice);
            println!("{:?}", new_buffer);
            assert_eq!(true, ipv4_slice.starts_with(&new_buffer));
        }
        counter += 1;
    }
}
