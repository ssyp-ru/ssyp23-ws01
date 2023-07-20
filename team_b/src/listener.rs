use crate::{ConnectionHandle, ConnectionManager};

pub struct Listener {
    pub ip: u32,
    pub port: u16,
    pub mgr: ConnectionManager,
}

impl Listener {
    pub fn new(ip: u32, port: u16, mgr: ConnectionManager) -> Listener {
        Listener { ip, port, mgr }
    }

    pub fn accept(&mut self) -> ConnectionHandle {
        loop {
            if let Some(conn) = self.mgr.accept(self.ip, self.port) {
                return conn;
            }
        }
    }
}

impl Iterator for Listener {
    type Item = ConnectionHandle;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.accept())
    }
}
