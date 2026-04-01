use std::io;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PrivilegeLevel { Root, User }

impl std::fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivilegeLevel::Root => write!(f, "root"),
            PrivilegeLevel::User => write!(f, "user"),
        }
    }
}

pub fn detect_privilege() -> PrivilegeLevel {
    match socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    ) {
        Ok(_) => PrivilegeLevel::Root,
        Err(_) => PrivilegeLevel::User,
    }
}

pub fn raw_socket(protocol: socket2::Protocol) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(protocol),
    )?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}
