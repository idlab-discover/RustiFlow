//! Promiscuous mode for realtime capture through a packet-socket membership.
//!
//! A `PACKET_MR_PROMISC` membership raises the interface's promiscuity count
//! instead of setting `IFF_PROMISC` directly. The kernel drops the membership
//! when the socket closes, including when the process is killed, so an
//! operator's own promiscuous setting and other tools' memberships survive.

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::Context;

/// Keeps `interface` promiscuous for as long as this value lives.
///
/// The socket uses protocol 0, so it never receives packets.
pub struct PromiscuousMembership {
    _socket: OwnedFd,
}

impl PromiscuousMembership {
    pub fn join(interface: &str) -> Result<Self, anyhow::Error> {
        let interface_name = CString::new(interface)
            .with_context(|| format!("interface name {interface:?} contains a NUL byte"))?;
        // SAFETY: `interface_name` is a valid NUL-terminated string that
        // outlives the call.
        let ifindex = unsafe { libc::if_nametoindex(interface_name.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("cannot find interface {interface:?}"));
        }
        let ifindex = libc::c_int::try_from(ifindex)
            .with_context(|| format!("interface index {ifindex} of {interface:?} is too large"))?;

        // SAFETY: plain socket creation; no pointers are passed.
        let raw_fd =
            unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if raw_fd < 0 {
            let err = io::Error::last_os_error();
            let hint = match err.raw_os_error() {
                Some(libc::EPERM) => " (opening a packet socket needs CAP_NET_RAW)",
                _ => "",
            };
            return Err(err).with_context(|| {
                format!("cannot open a packet socket to make {interface:?} promiscuous{hint}")
            });
        }
        // SAFETY: `socket` just returned this descriptor and nothing else owns it.
        let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let mreq = promiscuous_mreq(ifindex);
        // SAFETY: `socket` owns an open descriptor for the whole call, and
        // `mreq` is a valid `packet_mreq` that outlives the call; the length
        // passed is its exact size.
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                (&raw const mreq).cast(),
                mem::size_of_val(&mreq) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("cannot make {interface:?} promiscuous"));
        }

        Ok(Self { _socket: socket })
    }
}

fn promiscuous_mreq(ifindex: libc::c_int) -> libc::packet_mreq {
    libc::packet_mreq {
        mr_ifindex: ifindex,
        mr_type: libc::PACKET_MR_PROMISC as libc::c_ushort,
        mr_alen: 0,
        mr_address: [0; 8],
    }
}

#[cfg(test)]
mod tests {
    use super::{promiscuous_mreq, PromiscuousMembership};

    #[test]
    fn promiscuous_mreq_targets_the_interface_without_an_address() {
        let mreq = promiscuous_mreq(7);

        assert_eq!(
            (mreq.mr_ifindex, mreq.mr_type, mreq.mr_alen, mreq.mr_address),
            (7, 1, 0, [0; 8])
        );
    }

    #[test]
    fn joining_an_unknown_interface_names_it() {
        let err = PromiscuousMembership::join("rf-no-such-if0")
            .err()
            .expect("an unknown interface cannot be made promiscuous");

        assert!(
            format!("{err:#}").contains("cannot find interface \"rf-no-such-if0\""),
            "{err:#}"
        );
    }
}
