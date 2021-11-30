/*!
A zero-copy DHCPv4 parser.

This crate is suitable for writing DHCP relay agents, which only need
to read and write a few fields, set and possibly remove a couple of
options, before forwarding an incoming DHCP message.

Although fields in the underlying message buffers are stored in
network-endian, the arguments and return values of getters and setters
defined by this crate are all native-endian.
 */

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_debug_implementations)]

use core::fmt;

pub mod dhcpv4;
pub mod dhcpv6;

/// The type of errors that may be produced by this crate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The message was malformed.
    Malformed,
    /// Source buffer ended too soon.
    Underflow,
    /// Destination buffer is smaller than the encoding.
    Overflow,
    /// Data is longer than can fit in the length field.
    TooLong,
    /// Missing string NULL terminator.
    BadNull,
    /// Missing required option.
    MissingRequired,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Error::Malformed => "malformed message",
            Error::Underflow => "source buffer ended too soon",
            Error::Overflow => "destination buffer is too small",
            Error::TooLong => "data is too long to fit in a single entity",
            Error::BadNull => "missing NULL terminator",
            Error::MissingRequired => "an option marked as required was missing",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[doc(hidden)]
#[derive(Debug)]
pub struct Cursor<'a> {
    buffer: &'a mut [u8],
    index: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    fn write_u8(&mut self, b: u8) -> Result<(), Error> {
        *self.buffer.get_mut(self.index).ok_or(Error::Overflow)? = b;
        self.index += 1;
        Ok(())
    }

    fn write(&mut self, bs: &[u8]) -> Result<(), Error> {
        self.buffer
            .get_mut(self.index..self.index + bs.len())
            .ok_or(Error::Overflow)?
            .copy_from_slice(bs);
        self.index += bs.len();
        Ok(())
    }
}
