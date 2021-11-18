/*!
A zero-copy DHCPv4 parser.

See:
 * [RFC2131]: Dynamic Host Configuration Protocol
 * [RFC2132]: DHCP Options and BOOTP Vendor Extensions

[RFC2131]: https://datatracker.ietf.org/doc/html/rfc2131
[RFC2132]: https://datatracker.ietf.org/doc/html/rfc2132
 */

#![cfg_attr(not(feature = "std"), no_std)]

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use core::convert::{TryFrom, TryInto};
use core::fmt;
use core::iter::FusedIterator;
use core::mem;
use memchr::memchr;
use ref_cast::RefCast;

pub mod relay;

/// The 'DHCP server' UDP port.
pub const DHCP_SERVER_PORT: u16 = 67;
/// The 'DHCP client' UDP port.
pub const DHCP_CLIENT_PORT: u16 = 68;

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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Error::Malformed => "malformed message",
            Error::Underflow => "source buffer ended too soon",
            Error::Overflow => "destination buffer is too small",
            Error::TooLong => "data is too long to fit in a single entity",
            Error::BadNull => "missing NULL terminator",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[doc(hidden)]
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

/// An IPv4 address.
///
/// This is similar to [std::net::Ipv4Addr], but has an explicit
/// representation.
#[derive(Clone, PartialEq, Eq, RefCast, Debug)]
#[repr(transparent)]
pub struct Addr([u8; 4]);

impl<'a> TryFrom<&'a [u8]> for &'a Addr {
    type Error = Error;

    #[inline]
    fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
        b[..4]
            .try_into()
            .map(Addr::ref_cast)
            .map_err(|_| Error::Malformed)
    }
}

#[cfg(feature = "std")]
impl From<Addr> for ::std::net::Ipv4Addr {
    #[inline]
    fn from(Addr(x): Addr) -> Self {
        x.into()
    }
}

#[cfg(feature = "std")]
impl From<::std::net::Ipv4Addr> for Addr {
    #[inline]
    fn from(x: ::std::net::Ipv4Addr) -> Addr {
        Addr(x.octets())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/// The packet op code/message type.
pub enum OpCode {
    /// Signifies that the message is sent from a client to a server.
    BootRequest = 1,
    /// Signifies that the message is sent from a server to a client.
    BootReply,
}

impl TryFrom<u8> for OpCode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => OpCode::BootRequest,
            2 => OpCode::BootReply,
            _ => return Err(Error::Malformed),
        })
    }
}

/// The DHCP message type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageType {
    Discover = 1,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(x: u8) -> Result<Self, Self::Error> {
        Ok(match x {
            1 => MessageType::Discover,
            2 => MessageType::Offer,
            3 => MessageType::Request,
            4 => MessageType::Decline,
            5 => MessageType::Ack,
            6 => MessageType::Nak,
            7 => MessageType::Release,
            _ => return Err(Error::Malformed),
        })
    }
}

bitflags! {
    /// DHCPv4 flags.
    ///
    /// This is the type of the 'flags' field.
    #[repr(transparent)]
    pub struct Flags: u16 {
        const BROADCAST = 1 << 15;
    }

    /// The possible values of the 'option overload' option.
    #[repr(transparent)]
    pub struct OptionOverload: u8 {
        /// The 'file' field is used to hold options.
        const FILE = 0b01;
        /// The 'sname' field is used to hold options.
        const SNAME = 0b10;
    }
}

/// A DHCPv4 option.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DhcpOption<'a> {
    /// 0 Padding
    ///
    /// Can be used to cause subsequent fields to align on word
    /// boundaries.
    Pad,
    /// 255 End
    ///
    /// Marks the end of valid information in the 'options' field.
    End,
    /// 1 Subnet Mask.
    SubnetMask(&'a Addr),
    /// 3 Router
    Router(&'a [Addr]),
    /// 4 Time Server
    TimeServer(&'a [Addr]),
    /// 5 Name Server
    NameServer(&'a [Addr]),
    /// 6 Domain Name Server
    DomainNameServer(&'a [Addr]),
    /// 7 Log Server
    LogServer(&'a [Addr]),
    /// 8 Cookie Server
    CookieServer(&'a [Addr]),
    /// 9 LPR Server
    LPRServer(&'a [Addr]),
    /// 10 Impress Server
    ImpressServer(&'a [Addr]),
    /// 11 Resource Location Server
    ResourceLocationServer(&'a [Addr]),
    /// 12 Host Name
    HostName(&'a [u8]),
    /// 13 Boot File Size
    BootFileSize(u16),
    /// 14 Merit Dump File
    MeritDumpFile(&'a [u8]),
    /// 15 Domain Name
    DomainName(&'a [u8]),
    /// 16 Swap Server
    SwapServer(&'a Addr),
    /// 17 Root Path
    RootPath(&'a [u8]),
    /// 18 Extensions Path
    ExtensionsPath(&'a [u8]),
    /// 19 IP Forwarding Enable/Disable
    IpForwarding(bool),
    /// 52 Option Overload
    OptionOverload(OptionOverload),
    /// 53 DHCP Message Type
    ///
    /// This option is required.
    MessageType(MessageType),
    /// 82 Relay Agent Information
    RelayAgentInformation(relay::RelayAgentInformation<'a>),
    /// Unrecognized option.
    Unknown(u8, &'a [u8]),
}

impl DhcpOption<'_> {
    /// Returns the tag of this parameter.
    pub fn code(&self) -> u8 {
        use DhcpOption::*;
        match *self {
            Pad => 0,
            End => 255,
            SubnetMask(_) => 1,
            Router(_) => 3,
            TimeServer(_) => 4,
            NameServer(_) => 5,
            DomainNameServer(_) => 6,
            LogServer(_) => 7,
            CookieServer(_) => 8,
            LPRServer(_) => 9,
            ImpressServer(_) => 10,
            ResourceLocationServer(_) => 11,
            HostName(_) => 12,
            BootFileSize(_) => 13,
            MeritDumpFile(_) => 14,
            DomainName(_) => 15,
            SwapServer(_) => 16,
            RootPath(_) => 17,
            ExtensionsPath(_) => 18,
            IpForwarding(_) => 19,
            OptionOverload(_) => 52,
            MessageType(_) => 53,
            RelayAgentInformation(_) => 82,
            Unknown(code, _) => code,
        }
    }
}

#[inline]
fn read_str(b: &[u8]) -> Result<&[u8], Error> {
    if b.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(b)
}

#[inline]
fn read_addrs(b: &[u8]) -> Result<&[Addr], Error> {
    if b.len() < 4 || b.len() % mem::size_of::<Addr>() != 0 {
        return Err(Error::Malformed);
    }
    // Safety: Ok, since Addr has same representation as [u8; 4].
    Ok(unsafe { &*(b as *const [u8] as *const [Addr]) })
}

impl<'a> DhcpOption<'a> {
    fn read(buf: &'a [u8]) -> Result<(DhcpOption<'a>, usize), Error> {
        use DhcpOption::*;

        let (tag, b) = match *buf {
            [0, ..] => return Ok((Pad, 1)),
            [255, ..] => return Ok((End, 1)),
            [tag, len, ref rest @ ..] => (tag, rest.get(..len.into()).ok_or(Error::Malformed)?),
            _ => return Err(Error::Underflow),
        };
        Ok((
            match tag {
                0 | 255 => unreachable!(),
                1 => SubnetMask(b.try_into()?),
                3 => Router(read_addrs(b)?),
                4 => TimeServer(read_addrs(b)?),
                5 => NameServer(read_addrs(b)?),
                6 => DomainNameServer(read_addrs(b)?),
                7 => LogServer(read_addrs(b)?),
                8 => CookieServer(read_addrs(b)?),
                9 => LPRServer(read_addrs(b)?),
                10 => ImpressServer(read_addrs(b)?),
                11 => ResourceLocationServer(read_addrs(b)?),
                12 => HostName(read_str(b)?),
                13 => {
                    if b.len() != 2 {
                        return Err(Error::Malformed);
                    }
                    BootFileSize(NetworkEndian::read_u16(b))
                }
                14 => MeritDumpFile(read_str(b)?),
                15 => DomainName(read_str(b)?),
                16 => SwapServer(b.try_into()?),
                17 => RootPath(read_str(b)?),
                18 => ExtensionsPath(read_str(b)?),
                19 => match *b {
                    [x] => IpForwarding(x == 1),
                    _ => return Err(Error::Malformed),
                },
                52 => match *b {
                    [x] => {
                        OptionOverload(crate::OptionOverload::from_bits(x).ok_or(Error::Malformed)?)
                    }
                    _ => return Err(Error::Malformed),
                },
                53 => match *b {
                    [x] => MessageType(x.try_into()?),
                    _ => return Err(Error::Malformed),
                },
                82 => RelayAgentInformation(relay::RelayAgentInformation::new(b)?),
                _ => Unknown(tag, b),
            },
            2 + b.len(),
        ))
    }

    fn write<'buf>(&self, cursor: &mut Cursor<'buf>) -> Result<(), Error> {
        use DhcpOption::*;
        cursor.write_u8(self.code())?;
        match *self {
            Pad | End => Ok(()),
            SubnetMask(addr) | SwapServer(addr) => {
                cursor.write_u8(addr.0.len() as u8)?;
                cursor.write(&addr.0)
            }
            Router(addrs)
            | TimeServer(addrs)
            | NameServer(addrs)
            | DomainNameServer(addrs)
            | LogServer(addrs)
            | CookieServer(addrs)
            | LPRServer(addrs)
            | ImpressServer(addrs)
            | ResourceLocationServer(addrs) => {
                let xs = unsafe { &*(addrs as *const [Addr] as *const [u8]) };
                cursor.write_u8(xs.len().try_into().map_err(|_| Error::TooLong)?)?;
                cursor.write(xs)
            }
            HostName(xs)
            | MeritDumpFile(xs)
            | DomainName(xs)
            | RootPath(xs)
            | ExtensionsPath(xs)
            | RelayAgentInformation(relay::RelayAgentInformation(xs))
            | Unknown(_, xs) => {
                cursor.write_u8(xs.len().try_into().map_err(|_| Error::TooLong)?)?;
                cursor.write(xs)
            }
            BootFileSize(x) => {
                cursor.write_u8(1)?;
                cursor.write(&x.to_be_bytes())
            }
            IpForwarding(x) => {
                cursor.write_u8(1)?;
                cursor.write_u8(if x { 1 } else { 0 })
            }
            OptionOverload(x) => {
                cursor.write_u8(1)?;
                cursor.write_u8(x.bits())
            }
            MessageType(x) => {
                cursor.write_u8(1)?;
                cursor.write_u8(x as u8)
            }
        }
    }
}

const SNAME_FIELD_OFFSET: usize = 44;
const FILE_FIELD_OFFSET: usize = SNAME_FIELD_OFFSET + 64;
const OPTIONS_FIELD_OFFSET: usize = FILE_FIELD_OFFSET + 128;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

struct Options<'a> {
    /// The entire DHCP message.
    b: &'a [u8],
    overload: OptionOverload,
    /// The current position in `b`.
    cursor: usize,
}

impl<'a> Options<'a> {
    #[inline]
    fn new(b: &'a [u8]) -> Result<Self, Error> {
        if b[OPTIONS_FIELD_OFFSET..][..MAGIC_COOKIE.len()] != MAGIC_COOKIE {
            return Err(Error::Malformed);
        }

        Ok(Self {
            b,
            overload: OptionOverload::empty(),
            cursor: OPTIONS_FIELD_OFFSET + MAGIC_COOKIE.len(),
        })
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = Result<(DhcpOption<'a>, (usize, usize)), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let b = if self.cursor > OPTIONS_FIELD_OFFSET {
                &self.b[self.cursor..]
            } else if self.cursor >= FILE_FIELD_OFFSET {
                &self.b[FILE_FIELD_OFFSET..][..128][self.cursor - FILE_FIELD_OFFSET..]
            } else {
                &self.b[SNAME_FIELD_OFFSET..][..64][self.cursor - SNAME_FIELD_OFFSET..]
            };
            match DhcpOption::read(b) {
                Ok((DhcpOption::Pad, len)) => self.cursor += len,
                Ok((DhcpOption::End, _)) => {
                    self.cursor = if self.cursor > OPTIONS_FIELD_OFFSET
                        && self.overload.contains(OptionOverload::FILE)
                    {
                        FILE_FIELD_OFFSET // The 'file' field MUST be interpreted next
                    } else if self.cursor >= FILE_FIELD_OFFSET
                        && self.overload.contains(OptionOverload::SNAME)
                    {
                        SNAME_FIELD_OFFSET // ...followed by the 'sname' field
                    } else {
                        break None;
                    }
                }
                Ok((option, len)) => {
                    let bnd = (self.cursor, len);
                    self.cursor += len;
                    if let DhcpOption::OptionOverload(x) = option {
                        self.overload = x;
                    }
                    break Some(Ok((option, bnd)));
                }
                Err(e) => break Some(Err(e)),
            }
        }
    }
}

impl FusedIterator for Options<'_> {}

/// A read/write wrapper around a Dynamic Host Protocol version 4
/// message buffer.
#[derive(Clone)]
pub struct Dhcpv4View<T: AsRef<[u8]>>(T);

impl<T: AsRef<[u8]>> AsRef<[u8]> for Dhcpv4View<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Dhcpv4View<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<T: AsRef<[u8]>> Dhcpv4View<T> {
    /// Constructs a new view from an underlying message buffer.
    ///
    /// Returns an error if the length of the buffer is smaller than
    /// any valid message.
    #[inline]
    pub fn new(b: T) -> Result<Dhcpv4View<T>, Error> {
        if b.as_ref().len() < OPTIONS_FIELD_OFFSET + MAGIC_COOKIE.len() + 4 {
            return Err(Error::Underflow);
        }
        Ok(Dhcpv4View(b))
    }

    #[inline]
    pub fn op(&self) -> Result<OpCode, Error> {
        self.as_ref()[0].try_into()
    }

    /// Gets the hardware len of the message (len of `chaddr`).
    #[inline]
    pub fn hlen(&self) -> u8 {
        self.as_ref()[2]
    }

    /// Gets the 'secs' field.
    ///
    /// This is the number of seconds elapsed since client began
    /// address acquisition or renewal process.
    #[inline]
    pub fn secs(&self) -> u16 {
        NetworkEndian::read_u16(&self.as_ref()[8..])
    }

    #[inline]
    pub fn flags(&self) -> Flags {
        Flags::from_bits_truncate(NetworkEndian::read_u16(&self.as_ref()[10..]))
    }

    /// Gets the 'yiaddr' field (your address).
    #[inline]
    pub fn yiaddr(&self) -> &Addr {
        self.as_ref()[16..].try_into().unwrap()
    }

    /// Gets the 'siaddr' field (IP address of next server to use in bootstrap).
    #[inline]
    pub fn siaddr(&self) -> &Addr {
        self.as_ref()[20..].try_into().unwrap()
    }

    /// Gets the 'giaddr' field (the gateway IP or unspecified).
    #[inline]
    pub fn giaddr(&self) -> &Addr {
        self.as_ref()[24..].try_into().unwrap()
    }

    /// Returns the 'chaddr' field (client hardware address).
    ///
    /// An error is returned if the value of the 'hlen' field exceeds
    /// the maximum length of 16.
    #[inline]
    pub fn chaddr(&self) -> Result<&[u8], Error> {
        self.as_ref()[28..][..16]
            .get(..self.hlen() as usize)
            .ok_or(Error::Malformed)
    }

    /// Returns the optional server host name.
    pub fn sname(&self) -> Result<&[u8], Error> {
        let data = self.as_ref();
        if let Some(nul_pos) = memchr(0, &data[SNAME_FIELD_OFFSET..][..64]) {
            Ok(&data[SNAME_FIELD_OFFSET..][..nul_pos])
        } else {
            Err(Error::BadNull)
        }
    }

    /// Returns the boot file name.
    pub fn file(&self) -> Result<&[u8], Error> {
        let data = self.as_ref();
        if let Some(nul_pos) = memchr(0, &data[FILE_FIELD_OFFSET..][..128]) {
            Ok(&data[FILE_FIELD_OFFSET..][..nul_pos])
        } else {
            Err(Error::BadNull)
        }
    }

    /// Returns an iterator over DHCP options.
    ///
    /// The ['pad'](DhcpOption::Pad) and ['end'](DhcpOption::End)
    /// options are excluded.
    #[inline]
    pub fn options(
        &self,
    ) -> Result<impl Iterator<Item = Result<(DhcpOption<'_>, (usize, usize)), Error>>, Error> {
        Options::new(self.as_ref())
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Dhcpv4View<T> {
    /// Sets the 'op' field.
    #[inline]
    pub fn set_op(&mut self, op: OpCode) {
        self.as_mut()[0] = op as u8;
    }

    /// Sets the gatewap IP address.
    #[inline]
    pub fn set_giaddr(&mut self, Addr(giaddr): Addr) {
        self.as_mut()[24..][..4].copy_from_slice(&giaddr)
    }

    /// Sets the 'chaddr' field.
    ///
    /// This setter also updates the length stored in the 'hlen' field.
    #[inline]
    pub fn set_chaddr(&mut self, chaddr: &[u8]) -> Result<(), Error> {
        self.as_mut()[28..][..4]
            .get_mut(..chaddr.len())
            .ok_or(Error::TooLong)?
            .copy_from_slice(chaddr);
        self.as_mut()[2] = chaddr.len() as u8;
        Ok(())
    }
}

/// An interface for DHCPv4 message transforms.
pub trait Encode {
    /// Reencodes the given DHCPv4 message using this transform.
    ///
    /// The return value, if successful, is a sliced reference to the
    /// written bytes.
    fn encode<'dst, T: AsRef<[u8]>>(
        mut self,
        src: &Dhcpv4View<T>,
        dst: &'dst mut [u8],
    ) -> Result<&'dst mut [u8], Error>
    where
        Self: Sized,
    {
        let data = src.as_ref();
        dst[..data.len()].copy_from_slice(data);
        let mut cursor = Cursor {
            buffer: dst,
            index: OPTIONS_FIELD_OFFSET + MAGIC_COOKIE.len(),
        };

        src.options()?.try_for_each(|x| {
            let (option, bnd) = x?;
            self.write_option(&mut cursor, (&option, bnd))
        })?;
        self.write_new_options(&mut cursor)?;
        DhcpOption::End.write(&mut cursor)?;

        let len = cursor.index;
        Ok(&mut dst[..len])
    }

    #[doc(hidden)]
    fn write_option<'old, 'new>(
        &mut self,
        cursor: &mut Cursor<'new>,
        old_option: (&DhcpOption<'old>, (usize, usize)),
    ) -> Result<(), Error>;

    #[doc(hidden)]
    fn write_new_options<'new>(&mut self, cursor: &mut Cursor<'new>) -> Result<(), Error>;

    /// Returns a new transform that additionally sets the given option.
    ///
    /// This does not support setting options need more than 255 bytes
    /// of data.
    #[inline]
    fn set_option(self, option: DhcpOption<'_>) -> SetOption<'_, Self>
    where
        Self: Sized,
    {
        SetOption {
            prev: self,
            replaced: false,
            option,
        }
    }
}

/// A base transform that just copies the old message.
pub struct Encoder;

impl Encode for Encoder {
    #[inline]
    fn write_option<'old, 'new>(
        &mut self,
        cursor: &mut Cursor<'new>,
        (old_option, (start, len)): (&DhcpOption<'old>, (usize, usize)),
    ) -> Result<(), Error> {
        if cursor.index == start {
            // Since we copied old data the option has already been written
            cursor.index += len;
            Ok(())
        } else {
            old_option.write(cursor)
        }
    }

    #[inline]
    fn write_new_options<'new>(&mut self, _cursor: &mut Cursor<'new>) -> Result<(), Error> {
        Ok(())
    }
}

/// A transform that sets a given option.
pub struct SetOption<'a, Prev> {
    prev: Prev,
    replaced: bool,
    option: DhcpOption<'a>,
}

impl<'a, Prev: Encode> Encode for SetOption<'a, Prev> {
    #[inline]
    fn write_option<'old, 'new>(
        &mut self,
        cursor: &mut Cursor<'new>,
        (old_option, bnd): (&DhcpOption<'old>, (usize, usize)),
    ) -> Result<(), Error> {
        if old_option.code() == self.option.code() {
            if !self.replaced {
                self.option.write(cursor)?;
            }
            self.replaced = true;
            Ok(())
        } else {
            self.prev.write_option(cursor, (old_option, bnd))
        }
    }

    #[inline]
    fn write_new_options<'new>(&mut self, cursor: &mut Cursor<'new>) -> Result<(), Error> {
        self.prev.write_new_options(cursor)?;
        if !self.replaced {
            self.option.write(cursor)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An example DHCPOFFER message.
    const EX_MSG: [u8; 244] = [
        /* op */ 2, /* htype */ 1, /* hlen */ 6, /* hops */ 0,
        /* xid */ 0xC7, 0xF5, 0xA0, 0xA7, /* secs */ 1, 2, /* flags */ 0x80, 0x00,
        /* ciaddr */ 0x00, 0x00, 0x00, 0x00, /* yiaddr */ 0x12, 0x34, 0x56, 0x78,
        /* siaddr */ 0x00, 0x00, 0x00, 0x00, /* giaddr */ 0x11, 0x22, 0x33, 0x44,
        /* chaddr */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* sname */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, /* file */ /* msg type */ 53, 1, 2, /* end */ 255, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, /* magic */ 99, 130, 83, 99, /* options */
        /* option overload */ 52, 1, 0b01, /* end */ 255,
    ];

    #[cfg(feature = "std")]
    #[test]
    fn it_works() -> Result<(), Error> {
        use std::net::Ipv4Addr;

        let view = Dhcpv4View::new(EX_MSG)?;
        assert_eq!(view.op()?, OpCode::BootReply);
        assert_eq!(view.hlen(), 6);
        assert_eq!(view.secs(), 0x0102);
        assert_eq!(view.flags(), Flags::BROADCAST);
        assert_eq!(view.yiaddr(), &Ipv4Addr::new(0x12, 0x34, 0x56, 0x78).into());
        assert_eq!(view.siaddr(), &Ipv4Addr::UNSPECIFIED.into());
        assert_eq!(view.giaddr(), &Ipv4Addr::new(0x11, 0x22, 0x33, 0x44).into());
        assert_eq!(view.chaddr()?, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        Ok(())
    }

    #[cfg(feature = "std")]
    #[test]
    fn can_set_giaddr() -> Result<(), Error> {
        use std::net::Ipv4Addr;

        let mut view = Dhcpv4View::new(EX_MSG)?;
        let new_giaddr = Ipv4Addr::new(0x31, 0x41, 0x59, 0x26);
        view.set_giaddr(new_giaddr.into());
        assert_eq!(view.giaddr(), &new_giaddr.into());
        Ok(())
    }

    #[cfg(feature = "std")]
    #[test]
    fn read_options() -> Result<(), Error> {
        let view = Dhcpv4View::new(EX_MSG)?;
        assert_eq!(
            view.options()?.collect::<Result<Vec<_>, _>>()?,
            [
                (DhcpOption::OptionOverload(OptionOverload::FILE), (240, 3)),
                (DhcpOption::MessageType(MessageType::Offer), (108, 3))
            ]
        );
        Ok(())
    }

    #[cfg(feature = "std")]
    #[test]
    fn write_options() -> Result<(), Error> {
        let view = Dhcpv4View::new(EX_MSG)?;
        let mut out = [0; 576];

        // Try to replace an option
        assert_eq!(
            Dhcpv4View::new(
                Encoder
                    .set_option(DhcpOption::MessageType(MessageType::Request))
                    .encode(&view, &mut out)?
            )?
            .options()?
            .map(|x| x.unwrap().0)
            .find(|x| matches!(x, DhcpOption::MessageType(_))),
            Some(DhcpOption::MessageType(MessageType::Request)),
        );

        // Add a new option
        assert_eq!(
            Dhcpv4View::new(
                Encoder
                    .set_option(DhcpOption::IpForwarding(true))
                    .encode(&view, &mut out)?
            )?
            .options()?
            .map(|x| x.unwrap().0)
            .find(|x| matches!(x, DhcpOption::IpForwarding(_))),
            Some(DhcpOption::IpForwarding(true)),
        );

        Ok(())
    }
}
