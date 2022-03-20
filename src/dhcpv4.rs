/*!
DHCPv4 definitions and parser.

# Examples

Basic usage:

```
# const EXAMPLE_DISCOVER_MSG: [u8; 250] = [
#     /* op */ 2, /* htype */ 1, /* hlen */ 6, /* hops */ 0,
#     /* xid */ 0xC7, 0xF5, 0xA0, 0xA7, /* secs */ 0, 0, /* flags */ 0x00, 0x00,
#     /* ciaddr */ 0x00, 0x00, 0x00, 0x00, /* yiaddr */ 0x00, 0x00, 0x00, 0x00,
#     /* siaddr */ 0x00, 0x00, 0x00, 0x00, /* giaddr */ 0x00, 0x00, 0x00, 0x00,
#     /* chaddr */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#     /* sname */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#     0, 0, 0, 0, 0, 0, 0, 0, 0, /* file */ /* msg type */ 53, 1, 1, /* end */ 255, 0,
#     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#     0, 0, 0, /* magic */ 99, 130, 83, 99, /* options */
#     /* option overload */ 52, 1, 0b01, /* requested addr */ 50, 4, 192, 168, 1, 100, /* end */ 255,
# ];
use dhcparse::{v4_options, dhcpv4::{Message, MessageType}};
use std::net::Ipv4Addr;

let mut msg = Message::new(EXAMPLE_DISCOVER_MSG)?;

// Read a field
assert_eq!(msg.chaddr()?, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

// Set a field
*msg.giaddr_mut() = Ipv4Addr::new(192, 168, 1, 50).into();

// Parse a set of options
assert_eq!(
    v4_options!(msg; MessageType required, ServerIdentifier, RequestedIpAddress)?,
    (
        MessageType::DISCOVER,
        None,
        Some(&Ipv4Addr::new(192, 168, 1, 100).into())
    )
);
# Ok::<(), dhcparse::Error>(())
```

Constructing a new message:

```
use dhcparse::dhcpv4::{DhcpOption, Encode as _, Encoder, Message, MessageType, OpCode};
// Create a copy of an empty message with the message type option added
let mut msg = Encoder
    .append_option(DhcpOption::MessageType(MessageType::DISCOVER))
    .encode_to_owned(&Message::default())?;
msg.set_op(OpCode::BootRequest);

assert_eq!(msg.options()?.count(), 1);
# Ok::<(), dhcparse::Error>(())
```

See:
 * [RFC2131]: Dynamic Host Configuration Protocol
 * [RFC2132]: DHCP Options and BOOTP Vendor Extensions

[RFC2131]: https://datatracker.ietf.org/doc/html/rfc2131
[RFC2132]: https://datatracker.ietf.org/doc/html/rfc2132
 */

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use core::convert::{TryFrom, TryInto};
use core::fmt;
use core::iter::FusedIterator;
use core::mem;
use memchr::memchr;
use ref_cast::RefCast;

use crate::{Cursor, Error};

pub mod relay;

/// The 'DHCP server' UDP port.
pub const SERVER_PORT: u16 = 67;
/// The 'DHCP client' UDP port.
pub const CLIENT_PORT: u16 = 68;
/// The minimum DHCP message size all agents are required to support.
pub const MAX_MESSAGE_SIZE: usize = 576;

/// An IPv4 address.
///
/// This is similar to [std::net::Ipv4Addr], but has an explicit
/// representation.
#[derive(Clone, Copy, PartialEq, Eq, RefCast, Debug)]
#[repr(transparent)]
pub struct Addr(pub [u8; 4]);

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
impl From<Addr> for std::net::Ipv4Addr {
    #[inline]
    fn from(Addr(x): Addr) -> Self {
        x.into()
    }
}

#[cfg(feature = "std")]
impl From<std::net::Ipv4Addr> for Addr {
    #[inline]
    fn from(x: std::net::Ipv4Addr) -> Addr {
        Addr(x.octets())
    }
}

/// The packet op code/message type.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
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

/// DHCP message type.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageType(u8);

impl MessageType {
    pub const DISCOVER: MessageType = MessageType(1);
    pub const OFFER: MessageType = MessageType(2);
    pub const REQUEST: MessageType = MessageType(3);
    pub const DECLINE: MessageType = MessageType(4);
    pub const ACK: MessageType = MessageType(5);
    pub const NAK: MessageType = MessageType(6);
    pub const RELEASE: MessageType = MessageType(7);
    pub const INFORM: MessageType = MessageType(8);
}

impl From<u8> for MessageType {
    fn from(x: u8) -> Self {
        Self(x)
    }
}

impl From<MessageType> for u8 {
    fn from(MessageType(x): MessageType) -> Self {
        x
    }
}

impl fmt::Debug for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match *self {
            MessageType::DISCOVER => "DISCOVER",
            MessageType::OFFER => "OFFER",
            MessageType::REQUEST => "REQUEST",
            MessageType::DECLINE => "DECLINE",
            MessageType::ACK => "ACK",
            MessageType::NAK => "NAK",
            MessageType::RELEASE => "RELEASE",
            MessageType::INFORM => "INFORM",
            Self(x) => return f.debug_tuple("MessageType").field(&x).finish(),
        };
        f.write_str(name)
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
#[non_exhaustive]
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
    /// 2 Time Offset
    TimeOffset(i32),
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
    LprServer(&'a [Addr]),
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
    /// 20 Non-Local Source Routing Enable/Disable
    NonLocalSrcRouting(bool),
    /// 21 Policy Filter
    PolicyFilter(&'a [[Addr; 2]]),
    /// 22 Maximum Datagram Reassembly Size
    ///
    /// The minimum legal value is [`MAX_MESSAGE_SIZE`].
    MaximumDatagramSize(u16),
    /// 50 Requested IP Address
    RequestedIpAddress(&'a Addr),
    /// 51 IP Address Lease Time
    AddressLeaseTime(u32),
    /// 52 Option Overload
    OptionOverload(OptionOverload),
    /// 53 DHCP Message Type
    ///
    /// This option is required.
    MessageType(MessageType),
    /// 54 Server Identifier
    ServerIdentifier(&'a Addr),
    /// 55 Parameter Request List
    ParameterRequestList(&'a [u8]),
    /// 56 Message
    Message(&'a [u8]),
    /// 57 Maximum DHCP Message Size
    ///
    /// The minimum legal value is [`MAX_MESSAGE_SIZE`].
    MaximumMessageSize(u16),
    /// 60 Vendor class identifier
    VendorClassIdentifier(&'a [u8]),
    /// 61 Client-identifier
    ///
    /// The first byte is the type field which should correspond to
    /// 'htype' in case the client identifier is a hardware address,
    /// or be zero.
    ClientIdentifier(&'a [u8]),
    /// 82 Relay Agent Information
    RelayAgentInformation(relay::RelayAgentInformation<'a>),
    /// Unrecognized option.
    Unknown(u8, &'a [u8]),
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

#[inline]
fn read_addr_pairs(b: &[u8]) -> Result<&[[Addr; 2]], Error> {
    if b.len() < 8 || b.len() % mem::size_of::<[Addr; 2]>() != 0 {
        return Err(Error::Malformed);
    }
    // Safety: Ok, since Addr has same representation as [u8; 4].
    Ok(unsafe { &*(b as *const [u8] as *const [[Addr; 2]]) })
}

impl<'a> DhcpOption<'a> {
    /// Returns the tag of this parameter.
    pub fn code(&self) -> u8 {
        use DhcpOption::*;
        match *self {
            Pad => 0,
            End => 255,
            SubnetMask(_) => 1,
            TimeOffset(_) => 2,
            Router(_) => 3,
            TimeServer(_) => 4,
            NameServer(_) => 5,
            DomainNameServer(_) => 6,
            LogServer(_) => 7,
            CookieServer(_) => 8,
            LprServer(_) => 9,
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
            NonLocalSrcRouting(_) => 20,
            PolicyFilter(_) => 21,
            MaximumDatagramSize(_) => 22,
            RequestedIpAddress(_) => 50,
            AddressLeaseTime(_) => 51,
            OptionOverload(_) => 52,
            MessageType(_) => 53,
            ServerIdentifier(_) => 54,
            ParameterRequestList(_) => 55,
            Message(_) => 56,
            MaximumMessageSize(_) => 57,
            VendorClassIdentifier(_) => 60,
            ClientIdentifier(_) => 61,
            RelayAgentInformation(_) => 82,
            Unknown(code, _) => code,
        }
    }

    fn read(buf: &'a [u8]) -> Result<(Self, usize), Error> {
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
                2 => {
                    if b.len() != 4 {
                        return Err(Error::Malformed);
                    }
                    TimeOffset(NetworkEndian::read_i32(b))
                }
                3 => Router(read_addrs(b)?),
                4 => TimeServer(read_addrs(b)?),
                5 => NameServer(read_addrs(b)?),
                6 => DomainNameServer(read_addrs(b)?),
                7 => LogServer(read_addrs(b)?),
                8 => CookieServer(read_addrs(b)?),
                9 => LprServer(read_addrs(b)?),
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
                20 => match *b {
                    [x] => NonLocalSrcRouting(x == 1),
                    _ => return Err(Error::Malformed),
                },
                21 => PolicyFilter(read_addr_pairs(b)?),
                22 => {
                    if b.len() != 2 {
                        return Err(Error::Malformed);
                    }
                    MaximumDatagramSize(NetworkEndian::read_u16(b))
                }
                50 => RequestedIpAddress(b.try_into()?),
                51 => {
                    if b.len() != 4 {
                        return Err(Error::Malformed);
                    }
                    AddressLeaseTime(NetworkEndian::read_u32(b))
                }
                52 => match *b {
                    [x] => {
                        OptionOverload(self::OptionOverload::from_bits(x).ok_or(Error::Malformed)?)
                    }
                    _ => return Err(Error::Malformed),
                },
                53 => match *b {
                    [x] => MessageType(x.into()),
                    _ => return Err(Error::Malformed),
                },
                54 => ServerIdentifier(b.try_into()?),
                55 => ParameterRequestList(read_str(b)?),
                56 => Message(read_str(b)?),
                57 => {
                    if b.len() != 2 {
                        return Err(Error::Malformed);
                    }
                    MaximumMessageSize(NetworkEndian::read_u16(b))
                }
                60 => VendorClassIdentifier(read_str(b)?),
                61 => {
                    if b.len() < 2 {
                        return Err(Error::Malformed);
                    }
                    ClientIdentifier(read_str(b)?)
                }
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
            SubnetMask(addr)
            | SwapServer(addr)
            | RequestedIpAddress(addr)
            | ServerIdentifier(addr) => {
                cursor.write_u8(addr.0.len() as u8)?;
                cursor.write(&addr.0)
            }
            TimeOffset(i) => {
                cursor.write_u8(4)?;
                cursor.write(&i.to_be_bytes())
            }
            Router(addrs)
            | TimeServer(addrs)
            | NameServer(addrs)
            | DomainNameServer(addrs)
            | LogServer(addrs)
            | CookieServer(addrs)
            | LprServer(addrs)
            | ImpressServer(addrs)
            | ResourceLocationServer(addrs) => {
                // Safety: Addr has the same representation as [u8; 4]
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
            | ParameterRequestList(xs)
            | Message(xs)
            | VendorClassIdentifier(xs)
            | ClientIdentifier(xs)
            | Unknown(_, xs) => {
                cursor.write_u8(xs.len().try_into().map_err(|_| Error::TooLong)?)?;
                cursor.write(xs)
            }
            BootFileSize(x) | MaximumDatagramSize(x) | MaximumMessageSize(x) => {
                cursor.write_u8(2)?;
                cursor.write(&x.to_be_bytes())
            }
            IpForwarding(x) | NonLocalSrcRouting(x) => {
                cursor.write_u8(1)?;
                cursor.write_u8(if x { 1 } else { 0 })
            }
            PolicyFilter(addr_pairs) => {
                // Safety: Addr has the same representation as [u8; 4]
                let xs = unsafe { &*(addr_pairs as *const [[Addr; 2]] as *const [u8]) };
                cursor.write_u8(xs.len().try_into().map_err(|_| Error::TooLong)?)?;
                cursor.write(xs)
            }
            AddressLeaseTime(i) => {
                cursor.write_u8(4)?;
                cursor.write(&i.to_be_bytes())
            }
            OptionOverload(x) => {
                cursor.write_u8(1)?;
                cursor.write_u8(x.bits())
            }
            MessageType(self::MessageType(x)) => {
                cursor.write_u8(1)?;
                cursor.write_u8(x)
            }
        }
    }

    /// Returns the byte size of this option when serialized.
    fn size(&self) -> usize {
        use DhcpOption::*;
        match self {
            Pad
            | IpForwarding(_)
            | NonLocalSrcRouting(_)
            | OptionOverload(_)
            | MessageType(_)
            | End => 1,
            SubnetMask(addr)
            | SwapServer(addr)
            | RequestedIpAddress(addr)
            | ServerIdentifier(addr) => mem::size_of_val(addr),
            TimeOffset(_) | AddressLeaseTime(_) => 4,
            Router(addrs)
            | TimeServer(addrs)
            | NameServer(addrs)
            | DomainNameServer(addrs)
            | LogServer(addrs)
            | CookieServer(addrs)
            | LprServer(addrs)
            | ImpressServer(addrs)
            | ResourceLocationServer(addrs) => mem::size_of_val(addrs),
            HostName(xs)
            | MeritDumpFile(xs)
            | DomainName(xs)
            | RootPath(xs)
            | ExtensionsPath(xs)
            | RelayAgentInformation(relay::RelayAgentInformation(xs))
            | ParameterRequestList(xs)
            | Message(xs)
            | VendorClassIdentifier(xs)
            | ClientIdentifier(xs)
            | Unknown(_, xs) => mem::size_of_val(xs),
            BootFileSize(_) | MaximumDatagramSize(_) | MaximumMessageSize(_) => 2,
            PolicyFilter(addr_pairs) => mem::size_of_val(addr_pairs),
        }
    }
}

const SNAME_FIELD_OFFSET: usize = 44;
const FILE_FIELD_OFFSET: usize = SNAME_FIELD_OFFSET + 64;
const OPTIONS_FIELD_OFFSET: usize = FILE_FIELD_OFFSET + 128;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Immutable DHCPv4 option iterator.
///
/// This `struct` is created by the [`options`] method on [`Message`].
/// See its documentation for more.
///
/// [`options`]: Message::options
#[derive(Clone, Debug)]
pub struct Options<'a> {
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
#[derive(Clone, Debug)]
pub struct Message<T>(T);

impl<T: AsRef<[u8]>> AsRef<[u8]> for Message<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: AsMut<[u8]>> AsMut<[u8]> for Message<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<T> Message<T> {
    /// Consumes the view and returns the underlying buffer.
    #[inline]
    pub fn into_inner(self) -> T {
        let Message(inner) = self;
        inner
    }
}

impl Default for Message<[u8; 241]> {
    /// Returns a DHCPv4 message with all fields set to zero and zero options.
    ///
    /// This is intended for bootstrapping a message with [`Encoder::encode`].
    fn default() -> Self {
        let mut buf = [0; 241];
        buf[OPTIONS_FIELD_OFFSET..][..MAGIC_COOKIE.len()].copy_from_slice(&MAGIC_COOKIE);
        buf[OPTIONS_FIELD_OFFSET + MAGIC_COOKIE.len()] = DhcpOption::End.code();
        Self(buf)
    }
}

impl<T: AsRef<[u8]>> Message<T> {
    /// Constructs a new view from an underlying message buffer.
    ///
    /// Returns an error if the length of the buffer is smaller than
    /// any valid message.
    #[inline]
    pub fn new(b: T) -> Result<Message<T>, Error> {
        if b.as_ref().len() < OPTIONS_FIELD_OFFSET + MAGIC_COOKIE.len() + 4 {
            return Err(Error::Underflow);
        }
        Ok(Message(b))
    }

    /// Gets the 'op' field (message type).
    #[inline]
    pub fn op(&self) -> Result<OpCode, Error> {
        self.as_ref()[0].try_into()
    }

    /// Gets the hardware len of the message (length of `chaddr`).
    #[inline]
    pub fn hlen(&self) -> u8 {
        self.as_ref()[2]
    }

    /// Gets the 'hops' field.
    #[inline]
    pub fn hops(&self) -> u8 {
        self.as_ref()[3]
    }

    /// Gets the transaction ID.
    #[inline]
    pub fn xid(&self) -> u32 {
        NetworkEndian::read_u32(&self.as_ref()[4..])
    }

    /// Gets the 'secs' field.
    ///
    /// This is the number of seconds elapsed since client began
    /// address acquisition or renewal process.
    #[inline]
    pub fn secs(&self) -> u16 {
        NetworkEndian::read_u16(&self.as_ref()[8..])
    }

    /// Gets the 'flags' field.
    #[inline]
    pub fn flags(&self) -> Flags {
        Flags::from_bits_truncate(NetworkEndian::read_u16(&self.as_ref()[10..]))
    }

    /// Gets the 'ciaddr' field (client address).
    #[inline]
    pub fn ciaddr(&self) -> &Addr {
        self.as_ref()[12..].try_into().unwrap()
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
    /// # Errors
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

    /// Returns an iterator over the DHCP options.
    ///
    /// The ['pad'](DhcpOption::Pad) and ['end'](DhcpOption::End)
    /// options are excluded. If at some point the message is
    /// malformed, the corresponding error will be repeated endlessly.
    #[inline]
    pub fn options(&self) -> Result<Options<'_>, Error> {
        Options::new(self.as_ref())
    }
}

impl<T: AsMut<[u8]>> Message<T> {
    /// Sets the 'op' field.
    #[inline]
    pub fn set_op(&mut self, op: OpCode) {
        self.as_mut()[0] = op as u8;
    }

    /// Returns a mutable reference to the 'hops' field.
    pub fn hops_mut(&mut self) -> &mut u8 {
        &mut self.as_mut()[3]
    }

    /// Sets the 'xid' field.
    pub fn set_xid(&mut self, xid: u32) {
        NetworkEndian::write_u32(&mut self.as_mut()[4..], xid)
    }

    /// Sets the 'secs' field.
    pub fn set_secs(&mut self, secs: u16) {
        NetworkEndian::write_u16(&mut self.as_mut()[8..], secs)
    }

    /// Sets the 'flags' field.
    #[inline]
    pub fn set_flags(&mut self, flags: Flags) {
        NetworkEndian::write_u16(&mut self.as_mut()[10..], flags.bits())
    }

    /// Returns a mutable reference to the 'ciaddr' field.
    #[inline]
    pub fn ciaddr_mut(&mut self) -> &mut Addr {
        Addr::ref_cast_mut((&mut self.as_mut()[12..][..4]).try_into().unwrap())
    }

    /// Returns a mutable reference to the 'yiaddr' field.
    #[inline]
    pub fn yiaddr_mut(&mut self) -> &mut Addr {
        Addr::ref_cast_mut((&mut self.as_mut()[16..][..4]).try_into().unwrap())
    }

    /// Returns a mutable reference to the 'siaddr' field.
    #[inline]
    pub fn siaddr_mut(&mut self) -> &mut Addr {
        Addr::ref_cast_mut((&mut self.as_mut()[20..][..4]).try_into().unwrap())
    }

    /// Returns a mutable reference to the 'giaddr' field.
    #[inline]
    pub fn giaddr_mut(&mut self) -> &mut Addr {
        Addr::ref_cast_mut((&mut self.as_mut()[24..][..4]).try_into().unwrap())
    }

    /// Sets the 'chaddr' field.
    ///
    /// This setter also updates the length stored in the 'hlen' field.
    #[inline]
    pub fn set_chaddr(&mut self, chaddr: &[u8]) -> Result<(), Error> {
        self.as_mut()[28..][..16]
            .get_mut(..chaddr.len())
            .ok_or(Error::TooLong)?
            .copy_from_slice(chaddr);
        self.as_mut()[2] = chaddr.len() as u8;
        Ok(())
    }
}

#[doc(hidden)]
pub mod _get_options {
    /// Dummy identifier to only allow the keyword `required` in [`v4_options`].
    #[allow(non_upper_case_globals)]
    pub const required: () = ();
}

/// Convenience macro for parsing a set of DHCPv4 options from a message.
///
/// It takes as arguments a [`Message`] and a set of [`DhcpOption`]
/// variant names and returns either a parse error or a tuple
/// containing the data of the respective options. Each option name
/// may optionally be followed by the keyword `required`. In that case
/// it is an error if the option is missing and the data will not be
/// wrapped in an [`Option`].
///
/// For getting *all* occurances of an option, one has to fall back on
/// [`Message::options`] with a custom reducer.
///
/// # Example
///
/// ```no_run
/// use std::net::Ipv4Addr;
/// use dhcparse::{v4_options, dhcpv4::{Message, MessageType}};
/// # let buf: &[u8] = todo!();
/// let msg = Message::new(buf)?;
/// assert_eq!(
///     v4_options!(msg; MessageType required, RequestedIpAddress)?,
///     (
///         MessageType::DISCOVER,
///         Some(&Ipv4Addr::new(192, 168, 1, 100).into())
///     )
/// );
/// # Ok::<(), dhcparse::Error>(())
/// ```
#[macro_export]
macro_rules! v4_options {
    ($msg:expr; $($opt:ident $($required:ident)? ),*) => ('outer: loop {
        use ::core::{result::Result::*, option::Option::*};
        let mut count = 0;
        $(#[allow(non_snake_case)] let mut $opt = None; count += 1;)*
        for x in match $msg.options() {
            Ok(x) => x,
            Err(e) => break Err(e),
        } {
            match x {
                $(Ok(($crate::dhcpv4::DhcpOption::$opt(data), _))
                    if $opt.is_none() => { $opt = Some(data); },)*
                Ok(_) => continue,
                Err(e) => break 'outer Err(e),
            }
            count -= 1;
            if count == 0 { break; }
        }
        break Ok(($({
            let x = $opt;
            $(
                $crate::dhcpv4::_get_options::$required;
                let x = if let Some(x) = x {
                    x
                } else {
                    break Err($crate::Error::MissingRequired);
                };
            )?
            x
        }),*));
    })
}

mod private {
    pub trait Sealed {}

    impl Sealed for super::Encoder {}
    impl<Prev> Sealed for super::AppendOption<'_, Prev> {}
    impl<Prev> Sealed for super::SetOption<'_, Prev> {}
    impl<Prev, F> Sealed for super::FilterOptions<Prev, F> {}
}

/// An interface for DHCPv4 message transforms.
pub trait Encode: private::Sealed {
    /// Reencodes the given DHCPv4 message using this transform.
    ///
    /// The return value, if successful, is a sliced reference to the
    /// written bytes.
    fn encode<'dst, T: AsRef<[u8]>>(
        mut self,
        src: &Message<T>,
        dst: &'dst mut [u8],
    ) -> Result<Message<&'dst mut [u8]>, Error>
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
            self.write_option(&mut cursor, data, (&option, bnd))
        })?;
        self.write_new_options(&mut cursor)?;
        DhcpOption::End.write(&mut cursor)?;

        let len = cursor.index;
        Ok(Message::new(&mut dst[..len]).unwrap())
    }

    /// Reencodes the given DHCPv4 message to a new owned buffer.
    #[cfg(feature = "std")]
    fn encode_to_owned<T: AsRef<[u8]>>(self, src: &Message<T>) -> Result<Message<Vec<u8>>, Error>
    where
        Self: Sized,
    {
        let mut buf = vec![0; src.as_ref().len() + self.max_size_diff()];
        let len = self.encode(src, &mut buf)?.as_ref().len();
        buf.truncate(len);
        Ok(Message::new(buf).unwrap())
    }

    #[doc(hidden)]
    fn write_option<'old, 'new>(
        &mut self,
        cursor: &mut Cursor<'new>,
        src: &'old [u8],
        old_option: (&DhcpOption<'old>, (usize, usize)),
    ) -> Result<(), Error>;

    #[doc(hidden)]
    fn write_new_options<'new>(&mut self, cursor: &mut Cursor<'new>) -> Result<(), Error>;

    /// Returns the largest byte size increase this encoder can incur
    /// when reencoding any message.
    fn max_size_diff(&self) -> usize;

    /// Returns a new transform that additionally appends the given option.
    #[inline]
    fn append_option(self, option: DhcpOption<'_>) -> AppendOption<'_, Self>
    where
        Self: Sized,
    {
        AppendOption { prev: self, option }
    }

    /// Returns a new transform that additionally sets the given option.
    ///
    /// For setting options that need more than 255 bytes of data, use
    /// a combination of [`append_option`] and [`filter_options`].
    ///
    /// [`append_option`]: Self::append_option
    /// [`filter_options`]: Self::filter_options
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

    /// Returns a new transform that initially discards any options
    /// for which the function returns true.
    #[inline]
    fn filter_options<F>(self, f: F) -> FilterOptions<Self, F>
    where
        FilterOptions<Self, F>: Encode,
        Self: Sized,
    {
        FilterOptions { prev: self, f }
    }
}

/// A base transform that just copies the old message.
#[derive(Debug)]
pub struct Encoder;

impl Encode for Encoder {
    #[inline]
    fn write_option<'old, 'new>(
        &mut self,
        cursor: &mut Cursor<'new>,
        src: &'old [u8],
        (old_option, (start, len)): (&DhcpOption<'old>, (usize, usize)),
    ) -> Result<(), Error> {
        if let DhcpOption::OptionOverload(_) = old_option {
            return Ok(());
        }
        if cursor.index == start {
            // Since we copied old data the option has already been written
            cursor.index += len;
            Ok(())
        } else {
            cursor.write(&src[start..][..len])
        }
    }

    #[inline]
    fn write_new_options<'new>(&mut self, _cursor: &mut Cursor<'new>) -> Result<(), Error> {
        Ok(())
    }

    #[inline]
    fn max_size_diff(&self) -> usize {
        // Since we do not use the sname/file fields when reencoding
        // messages, any options in those fields would take up space
        // at the end instead.
        /* sname field */
        64 + /* file field */ 128 - /* end in both fields */ 2 - /* option overload option */ 3
    }
}

/// A transform that appends a given option.
#[derive(Debug)]
pub struct AppendOption<'a, Prev> {
    prev: Prev,
    option: DhcpOption<'a>,
}

impl<'a, Prev: Encode> Encode for AppendOption<'a, Prev> {
    #[inline]
    fn write_option<'old, 'new>(
        &mut self,
        cursor: &mut Cursor<'new>,
        src: &'old [u8],
        (old_option, bnd): (&DhcpOption<'old>, (usize, usize)),
    ) -> Result<(), Error> {
        self.prev.write_option(cursor, src, (old_option, bnd))
    }

    #[inline]
    fn write_new_options<'new>(&mut self, cursor: &mut Cursor<'new>) -> Result<(), Error> {
        self.prev.write_new_options(cursor)?;
        self.option.write(cursor)
    }

    #[inline]
    fn max_size_diff(&self) -> usize {
        self.prev.max_size_diff() + self.option.size()
    }
}

/// A transform that sets a given option.
#[derive(Debug)]
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
        src: &'old [u8],
        (old_option, bnd): (&DhcpOption<'old>, (usize, usize)),
    ) -> Result<(), Error> {
        if old_option.code() == self.option.code() {
            if !self.replaced {
                self.option.write(cursor)?;
            }
            self.replaced = true;
            Ok(())
        } else {
            self.prev.write_option(cursor, src, (old_option, bnd))
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

    #[inline]
    fn max_size_diff(&self) -> usize {
        self.prev.max_size_diff() + self.option.size()
    }
}

/// A transform that filters options.
#[derive(Debug)]
pub struct FilterOptions<Prev, F> {
    prev: Prev,
    f: F,
}

impl<Prev: Encode, F> Encode for FilterOptions<Prev, F>
where
    for<'a> F: Fn(DhcpOption<'a>) -> bool,
{
    #[inline]
    fn write_option<'old, 'new>(
        &mut self,
        cursor: &mut Cursor<'new>,
        src: &'old [u8],
        (old_option, bnd): (&DhcpOption<'old>, (usize, usize)),
    ) -> Result<(), Error> {
        if (self.f)(*old_option) {
            self.prev.write_option(cursor, src, (old_option, bnd))
        } else {
            Ok(())
        }
    }

    #[inline]
    fn write_new_options<'new>(&mut self, cursor: &mut Cursor<'new>) -> Result<(), Error> {
        self.prev.write_new_options(cursor)
    }

    #[inline]
    fn max_size_diff(&self) -> usize {
        self.prev.max_size_diff()
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

    #[test]
    fn it_works() -> Result<(), Error> {
        use std::net::Ipv4Addr;

        let view = Message::new(EX_MSG)?;
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

    #[test]
    fn can_set_giaddr() -> Result<(), Error> {
        use std::net::Ipv4Addr;

        let mut view = Message::new(EX_MSG)?;
        let new_giaddr = Ipv4Addr::new(0x31, 0x41, 0x59, 0x26);
        *view.giaddr_mut() = new_giaddr.into();
        assert_eq!(view.giaddr(), &new_giaddr.into());
        Ok(())
    }

    #[test]
    fn read_options() -> Result<(), Error> {
        let view = Message::new(EX_MSG)?;
        assert_eq!(
            view.options()?.collect::<Result<Vec<_>, _>>()?,
            [
                (DhcpOption::OptionOverload(OptionOverload::FILE), (240, 3)),
                (DhcpOption::MessageType(MessageType::OFFER), (108, 3))
            ]
        );
        Ok(())
    }

    #[test]
    fn write_options() -> Result<(), Error> {
        let view = Message::new(EX_MSG)?;
        let mut out = [0; MAX_MESSAGE_SIZE];

        // Try to replace an option
        assert_eq!(
            Encoder
                .set_option(DhcpOption::MessageType(MessageType::REQUEST))
                .encode(&view, &mut out)?
                .options()?
                .map(|x| x.unwrap().0)
                .find(|x| matches!(x, DhcpOption::MessageType(_))),
            Some(DhcpOption::MessageType(MessageType::REQUEST)),
        );

        // Add a new option
        assert_eq!(
            Encoder
                .set_option(DhcpOption::IpForwarding(true))
                .encode(&view, &mut out)?
                .options()?
                .map(|x| x.unwrap().0)
                .find(|x| matches!(x, DhcpOption::IpForwarding(_))),
            Some(DhcpOption::IpForwarding(true)),
        );

        Ok(())
    }

    #[test]
    fn construct_new_msg() -> Result<(), Error> {
        let client_id = [/* type field */ 6, 0x06, 0, 0, 0, 0, 0];
        let chaddr = &client_id[1..];
        let mut msg = Encoder
            .append_option(DhcpOption::MessageType(MessageType::DISCOVER))
            .append_option(DhcpOption::ClientIdentifier(&client_id))
            .encode_to_owned(&Message::default())?;
        msg.set_chaddr(chaddr)?;

        assert_eq!(msg.chaddr()?, chaddr);
        assert_eq!(
            msg.options()?.collect::<Result<Vec<_>, _>>()?,
            [
                (DhcpOption::MessageType(MessageType::DISCOVER), (240, 3)),
                (DhcpOption::ClientIdentifier(&client_id), (243, 9))
            ]
        );
        Ok(())
    }
}
