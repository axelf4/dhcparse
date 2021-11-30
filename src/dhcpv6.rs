/*!
DHCPv6 definitions and parser.

This module is incomplete, unstable and exempt from semantic versioning.

See:
 * [RFC8415]: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)

[RFC8415]: https://datatracker.ietf.org/doc/html/rfc8415
 */

use byteorder::{ByteOrder, NetworkEndian};
use core::convert::{TryFrom, TryInto};
use core::marker::PhantomData;
use core::mem;
use ref_cast::RefCast;

use crate::Error;

/// The UDP port where clients listen for messages.
pub const CLIENT_PORT: u16 = 546;
/// The UDP port where servers and relay agents listen for messages.
pub const SERVER_PORT: u16 = 547;

/// An IPv6 address.
#[derive(Clone, Copy, PartialEq, Eq, RefCast, Debug)]
#[repr(transparent)]
pub struct Addr(pub [u8; 16]);

impl<'a> TryFrom<&'a [u8]> for &'a Addr {
    type Error = Error;

    #[inline]
    fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
        b[..16]
            .try_into()
            .map(Addr::ref_cast)
            .map_err(|_| Error::Malformed)
    }
}

#[cfg(feature = "std")]
impl From<Addr> for std::net::Ipv6Addr {
    #[inline]
    fn from(Addr(x): Addr) -> Self {
        x.into()
    }
}

#[cfg(feature = "std")]
impl From<std::net::Ipv6Addr> for Addr {
    #[inline]
    fn from(x: std::net::Ipv6Addr) -> Addr {
        Addr(x.octets())
    }
}

/// DHCPv6 message type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum MessageType {
    Solicit,
    Advertise,
    Request,
    Confirm,
    Renew,
    Rebind,
    Reply,
    Release,
    Decline,
    Reconfigure,
    InformationRequest,
    RelayForw,
    RelayRepl,
    Other(u8),
}

impl From<u8> for MessageType {
    fn from(x: u8) -> Self {
        use MessageType::*;
        match x {
            1 => Solicit,
            2 => Advertise,
            3 => Request,
            4 => Confirm,
            5 => Renew,
            6 => Rebind,
            7 => Reply,
            8 => Release,
            9 => Decline,
            10 => Reconfigure,
            11 => InformationRequest,
            12 => RelayForw,
            13 => RelayRepl,
            _ => Other(x),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(x: MessageType) -> u8 {
        use MessageType::*;
        match x {
            Solicit => 1,
            Advertise => 2,
            Request => 3,
            Confirm => 4,
            Renew => 5,
            Rebind => 6,
            Reply => 7,
            Release => 8,
            Decline => 9,
            Reconfigure => 10,
            InformationRequest => 11,
            RelayForw => 12,
            RelayRepl => 13,
            Other(x) => x,
        }
    }
}

trait FromOptionCodeData<'a> {
    fn from(code: u16, data: &'a [u8]) -> Result<Self, Error>
    where
        Self: Sized;
}

/// The DHCP option codes identifiying the specific option types.
#[allow(missing_docs)]
pub mod option_code {
    pub const OPTION_CLIENTID: u16 = 1;
    pub const OPTION_SERVERID: u16 = 2;
    pub const OPTION_IA_NA: u16 = 3;
    pub const OPTION_IA_TA: u16 = 4;
    pub const OPTION_IAADDR: u16 = 5;
    pub const OPTION_ORO: u16 = 6;
    pub const OPTION_PREFERENCE: u16 = 7;
    pub const OPTION_ELAPSED_TIME: u16 = 8;
    pub const OPTION_RELAY_MSG: u16 = 9;
    pub const OPTION_UNICAST: u16 = 12;
    pub const OPTION_RAPID_COMMIT: u16 = 14;
    pub const OPTION_USER_CLASS: u16 = 15;
    pub const OPTION_INTERFACE_ID: u16 = 18;
    pub const OPTION_RECONF_MSG: u16 = 19;
    pub const OPTION_RECONF_ACCEPT: u16 = 20;
    pub const OPTION_INFORMATION_REFRESH_TIME: u16 = 32;
}

/// Top-level DHCP option.
#[derive(Debug)]
pub enum DhcpOption<'a> {
    /// Client Identifier
    ///
    /// Used to carry a DUID that identifies the client.
    ClientIdentifier(&'a [u8]),
    /// Server Identifier
    ///
    /// Used to carry a DUID that identifies the server.
    ServerIdentifier(&'a [u8]),
    /// Identity Association for Non-temporary Addresses
    IaNa(IaNa<'a>),
    OptionRequest(OptionRequest<'a>),
    /// Preference
    Preference(u8),
    /// Elapsed Time
    ///
    /// The amount of time in hundredths of a second, since the client
    /// began its current DHCP transaction.
    ElapsedTime(u16),
    RelayMessage(&'a [u8]),
    ServerUnicast(&'a Addr),
    RapidCommit,
    UserClass(&'a [u8]),
    InterfaceId(&'a [u8]),
    ReconfigureMessage(MessageType),
    ReconfigureAccept,
    /// Information Refresh Time
    ///
    /// The value [`u32::MAX`] is taken to mean "infinity".
    InformationRefreshTime(u32),
    Other(u16, &'a [u8]),
}

impl<'a> FromOptionCodeData<'a> for DhcpOption<'a> {
    fn from(code: u16, data: &'a [u8]) -> Result<Self, Error> {
        use option_code::*;
        Ok(match code {
            OPTION_CLIENTID => Self::ClientIdentifier(data),
            OPTION_SERVERID => Self::ServerIdentifier(data),
            OPTION_IA_NA => Self::IaNa(IaNa::new(data)?),
            OPTION_ORO => Self::OptionRequest(OptionRequest::new(data)?),
            OPTION_PREFERENCE => {
                if data.len() != 1 {
                    return Err(Error::Malformed);
                }
                Self::Preference(data[0])
            }
            OPTION_ELAPSED_TIME => {
                if data.len() != 2 {
                    return Err(Error::Malformed);
                }
                Self::ElapsedTime(NetworkEndian::read_u16(data))
            }
            OPTION_RELAY_MSG => Self::RelayMessage(data),
            OPTION_UNICAST => {
                if data.len() != mem::size_of::<Addr>() {
                    return Err(Error::Malformed);
                }
                Self::ServerUnicast(data.try_into()?)
            }
            OPTION_RAPID_COMMIT => {
                if !data.is_empty() {
                    return Err(Error::Malformed);
                }
                Self::RapidCommit
            }
            OPTION_USER_CLASS => Self::UserClass(data),
            OPTION_INTERFACE_ID => Self::InterfaceId(data),
            OPTION_RECONF_MSG => match *data {
                [x] => {
                    let msg_type = x.into();
                    match msg_type {
                        MessageType::Renew
                        | MessageType::Rebind
                        | MessageType::InformationRequest => Self::ReconfigureMessage(msg_type),
                        _ => return Err(Error::Malformed),
                    }
                }
                _ => return Err(Error::Malformed),
            },
            OPTION_RECONF_ACCEPT => {
                if !data.is_empty() {
                    return Err(Error::Malformed);
                }
                Self::ReconfigureAccept
            }
            OPTION_INFORMATION_REFRESH_TIME => {
                if data.len() != 4 {
                    return Err(Error::Malformed);
                }
                Self::InformationRefreshTime(NetworkEndian::read_u32(data))
            }
            _ => Self::Other(code, data),
        })
    }
}

/// Identity Association for Non-temporary Addresses (IA_NA).
#[derive(Debug)]
pub struct IaNa<'a>(&'a [u8]);

/// An [IA_NA](IaNa) option.
#[derive(Debug)]
pub enum IaNaOption<'a> {
    IaAddress(IaAddress<'a>),
}

impl<'a> FromOptionCodeData<'a> for IaNaOption<'a> {
    fn from(code: u16, data: &'a [u8]) -> Result<Self, Error> {
        Ok(match code {
            option_code::OPTION_IAADDR => Self::IaAddress(IaAddress::new(data)?),
            _ => return Err(Error::Malformed),
        })
    }
}

impl<'a> IaNa<'a> {
    pub fn new(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 12 {
            return Err(Error::Underflow);
        }
        Ok(Self(b))
    }

    pub fn iaid(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[..4])
    }

    pub fn t1(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[4..][..4])
    }

    pub fn t2(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[8..][..4])
    }

    pub fn options(&self) -> impl Iterator<Item = Result<IaNaOption<'a>, Error>> {
        Options::new(&self.0[12..])
    }
}

/// The IA Address option, specifying an address associated with an
/// [IA_NA](IaNa) or IA_TA.
#[derive(Debug)]
pub struct IaAddress<'a>(&'a [u8]);

impl<'a> IaAddress<'a> {
    fn new(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 24 {
            return Err(Error::Underflow);
        }
        Ok(Self(b))
    }

    pub fn addr(&self) -> &'a Addr {
        self.0.try_into().unwrap()
    }

    /// The preferred lifetime in seconds for the address in this option.
    pub fn preferred_lifetime(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[16..][..4])
    }

    /// The valid lifetime in seconds for the address in this option.
    pub fn valid_lifetime(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[20..][..4])
    }
}

/// The data of the Option Request option.
#[derive(Clone, Debug)]
pub struct OptionRequest<'a>(&'a [u8]);

impl<'a> OptionRequest<'a> {
    pub fn new(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() % 2 != 0 {
            return Err(Error::Malformed);
        }
        Ok(Self(b))
    }

    /// Returns an iterator over the codes of the requested option types.
    pub fn requested_options(&self) -> impl Iterator<Item = u16> + 'a {
        self.0.chunks(2).map(NetworkEndian::read_u16)
    }
}

/// Iterator of options in variable-length fields.
struct Options<'a, T> {
    b: &'a [u8],
    option_type: PhantomData<T>,
}

impl<T> Options<'_, T> {
    fn new(b: &[u8]) -> Options<'_, T> {
        Options {
            b,
            option_type: PhantomData,
        }
    }
}

impl<'a, T: FromOptionCodeData<'a>> Iterator for Options<'a, T> {
    type Item = Result<T, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match *self.b {
            [] => None,
            [c0, c1, l0, l1, ref rest @ ..] => {
                let code = NetworkEndian::read_u16(&[c0, c1]);
                let len = NetworkEndian::read_u16(&[l0, l1]).into();
                if rest.len() < len {
                    return Some(Err(Error::Malformed));
                }
                let (data, newb) = rest.split_at(len);
                self.b = newb;
                Some(T::from(code, data))
            }
            _ => return Some(Err(Error::Underflow)),
        }
    }
}

/// A read/write wrapper around a Dynamic Host Protocol version 6
/// message buffer.
#[derive(Debug)]
pub struct Message<T>(T);

impl<T: AsRef<[u8]>> AsRef<[u8]> for Message<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: AsRef<[u8]>> Message<T> {
    pub fn new(b: T) -> Result<Self, Error> {
        if b.as_ref().len() < 4 {
            return Err(Error::Underflow);
        }
        Ok(Self(b))
    }

    /// Gets the DHCP message type.
    pub fn msg_type(&self) -> MessageType {
        self.as_ref()[0].into()
    }

    /// Gets the transaction ID for this message exchange.
    pub fn transaction_id(&self) -> &[u8; 3] {
        self.as_ref()[1..][..3].try_into().unwrap()
    }

    /// Returns an iterator of the options.
    pub fn options(&self) -> impl Iterator<Item = Result<DhcpOption<'_>, Error>> {
        Options::new(&self.as_ref()[4..])
    }
}
