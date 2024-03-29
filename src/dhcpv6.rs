/*!
DHCPv6 definitions and parser.

This module is incomplete, unstable and exempt from semantic versioning.

See:
 * [RFC8415]: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)

[RFC8415]: https://datatracker.ietf.org/doc/html/rfc8415
 */

use byteorder::{ByteOrder, NetworkEndian};
use core::convert::{TryFrom, TryInto};
use core::mem;
use ref_cast::RefCast;

use crate::Error;

/// The UDP port where clients listen for messages.
pub const CLIENT_PORT: u16 = 546;
/// The UDP port where servers and relay agents listen for messages.
pub const SERVER_PORT: u16 = 547;
/// A link-scoped multicast address for clients to communicate with on-link relay agents and servers.
pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Addr = Addr([
    0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x02,
]);
/// A site-scoped multicast address for relay agents to communicate with servers.
///
/// To be used if a relay agents wants to send messages to all servers
/// or because it does not know the unicast addresses of the servers.
pub const ALL_DHCP_SERVERS: Addr = Addr([
    0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x03,
]);

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
    fn from(x: std::net::Ipv6Addr) -> Self {
        Self(x.octets())
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
    RelayForward,
    RelayReply,
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
            12 => RelayForward,
            13 => RelayReply,
            _ => Other(x),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(x: MessageType) -> Self {
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
            RelayForward => 12,
            RelayReply => 13,
            Other(x) => x,
        }
    }
}

/// Statuses of DHCP messages or options.
///
/// See the ["Status Codes" registry](https://www.iana.org/assignments/dhcpv6-parameters)
/// for the current list of status codes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StatusCode {
    Success,
    UnspecFail,
    NoAddrsAvail,
    NoBinding,
    UseMulticast,
    NoPrefixAvail,
    Other(u16),
}

impl From<u16> for StatusCode {
    fn from(x: u16) -> Self {
        use StatusCode::*;
        match x {
            0 => Success,
            1 => UnspecFail,
            2 => NoAddrsAvail,
            3 => NoBinding,
            4 => UseMulticast,
            5 => NoPrefixAvail,
            _ => Other(x),
        }
    }
}

impl From<StatusCode> for u16 {
    fn from(x: StatusCode) -> Self {
        use StatusCode::*;
        match x {
            Success => 0,
            UnspecFail => 1,
            NoAddrsAvail => 2,
            NoBinding => 3,
            UseMulticast => 4,
            NoPrefixAvail => 5,
            Other(x) => x,
        }
    }
}

/// Identity Association for Non-temporary Addresses (IA_NA).
#[derive(Debug)]
pub struct IaNa<'a>(&'a [u8]);

impl<'a> IaNa<'a> {
    pub fn new(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 12 {
            return Err(Error::Underflow);
        }
        Ok(Self(b))
    }

    /// Returns the unique identifier for this IA_NA.
    pub fn iaid(&self) -> u32 {
        NetworkEndian::read_u32(self.0)
    }

    pub fn t1(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[4..])
    }

    pub fn t2(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[8..])
    }

    pub fn options(&self) -> impl Iterator<Item = Result<DhcpOption<'a>, Error>> {
        Options::new(&self.0[12..])
    }
}

/// Identity Association for Temporary Addresses (IA_TA).
#[derive(Debug)]
pub struct IaTa<'a>(&'a [u8]);

impl<'a> IaTa<'a> {
    pub fn new(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 4 {
            return Err(Error::Underflow);
        }
        Ok(Self(b))
    }

    /// Returns the unique identifier for this IA_TA.
    pub fn iaid(&self) -> u32 {
        NetworkEndian::read_u32(self.0)
    }

    pub fn options(&self) -> impl Iterator<Item = Result<DhcpOption<'a>, Error>> {
        Options::new(&self.0[4..])
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
        NetworkEndian::read_u32(&self.0[16..])
    }

    /// The valid lifetime in seconds for the address in this option.
    pub fn valid_lifetime(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[20..])
    }

    /// Returns an iterator over the 'IAaddr-options' associated with this address.
    pub fn options(&self) -> impl Iterator<Item = Result<DhcpOption<'a>, Error>> {
        Options::new(&self.0[24..])
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

/// Identity Association for Prefix Delegation (IA_PD).
#[derive(Debug)]
pub struct IaPd<'a>(&'a [u8]);

impl<'a> IaPd<'a> {
    pub fn new(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 12 {
            return Err(Error::Underflow);
        }
        Ok(Self(b))
    }

    /// Returns the unique identifier for this IA_PD.
    pub fn iaid(&self) -> u32 {
        NetworkEndian::read_u32(self.0)
    }

    pub fn t1(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[4..])
    }

    pub fn t2(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[8..])
    }

    pub fn options(&self) -> impl Iterator<Item = Result<DhcpOption<'a>, Error>> {
        Options::new(&self.0[12..])
    }
}

#[derive(Debug)]
pub struct IaPrefix<'a>(&'a [u8]);

impl<'a> IaPrefix<'a> {
    pub fn new(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 25 {
            return Err(Error::Underflow);
        }
        Ok(Self(b))
    }

    /// The preferred lifetime in seconds for the prefix in this option.
    pub fn preferred_lifetime(&self) -> u32 {
        NetworkEndian::read_u32(self.0)
    }

    /// The valid lifetime in seconds for the prefix in this option.
    pub fn valid_lifetime(&self) -> u32 {
        NetworkEndian::read_u32(&self.0[4..])
    }

    /// Length for this prefix in bits.
    pub fn prefix_len(&self) -> u8 {
        self.0[8]
    }

    /// Returns the IPv6 prefix.
    pub fn ipv6_prefix(&self) -> &'a Addr {
        self.0[9..].try_into().unwrap()
    }

    pub fn options(&self) -> impl Iterator<Item = Result<DhcpOption<'a>, Error>> {
        Options::new(&self.0[25..])
    }
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
    pub const OPTION_STATUS_CODE: u16 = 24;
    pub const OPTION_IA_PD: u16 = 25;
    pub const OPTION_IAPREFIX: u16 = 26;
    pub const OPTION_INFORMATION_REFRESH_TIME: u16 = 32;
    pub const OPTION_ERO: u16 = 43;
    pub const OPTION_CLIENT_LINKLAYER_ADDR: u16 = 79;
}

/// DHCPv6 option.
///
/// Some option variants may only be encapsulated in sub-option fields
/// of specific options.
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
    IaTa(IaTa<'a>),
    IaAddress(IaAddress<'a>),
    OptionRequest(OptionRequest<'a>),
    /// Preference
    Preference(u8),
    /// Elapsed Time
    ///
    /// The amount of time in hundredths of a second, since the client
    /// began its current DHCP transaction.
    ElapsedTime(u16),
    /// Relay Message
    ///
    /// Carries a DHCP message in a Relay-forward or Relay-reply message.
    RelayMessage(&'a [u8]),
    ServerUnicast(&'a Addr),
    RapidCommit,
    UserClass(&'a [u8]),
    InterfaceId(&'a [u8]),
    ReconfigureMessage(MessageType),
    ReconfigureAccept,
    /// Status Code
    ///
    /// The status-message is a UTF-8 encoded string that is not null-terminated.
    StatusCode(StatusCode, &'a [u8]),
    IaPd(IaPd<'a>),
    IaPrefix(IaPrefix<'a>),
    /// Information Refresh Time
    ///
    /// The value [`u32::MAX`] is taken to mean "infinity".
    InformationRefreshTime(u32),
    RelayAgentEchoRequest(&'a [u8]),
    /// DHCPv6 Client Link-Layer Address
    ///
    /// See: [RFC6939](https://datatracker.ietf.org/doc/html/rfc8415)
    ClientLinkLayerAddress(&'a [u8]),
    Other(u16, &'a [u8]),
}

impl<'a> DhcpOption<'a> {
    fn new(code: u16, data: &'a [u8]) -> Result<Self, Error> {
        use option_code::*;
        Ok(match code {
            OPTION_CLIENTID => Self::ClientIdentifier(data),
            OPTION_SERVERID => Self::ServerIdentifier(data),
            OPTION_IA_NA => Self::IaNa(IaNa::new(data)?),
            OPTION_IA_TA => Self::IaTa(IaTa::new(data)?),
            OPTION_IAADDR => Self::IaAddress(IaAddress::new(data)?),
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
            OPTION_STATUS_CODE => {
                if data.len() < 2 {
                    return Err(Error::Malformed);
                }
                let (status, msg) = data.split_at(2);
                Self::StatusCode(u16::from_be_bytes(status.try_into().unwrap()).into(), msg)
            }
            OPTION_IA_PD => Self::IaPd(IaPd::new(data)?),
            OPTION_IAPREFIX => Self::IaPrefix(IaPrefix::new(data)?),
            OPTION_INFORMATION_REFRESH_TIME => {
                if data.len() != 4 {
                    return Err(Error::Malformed);
                }
                Self::InformationRefreshTime(NetworkEndian::read_u32(data))
            }
            OPTION_ERO => {
                if data.len() % 2 != 0 {
                    return Err(Error::Malformed);
                }
                Self::RelayAgentEchoRequest(data)
            }
            OPTION_CLIENT_LINKLAYER_ADDR => Self::ClientLinkLayerAddress(data),
            _ => Self::Other(code, data),
        })
    }

    /// Returns the option code.
    pub fn code(&self) -> u16 {
        use option_code::*;
        use DhcpOption::*;
        match *self {
            ClientIdentifier(_) => OPTION_CLIENTID,
            ServerIdentifier(_) => OPTION_SERVERID,
            IaNa(_) => OPTION_IA_NA,
            IaTa(_) => OPTION_IA_TA,
            IaAddress(_) => OPTION_IAADDR,
            OptionRequest(_) => OPTION_ORO,
            Preference(_) => OPTION_PREFERENCE,
            ElapsedTime(_) => OPTION_ELAPSED_TIME,
            RelayMessage(_) => OPTION_RELAY_MSG,
            ServerUnicast(_) => OPTION_UNICAST,
            RapidCommit => OPTION_RAPID_COMMIT,
            UserClass(_) => OPTION_USER_CLASS,
            InterfaceId(_) => OPTION_INTERFACE_ID,
            ReconfigureMessage(_) => OPTION_RECONF_MSG,
            ReconfigureAccept => OPTION_RECONF_ACCEPT,
            StatusCode(_, _) => OPTION_STATUS_CODE,
            IaPd(_) => OPTION_IA_PD,
            IaPrefix(_) => OPTION_IAPREFIX,
            InformationRefreshTime(_) => OPTION_INFORMATION_REFRESH_TIME,
            RelayAgentEchoRequest(_) => OPTION_ERO,
            ClientLinkLayerAddress(_) => OPTION_CLIENT_LINKLAYER_ADDR,
            Other(code, _) => code,
        }
    }

    /// Returns the value of the 'option-len' field.
    pub fn length(&self) -> Result<u16, Error> {
        use DhcpOption::*;
        Ok(match *self {
            ClientIdentifier(xs)
            | ServerIdentifier(xs)
            | IaNa(self::IaNa(xs))
            | IaTa(self::IaTa(xs))
            | IaAddress(self::IaAddress(xs))
            | OptionRequest(self::OptionRequest(xs))
            | RelayMessage(xs)
            | UserClass(xs)
            | InterfaceId(xs)
            | IaPd(self::IaPd(xs))
            | IaPrefix(self::IaPrefix(xs))
            | RelayAgentEchoRequest(xs)
            | ClientLinkLayerAddress(xs)
            | Other(_, xs) => xs.len().try_into().map_err(|_| Error::Overflow)?,
            Preference(_) | ReconfigureMessage(_) => 1,
            ElapsedTime(_) => 2,
            ServerUnicast(_) => 16,
            RapidCommit | ReconfigureAccept => 0,
            StatusCode(_, xs) => (2 + xs.len()).try_into().map_err(|_| Error::Overflow)?,
            InformationRefreshTime(_) => 4,
        })
    }

    #[cfg(feature = "std")]
    pub fn write(&self, mut writer: impl std::io::Write) -> std::io::Result<()> {
        use DhcpOption::*;
        writer.write_all(&self.code().to_be_bytes())?;
        writer.write_all(
            &self
                .length()
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "too long length")
                })?
                .to_be_bytes(),
        )?;
        match *self {
            ClientIdentifier(xs)
            | ServerIdentifier(xs)
            | IaNa(self::IaNa(xs))
            | IaTa(self::IaTa(xs))
            | IaAddress(self::IaAddress(xs))
            | OptionRequest(self::OptionRequest(xs))
            | RelayMessage(xs)
            | UserClass(xs)
            | InterfaceId(xs)
            | IaPd(self::IaPd(xs))
            | IaPrefix(self::IaPrefix(xs))
            | RelayAgentEchoRequest(xs)
            | ClientLinkLayerAddress(xs)
            | Other(_, xs) => writer.write_all(xs),
            Preference(x) => writer.write_all(&[x]),
            ElapsedTime(x) => writer.write_all(&x.to_be_bytes()),
            ServerUnicast(x) => writer.write_all(&x.0),
            RapidCommit | ReconfigureAccept => Ok(()),
            ReconfigureMessage(x) => writer.write_all(&[x.into()]),
            StatusCode(status, xs) => {
                writer.write_all(&u16::to_be_bytes(status.into()))?;
                writer.write_all(xs)
            }
            InformationRefreshTime(x) => writer.write_all(&x.to_be_bytes()),
        }
    }
}

/// Iterator of options in variable-length fields.
struct Options<'a>(&'a [u8]);

impl<'a> Options<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self(b)
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = Result<DhcpOption<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match *self.0 {
            [] => None,
            [c0, c1, l0, l1, ref rest @ ..] => {
                let code = NetworkEndian::read_u16(&[c0, c1]);
                let len = NetworkEndian::read_u16(&[l0, l1]).into();
                if rest.len() < len {
                    return Some(Err(Error::Malformed));
                }
                let (data, newb) = rest.split_at(len);
                self.0 = newb;
                Some(DhcpOption::new(code, data))
            }
            _ => Some(Err(Error::Underflow)),
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

impl<T> Message<T> {
    /// Consumes the view and returns the underlying buffer.
    #[inline]
    pub fn into_inner(self) -> T {
        let Self(inner) = self;
        inner
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

    /// Gets the number of relay agents that have already relayed this message.
    ///
    /// Only applicable for relay agent messages.
    pub fn hop_count(&self) -> u8 {
        self.as_ref()[1]
    }

    /// Gets the link-address.
    ///
    /// Only applicable for relay agent messages.
    pub fn link_address(&self) -> &Addr {
        self.as_ref()[2..].try_into().unwrap()
    }

    /// Gets the peer-address.
    ///
    /// Only applicable for relay agent messages.
    pub fn peer_address(&self) -> &Addr {
        self.as_ref()[18..].try_into().unwrap()
    }

    /// Returns an iterator of the options.
    pub fn options(&self) -> impl Iterator<Item = Result<DhcpOption<'_>, Error>> {
        let offset = match self.msg_type() {
            MessageType::RelayForward | MessageType::RelayReply => 34,
            _ => 4,
        };
        Options::new(&self.as_ref()[offset..])
    }
}
