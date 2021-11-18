/*!
Definitions and parser for the Relay Agent Information DHCP option.

See: [RFC3046] DHCP Relay Agent Information Option

[RFC3046]: https://datatracker.ietf.org/doc/html/rfc3046
 */
use crate::Error;
use core::iter::FusedIterator;

/// DHCP agent sub-option codes.
pub mod subopt {
    pub const AGENT_CIRCUIT_ID: u8 = 1;
    pub const AGENT_REMOTE_ID: u8 = 2;
}

/// Relay Agent Information sub-option.
#[derive(Clone, Copy, Debug)]
pub enum SubOption<'a> {
    /// 1 Agent Circuit ID
    AgentCircuitId(&'a [u8]),
    /// 2 Agent Remote ID
    AgentRemoteId(&'a [u8]),
    /// Unrecognized sub-option.
    Unknown(u8, &'a [u8]),
}

impl<'a> SubOption<'a> {
    pub fn code(&self) -> u8 {
        match self {
            SubOption::AgentCircuitId(_) => subopt::AGENT_CIRCUIT_ID,
            SubOption::AgentRemoteId(_) => subopt::AGENT_REMOTE_ID,
            SubOption::Unknown(code, _) => *code,
        }
    }
}

struct SubOptionIter<'a>(&'a [u8]);

impl<'a> Iterator for SubOptionIter<'a> {
    type Item = Result<SubOption<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match *self.0 {
            [] => None,
            [code, len, ref rest @ ..] if len as usize <= rest.len() => {
                let (value, next_slice) = rest.split_at(len.into());
                self.0 = next_slice;
                Some(Ok(match code {
                    subopt::AGENT_CIRCUIT_ID => SubOption::AgentCircuitId(value),
                    subopt::AGENT_REMOTE_ID => SubOption::AgentRemoteId(value),
                    _ => SubOption::Unknown(code, value),
                }))
            }
            _ => Some(Err(Error::Malformed)),
        }
    }
}

impl FusedIterator for SubOptionIter<'_> {}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RelayAgentInformation<'a>(pub(crate) &'a [u8]);

impl AsRef<[u8]> for RelayAgentInformation<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a> RelayAgentInformation<'a> {
    pub fn new(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 2 {
            return Err(Error::Underflow);
        }
        Ok(Self(b))
    }

    pub fn suboptions(&self) -> impl Iterator<Item = Result<SubOption<'a>, Error>> {
        SubOptionIter(self.0)
    }
}

#[cfg(feature = "std")]
pub fn encode<'a>(iter: impl IntoIterator<Item = SubOption<'a>>) -> Result<Vec<u8>, Error> {
    use std::convert::TryInto;

    let mut res = Vec::new();
    for subopt in iter {
        res.push(subopt.code());
        match subopt {
            SubOption::AgentCircuitId(b) | SubOption::AgentRemoteId(b) => {
                res.push(b.len().try_into().map_err(|_| Error::TooLong)?);
                res.extend_from_slice(b);
            }
            SubOption::Unknown(_code, b) => {
                res.push(b.len().try_into().map_err(|_| Error::TooLong)?);
                res.extend_from_slice(b);
            }
        }
    }
    Ok(res)
}
