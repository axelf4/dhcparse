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
#[non_exhaustive]
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

struct SubOptions<'a>(&'a [u8]);

impl<'a> Iterator for SubOptions<'a> {
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

impl FusedIterator for SubOptions<'_> {}

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
        SubOptions(self.0)
    }
}

/// Writes the Relay Agent Information data into the given writer.
#[cfg(feature = "std")]
pub fn encode<'a>(
    mut writer: impl std::io::Write,
    iter: impl IntoIterator<Item = SubOption<'a>>,
) -> std::io::Result<()> {
    use std::{convert::TryInto, io};

    for subopt in iter {
        writer.write_all(&[subopt.code()])?;
        match subopt {
            SubOption::AgentCircuitId(b)
            | SubOption::AgentRemoteId(b)
            | SubOption::Unknown(_, b) => {
                writer
                    .write_all(&[b.len().try_into().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, Error::TooLong)
                    })?])?;
                writer.write_all(b)?;
            }
        }
    }
    Ok(())
}
