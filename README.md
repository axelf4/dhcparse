# dhcparse

A zero-copy DHCPv4 parser.

[![crates.io](https://img.shields.io/crates/v/dhcparse.svg)](https://crates.io/crates/dhcparse)
[![docs.rs](https://img.shields.io/docsrs/dhcparse)](https://docs.rs/dhcparse)

This crate is suitable for writing DHCP relay agents, which only need
to read and write a few fields, set and possibly remove a couple of
options, before forwarding an incoming DHCP message.

## Examples

Basic usage:

```rust
use dhcparse::{get_options, Dhcpv4View, MessageType};
use std::net::Ipv4Addr;

let mut msg = Dhcpv4View::new(EXAMPLE_DISCOVER_MSG)?;

// Read a field
assert_eq!(msg.chaddr()?, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

// Set a field
*msg.giaddr_mut() = Ipv4Addr::new(192, 168, 1, 50).into();

// Parse a set of options
assert_eq!(
    get_options!(msg; MessageType required, ServerIdentifier, RequestedIpAddress)?,
    (
        MessageType::Discover,
        None,
        Some(&Ipv4Addr::new(192, 168, 1, 100).into())
    )
);
```