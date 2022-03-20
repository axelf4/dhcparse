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
```

Constructing a new message:

```rust
use dhcparse::dhcpv4::{DhcpOption, Encode as _, Encoder, Message, MessageType, OpCode};
// Create a copy of an empty message with the message type option added
let mut msg = Encoder
    .append_option(DhcpOption::MessageType(MessageType::DISCOVER))
    .encode_to_owned(&Message::default())?;
msg.set_op(OpCode::BootRequest);

assert_eq!(msg.options()?.count(), 1);
```

## Related projects

* [dhcproto] is another Rust crate that parses DHCP messages into a
  high-level representation. This may be more convenient for some
  applications, but comes with the overhead of copying and heap
  allocations. For instance, the current set of dhcproto benchmarks
  would be no-ops with dhcparse.

[dhcproto]: https://github.com/bluecatengineering/dhcproto
