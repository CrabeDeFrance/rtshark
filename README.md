# rtshark

[![Crate](https://img.shields.io/crates/v/rtshark.svg)](https://crates.io/crates/rtshark)
[![Crate](https://img.shields.io/crates/d/rtshark.svg)](https://crates.io/crates/rtshark)
[![Crate](https://img.shields.io/crates/l/rtshark.svg)](https://crates.io/crates/rtshark)
[![Documentation](https://docs.rs/rtshark/badge.svg)](https://docs.rs/rtshark/)
[![dependency status](https://deps.rs/repo/github/CrabeDeFrance/rtshark/status.svg)](https://deps.rs/repo/github/CrabeDeFrance/rtshark)

A Rust interface to TShark, the famous network protocol analyzer. [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) is a part of [Wireshark](https://www.wireshark.org/) distribution.
This crate provides an API to start TShark and analyze it's output.
It lets you capture packet data from a live network, or read packets from a previously saved capture file, printing a decoded form of those packets.
TShark's native capture file format is pcapng format, which is also the format used by Wireshark and various other tools.

TShark application must be installed for this crate to work properly.

This crates supports both offline processing (using pcap file) and live analysis (using an interface or a fifo).

## Example

```rust
// Creates a builder with needed tshark parameters
let builder = rtshark::RTSharkBuilder::builder()
    .input_path("/tmp/my.pcap");

// Start a new tshark process
let mut rtshark = builder.spawn()
    .unwrap_or_else(|e| panic!("Error starting tshark: {e}"));

// read packets until the end of the PCAP file
loop {
    let packet = match rtshark.read().unwrap() {
        rtshark::Output::Packet(p) => p,
        rtshark::Output::EOF => break
    };

    for layer in packet {
        println!("Layer: {}", layer.name());
        for metadata in layer {
            println!("\t{}", metadata.display());
        }
    }
}
```

## Development rules

### New parameters

There is actually no specific work to add more TShark parameters. If you miss an important parameter, you can create an issue.
But if you want something to be added quickly, please do a patch proposal with the missing parameter or feature.
Of course, any new proposal should include documentation to explain how to use it and an unit test to validate it.

### Version

This library follows the Semantic Versioning rules <https://semver.org/>, including :

* Only make breaking changes when you increment the major version. Don't break the build.
* Don't add any new public API (no new pub anything) in patch-level versions. Always increment the minor version if you add any new pub structs, traits, fields, types, functions, methods or anything else.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.