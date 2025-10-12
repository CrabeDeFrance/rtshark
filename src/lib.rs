//! An interface to [TShark], the famous network protocol analyzer. [TShark] is a part of [Wireshark] distribution.
//! This crate provides an API to start TShark and analyze it's output.
//! It lets you capture packet data from a live network, or read packets from a previously saved capture file, printing a decoded form of those packets.
//! TShark's native capture file format is pcapng format, which is also the format used by Wireshark and various other tools.
//!
//! [Wireshark]: <https://www.wireshark.org/>
//! [TShark]: <https://www.wireshark.org/docs/man-pages/tshark.html>
//!
//! Many information about TShark usage could also be found [here](https://tshark.dev/).
//!
//! TShark application must be installed for this crate to work properly.
//!
//! This crates supports both offline processing (using pcap file) and live analysis (using an interface or a fifo).
//!
//! # Examples
//!
//! ```
//! // Creates a builder with needed tshark parameters
//! let builder = rtshark::RTSharkBuilder::builder()
//!     .input_path("/tmp/my.pcap");
//!
//! // Start a new TShark process
//! let mut rtshark = match builder.spawn() {
//!     Err(err) =>  { eprintln!("Error running tshark: {err}"); return }
//!     Ok(rtshark) => rtshark,
//! };
//!
//! // read packets until the end of the PCAP file
//! while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
//!     eprintln!("Error parsing TShark output: {e}");
//!     None
//! }) {
//!     for layer in packet {
//!         println!("Layer: {}", layer.name());
//!         for metadata in layer {
//!             println!("\t{}", metadata.value());
//!         }
//!     }
//! }
//! ```

mod builder;
mod layer;
mod metadata;
mod packet;
mod rtshark;
mod xml;

pub use builder::{RTSharkBuilder, RTSharkBuilderReady, RTSharkVersion};
pub use layer::Layer;
pub use metadata::Metadata;
pub use packet::Packet;
pub use rtshark::RTShark;
#[cfg(feature = "async")]
mod rtshark_async;
#[cfg(feature = "async")]
pub use rtshark_async::RTSharkAsync;
