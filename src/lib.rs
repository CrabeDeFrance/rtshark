//! An interface to [TShark], the famous network protocol analyzer. [TShark] is a part of [Wireshark] distribution.
//! It lets you capture packet data from a live network, or read packets from a previously saved capture file, printing a decoded form of those packets.
//! TShark's native capture file format is pcapng format, which is also the format used by Wireshark and various other tools.
//!
//! [Wireshark]: <https://www.wireshark.org/>
//! [TShark]: <https://www.wireshark.org/docs/man-pages/tshark.html>
//!
//! Many information about TShark usage could also be found here <https://tshark.dev/>
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
//! // Start a new tshark process
//! let mut rtshark = match builder.run() {
//!     Err(err) =>  { eprintln!("Error running tshark: {err}"); return }
//!     Ok(rtshark) => rtshark,
//! };
//!
//! // read packets until the end of the PCAP file
//! loop {
//!     let packet = match rtshark.read().unwrap() {
//!         rtshark::Output::Packet(p) => p,
//!         rtshark::Output::EOF => break
//!     };
//!
//!     for layer in packet {
//!         println!("Layer: {}", layer.name());
//!         for metadata in layer {
//!             println!("\t{}", metadata.display());
//!         }
//!     }
//! }
//! ```

use quick_xml::events::{BytesStart, Event};
use std::io::{BufRead, BufReader, Result};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStdout, Command, Stdio};

/// A metadata belongs to one [Layer]. It describes one particular information about a [Packet] (example: IP source address).
#[derive(Clone)]
pub struct Metadata {
    /// Name displayed by tshark
    name: String,
    /// Value displayed by tshark, in a human readable format
    value: String,
    /// Both name and value, as displayed by thshark
    display: String,
    /// Size of this data extracted from packet header protocol, in bytes
    size: u32,
    /// Offset of this data in the packet, in bytes
    position: u32,
}

/// This is one metadata from a given layer of the packet returned by tshark application.
impl Metadata {
    /// Create a new metadata. This function is useless for most applications.
    pub fn new(name: String, value: String, display: String, size: u32, position: u32) -> Metadata {
        Metadata {
            name,
            value,
            display,
            size,
            position,
        }
    }

    /// Get the name of this metadata. The name is returned by tshark.
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// assert_eq!(ip_src.name(), "ip.src")
    /// ```
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Value for this metadata, displayed by tshark, in a human readable format
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// assert_eq!(ip_src.value(), "127.0.0.1")
    /// ```
    pub fn value(&self) -> &str {
        self.value.as_str()
    }

    /// Both name and value, as displayed by thshark
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// assert_eq!(ip_src.display(), "Source: 127.0.0.1")
    /// ```
    pub fn display(&self) -> &str {
        self.display.as_str()
    }

    /// Size of this data extracted from packet header protocol, in bytes
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// assert_eq!(ip_src.size(), 4)
    /// ```
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Offset of this data in the packet, in bytes
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// assert_eq!(ip_src.position(), 12)
    /// ```
    pub fn position(&self) -> u32 {
        self.position
    }
}

/// A layer is a protocol in the protocol stack of a packet (example: IP layer). It may contain multiple [Metadata].
#[derive(Clone)]
pub struct Layer {
    /// Name of this layer
    name: String,
    /// Number of this layer for this packet in the stack of layers
    index: usize,
    /// List of metadata associated to this layer
    metadata: Vec<Metadata>,
}

impl Layer {
    /// Create a new layer. This function is useless for most applications.
    /// # Examples
    ///
    /// ```
    /// let ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// ```
    pub fn new(name: String, index: usize) -> Self {
        Layer {
            name,
            index,
            metadata: vec![],
        }
    }
    /// Retrieve the layer name of this layer object. This name is a protocol name returned by tshark.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// assert_eq!(ip_layer.name(), "ip")
    /// ```
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Retrieve layer index (number of this layer in the stack of layers).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// assert_eq!(ip_layer.index(), 1)
    /// ```
    pub fn index(&self) -> usize {
        self.index
    }

    /// Add a metadata in the list of this layer. This function is useless for most applications.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// ip_layer.add(ip_src);
    /// ```
    pub fn add(&mut self, metadata: Metadata) {
        self.metadata.push(metadata);
    }

    /// Get a metadata by its name.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// ip_layer.add(ip_src);
    /// let ip_src = ip_layer.metadata("ip.src").unwrap();
    /// assert_eq!(ip_src.display(), "Source: 127.0.0.1")
    /// ```
    pub fn metadata(&self, name: &str) -> Option<&Metadata> {
        self.metadata.iter().find(|m| m.name().eq(name))
    }

    /// Get an iterator on the list of [Metadata] for this [Layer].
    /// This iterator does not take ownership of returned [Metadata].
    /// This is the opposite of the "into"-iterator which returns owned objects.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// ip_layer.add(ip_src);
    /// let metadata = ip_layer.iter().next().unwrap();
    /// assert_eq!(metadata.display(), "Source: 127.0.0.1")
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = &Metadata> {
        self.metadata.iter()
    }
}

impl IntoIterator for Layer {
    type Item = Metadata;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    /// Get an "into" iterator on the list of [Metadata] for this [Layer].
    /// This iterator takes ownership of returned [Metadata].
    /// This is the opposite of an iterator by reference.
    ///
    /// # Example 1
    ///
    /// ```
    /// let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// ip_layer.add(ip_src);
    /// for metadata in ip_layer {
    ///     assert_eq!(metadata.display(), "Source: 127.0.0.1")
    /// }
    /// ```
    /// # Example 2
    ///
    /// ```
    /// # let mut ip_layer = rtshark::Layer::new("ip".to_string(), 1);
    /// # let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), "Source: 127.0.0.1".to_string(), 4, 12);
    /// # ip_layer.add(ip_src);
    /// let metadata = ip_layer.into_iter().next().unwrap();
    /// assert_eq!(metadata.display(), "Source: 127.0.0.1")
    /// ```
    fn into_iter(self) -> Self::IntoIter {
        self.metadata.into_iter()
    }
}

/// The [Packet] object represents a network packet, a formatted unit of data carried by a packet-switched network. It may contain multiple [Layer].
pub struct Packet {
    /// Stack of layers for a packet
    layers: Vec<Layer>,
}

impl Packet {
    /// Creates a new empty layer. This function is useless for most applications.
    /// # Examples
    ///
    /// ```
    /// let packet = rtshark::Packet::new();
    /// ```
    pub fn new() -> Self {
        Packet { layers: vec![] }
    }

    /// Push a new layer at the end of the layer stack. This function is useless for most applications.
    /// # Examples
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("ip".to_string());
    /// ```
    pub fn push(&mut self, name: String) {
        let layer = Layer::new(name, self.layers.len());
        self.layers.push(layer);
    }

    /// Get the last layer as mutable reference. It is used to push incoming metadata in the current packet.
    fn last_layer_mut(&mut self) -> Option<&mut Layer> {
        self.layers.last_mut()
    }

    /// Get the layer for the required index. Indexes starts at 0.
    /// # Examples
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("eth".to_string());
    /// ip_packet.push("ip".to_string());
    /// ip_packet.push("tcp".to_string());
    /// assert_eq!(ip_packet.layer_index(0).unwrap().name(), "eth");
    /// assert_eq!(ip_packet.layer_index(1).unwrap().name(), "ip");
    /// assert_eq!(ip_packet.layer_index(2).unwrap().name(), "tcp");
    /// ```
    pub fn layer_index(&self, index: usize) -> Option<&Layer> {
        self.layers.get(index)
    }

    /// Get the layer with the searched name.
    /// If multiple layers have the same name, in case of IP tunnels for instance, the layer with the lowest index is returned.
    /// # Examples
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("eth".to_string());
    /// ip_packet.push("ip".to_string());
    /// ip_packet.push("ip".to_string());
    /// let ip_layer = ip_packet.layer_name("ip").unwrap();
    /// assert_eq!(ip_layer.index(), 1);
    /// ```
    pub fn layer_name(&self, name: &str) -> Option<&Layer> {
        self.layers.iter().find(|&layer| layer.name.eq(name))
    }

    /// Get the number of layers for this packet.
    /// # Examples
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("eth".to_string());
    /// ip_packet.push("ip".to_string());
    /// ip_packet.push("tcp".to_string());
    /// assert_eq!(ip_packet.layer_count(), 3);
    /// ```
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Get an iterator on the list of [Layer] for this [Packet].
    /// This iterator does not take ownership of returned data.
    /// This is the opposite of the "into"-iterator which returns owned objects.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("ip".to_string());
    /// let layer = ip_packet.iter().next().unwrap();
    /// assert_eq!(layer.name(), "ip")
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = &Layer> {
        self.layers.iter()
    }
}

impl IntoIterator for Packet {
    type Item = Layer;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    /// Get an "into" iterator on the list of [Layer] for this [Packet].
    /// This iterator takes ownership of returned [Layer].
    /// This is the opposite of an iterator by reference.
    ///
    /// # Example 1
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("ip".to_string());
    /// for layer in ip_packet {
    ///     assert_eq!(layer.name(), "ip")
    /// }
    /// ```
    /// # Example 2
    ///
    /// ```
    /// let mut ip_packet = rtshark::Packet::new();
    /// ip_packet.push("ip".to_string());
    /// let layer = ip_packet.into_iter().next().unwrap();
    /// assert_eq!(layer.name(), "ip")
    /// ```
    fn into_iter(self) -> Self::IntoIter {
        self.layers.into_iter()
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self::new()
    }
}

/// RTSharkBuilder is used to prepares arguments needed to start a tshark instance.
/// When the mandatory input_path is set, it creates a [RTSharkBuilderReady] object,
/// which can be used to add more optional parameters or run to create a [RTShark] instance.
pub struct RTSharkBuilder {}

impl<'a> RTSharkBuilder {
    /// Initial builder function which creates an empty object.
    pub fn builder() -> Self {
        RTSharkBuilder {}
    }

    /// This is the only mandatory parameter, used to provide source of packets.
    /// It enables either -r or -i option of TShark, depending on the use of .live_capture(), see below.
    ///
    /// # Without .live_capture()
    ///
    /// If .live_capture() is not set, TShark will read packet data from a file. It can be any supported capture file format (including gzipped files).
    ///
    /// It is possible to use named pipes or stdin (-) here but only with certain (not compressed) capture file formats
    /// (in particular: those that can be read without seeking backwards).
    ///
    /// ## Example: Prepare an instance of tshark to read a PCAP file
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap");
    /// ```
    ///
    /// # With .live_capture()
    ///
    /// If .live_capture() is set, a network interface or a named pipe can be used to read packets.
    ///
    /// Network interface names should match one of the names listed in "tshark -D" (described above);
    /// a number, as reported by "tshark -D", can also be used.
    ///
    /// If you’re using UNIX, "netstat -i", "ifconfig -a" or "ip link" might also work to list interface names,
    /// although not all versions of UNIX support the -a option to ifconfig.
    /// Pipe names should be the name of a FIFO (named pipe).
    ///
    /// On Windows systems, pipe names must be of the form "\\pipe\.*pipename*".
    ///
    /// "TCP@<host>:<port>" causes TShark to attempt to connect to the specified port on the specified host and read pcapng or pcap data.
    ///
    /// Data read from pipes must be in standard pcapng or pcap format. Pcapng data must have the same endianness as the capturing host.
    ///
    /// ## Example: Prepare an instance of tshark to read from a fifo
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.fifo")
    ///     .live_capture();
    /// ```
    /// ## Example: Prepare an instance of tshark to read from a network interface
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("eth0")
    ///     .live_capture();
    /// ```

    pub fn input_path(&mut self, path: &'a str) -> RTSharkBuilderReady<'a> {
        RTSharkBuilderReady::<'a> {
            input_path: path,
            live_capture: false,
            metadata_blacklist: &[],
            pcap_filter: "",
            env_path: "",
            output_path: "",
        }
    }
}

/// RTSharkBuilderReady is an object used to run to create a [RTShark] instance.
/// It is possible to use it to add more optional parameters before starting a tshark application.
#[derive(Clone)]
pub struct RTSharkBuilderReady<'a> {
    /// path to input source
    input_path: &'a str,
    /// activate live streaming (fifo, network interface). This activates -i option instread of -r.
    live_capture: bool,
    /// filter out (blacklist) useless metadata names, to prevent storing them in output packet structure
    metadata_blacklist: &'a [&'a str],
    /// pcap filter : string to be passed to libpcap to filter packets (let pass only packets matching this filter)
    pcap_filter: &'a str,
    /// custom environment path containing tshark application
    env_path: &'a str,
    /// path to input source
    output_path: &'a str,
}

impl<'a> RTSharkBuilderReady<'a> {
    /// Enable -i option of TShark.
    ///
    /// This option must be set to use network interface or pipe for live packet capture. See input_path() option of [RTSharkBuilder] for more details.
    ///
    pub fn live_capture(&self) -> Self {
        let mut new = self.clone();
        new.live_capture = true;
        new
    }

    /// Filter expression to be passed to libpcap to filter packets.
    ///
    /// Warning: these capture filters cannot be specified when reading a capture file.
    /// There are enabled only when using live_capture().
    ///
    /// Packet capturing filter is performed with the pcap library.
    /// That library supports specifying a filter expression; packets that don’t match that filter are discarded.
    /// The syntax of a capture filter is defined by the pcap library.
    /// This syntax is different from the tshark filter syntax.
    ///
    /// More information about libpcap filters here : <https://www.tcpdump.org/manpages/pcap-filter.7.html>
    ///
    /// ### Example: Prepare an instance of tshark with packet capture filter.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .live_capture()
    ///     .pcap_filter("port 53");
    /// ```
    pub fn pcap_filter(&self, filter: &'a str) -> Self {
        let mut new = self.clone();
        new.pcap_filter = filter;
        new
    }

    /// Filter out (blacklist) a list of useless metadata names extracted by tshark,
    /// to prevent storing them in [Output] packet structure and consume extra memory.
    /// Filtered [Metadata] will not be available in [Packet]'s [Layer].
    ///
    /// ### Example: Prepare an instance of tshark with IP source and destination metadata filtered.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .metadata_blacklist(&["ip.src", "ip.dst"]);
    /// ```
    pub fn metadata_blacklist(&self, blacklist: &'a [&'a str]) -> Self {
        let mut new = self.clone();
        new.metadata_blacklist = blacklist;
        new
    }

    /// Replace the PATH environment variable. This is used to specify where to look for tshark executable.
    ///
    /// Note that environment variable names are case-insensitive (but case-preserving) on Windows,
    /// and case-sensitive on all other platforms.
    ///
    /// ### Example: Prepare an instance of tshark when binary is installed in a custom path
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .env_path("/opt/local/tshark/");
    /// ```
    pub fn env_path(&self, path: &'a str) -> Self {
        let mut new = self.clone();
        new.env_path = path;
        new
    }

    /// Write raw packet data to outfile or to the standard output if outfile is '-'.
    /// Note : this option provides raw packet data, not text.
    ///
    /// ### Example: Prepare an instance of tshark to store raw packet data
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/in.pcap")
    ///     .output_path("/tmp/out.pcap");
    /// ```
    pub fn output_path(&self, path: &'a str) -> Self {
        let mut new = self.clone();
        new.output_path = path;
        new
    }

    /// Starts a new tshark process given the provided parameters, mapped to a new [RTShark] instance.
    /// This function may fail if tshark binary is not in PATH or if there are some issues with input_path parameter : not found, no read permission...
    /// # Example
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap");
    /// let tshark: std::io::Result<rtshark::RTShark> = builder.run();
    /// ```
    pub fn run(&self) -> Result<RTShark> {
        // test if input file exists
        if !self.live_capture {
            std::fs::metadata(&self.input_path).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => std::io::Error::new(
                    e.kind(),
                    format!("Unable to find {}: {}", &self.input_path, e),
                ),
                _ => e,
            })?;
        }

        // prepare tshark command line parameters
        let mut tshark_params = vec![
            if !self.live_capture { "-r" } else { "-i" },
            self.input_path,
            "-Tpdml",
            "-n",
        ];

        // it would be possible to ask tshark to "mix in" a keylog file
        // when opening the pcap file
        // (obtain the keylog file through `SSLKEYLOGFILE=browser_keylog.txt google-chrome` or firefox,
        // pass it to tshark through "-o ssh.keylog_file:/path/to/keylog")
        // but we get in flatpak limitations (can only access the file that the user opened
        // due to the sandbox) => better to just mix in the secrets manually and open a single
        // file. this is done through => editcap --inject-secrets tls,/path/to/keylog.txt ~/testtls.pcap ~/outtls.pcapng

        tshark_params.extend(&["-l"]);

        if !self.output_path.is_empty() {
            tshark_params.extend(&["-w", self.output_path]);
        }

        if self.live_capture && !self.pcap_filter.is_empty() {
            tshark_params.extend(&["-f", self.pcap_filter]);
        }

        /* TODO : implement filters
        {
            //tshark_params.extend(&[filters]);
        }
        */

        // piping from tshark, not to load the entire JSON in ram...
        // this may fail if tshark is not found in path

        let tshark_child = if self.env_path.is_empty() {
            Command::new("tshark")
                .args(&tshark_params)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
        } else {
            Command::new("tshark")
                .args(&tshark_params)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .env("PATH", self.env_path)
                .spawn()
        };

        let mut tshark_child = tshark_child.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                std::io::Error::new(e.kind(), format!("Unable to find tshark: {}", e))
            }
            _ => e,
        })?;

        let buf_reader = BufReader::new(tshark_child.stdout.take().unwrap());

        let reader = quick_xml::Reader::from_reader(buf_reader);

        let filters: Vec<String> = self
            .metadata_blacklist
            .iter()
            .map(|s| s.to_string())
            .collect();
        Ok(RTShark::new(tshark_child, reader, filters))
    }
}

/// This output type describes the result of tshark parsing. It could be a newly decoded packet or the end of the packet stream.
pub enum Output {
    /// Type returned when a packet was properly decoded
    Packet(Packet),
    /// No more packets can be decoded from this stream. This could happen when tshark application dies or when this is the end of the PCAP file.
    EOF,
}

/// RTShark structure represents a tshark process.
/// It allows controlling the tshark process and reading from its [Output].
/// It is created by [RTSharkBuilder].
pub struct RTShark {
    /// Contains the tshark process handle, when tshark is running
    process: Option<Child>,
    /// xml parser on tshark piped output
    parser: quick_xml::Reader<BufReader<ChildStdout>>,
    /// optional metadata blacklist, to prevent storing useless metadata in output packet structure
    filters: Vec<String>,
}

impl RTShark {
    /// create a new RTShark instance from a successful builder call.
    fn new(
        process: Child,
        parser: quick_xml::Reader<BufReader<ChildStdout>>,
        filters: Vec<String>,
    ) -> Self {
        RTShark {
            process: Some(process),
            parser,
            filters,
        }
    }

    /// Read a packet from thsark output and map it to the [Output] type.
    /// Reading packet can be done until [Output::EOF] is returned.
    /// Once EOF is returned, no more packets can be read from this stream.
    /// This could happen when tshark application dies or when this is the end of the PCAP file.
    /// # Example
    ///
    /// ```
    /// # // Creates a builder with needed tshark parameters
    /// # let builder = rtshark::RTSharkBuilder::builder()
    /// #     .input_path("/tmp/my.pcap");
    /// // Start a new tshark process
    /// let mut rtshark = match builder.run() {
    ///     Err(err) => { eprintln!("Error running tshark: {err}"); return; }
    ///     Ok(rtshark) => rtshark
    /// };
    ///
    /// // read packets until the end of the PCAP file
    /// loop {
    ///     let packet = match rtshark.read() {
    ///         Ok(packet) => packet,
    ///         Err(e) => { eprintln!("Got decoding error: {e}"); continue; }
    ///     };
    ///
    ///     match packet {
    ///         rtshark::Output::Packet(_packet) => println!("Got a packet"),
    ///         rtshark::Output::EOF => break,
    ///     }
    /// }
    /// ```
    pub fn read(&mut self) -> Result<Output> {
        let xml_reader = &mut self.parser;

        let msg = parse_xml(xml_reader, &self.filters);
        if let Ok(ref msg) = msg {
            let done = match msg {
                Output::EOF => match self.process {
                    Some(ref mut process) => RTShark::try_wait_has_exited(process),
                    _ => true,
                },
                _ => false,
            };

            if done {
                self.process = None;
            }
        }

        msg
    }

    /// Kill the running tshark process associated to this rtshark instance.
    /// Once tshark is killed, there is no way to start it again using this object.
    /// Any new tshark instance has to be created using RTSharkBuilder.
    /// # Example
    ///
    /// ```
    /// // Creates a builder with needed tshark parameters
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap");
    ///
    /// // Start a new tshark process
    /// let mut rtshark = match builder.run() {
    ///     Err(err) => { eprintln!("Error running tshark: {err}"); return; }
    ///     Ok(rtshark) => rtshark
    /// };
    ///
    /// // kill running tshark process
    /// rtshark.kill();
    /// ```

    pub fn kill(&mut self) {
        if let Some(ref mut process) = self.process {
            let done = match process.try_wait() {
                Ok(maybe) => match maybe {
                    None => false,
                    Some(_exitcode) => true,
                },
                Err(e) => {
                    eprintln!("Error while killing rtshark: wait: {e}");
                    false
                }
            };

            if !done {
                match process.kill() {
                    Ok(()) => (),
                    Err(e) => eprintln!("Error while killing rtshark: kill: {e}"),
                }
                if let Err(e) = process.wait() {
                    eprintln!("Error while killing rtshark: wait: {e}");
                }
            }

            self.process = None;
        }
    }

    /// Returns tshark process id if tshark is running.
    /// # Example
    ///
    /// ```
    /// // Creates a builder with needed tshark parameters
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap");
    ///
    /// // Start a new tshark process
    /// let mut rtshark = match builder.run() {
    ///     Err(err) => { eprintln!("Error running tshark: {err}"); return; }
    ///     Ok(rtshark) => println!("tshark PID is {}", rtshark.pid().unwrap())
    /// };
    ///
    /// ```
    pub fn pid(&self) -> Option<u32> {
        self.process.as_ref().map(|p| p.id())
    }

    /// Check if process is stopped, get the exit code and return true if stopped.
    fn try_wait_has_exited(child: &mut Child) -> bool {
        matches!(child.try_wait(), Ok(Some(s)) if s.code().is_some() || s.signal().is_some())
    }
}

impl Drop for RTShark {
    fn drop(&mut self) {
        self.kill()
    }
}

/// search for an attribute of a XML tag using its name and return a string.
fn rtshark_attr_by_name<'a>(tag: &'a BytesStart, key: &[u8]) -> Result<String> {
    let attrs = &mut tag.attributes();
    for attr in attrs {
        let attr = attr.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error decoding xml attribute: {e:?}"),
            )
        })?;
        if attr.key == key {
            let value = std::str::from_utf8(&attr.value).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Error decoding utf8 value: {e:?}"),
                )
            })?;
            return Ok(value.to_owned());
        }
    }

    let line =
        std::str::from_utf8(tag.attributes_raw()).unwrap_or("Unable to decode UTF8 XML buffer");

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "xml lookup error: no key '{}' in '{}'",
            std::str::from_utf8(key).unwrap(),
            line
        ),
    ))
}

/// search for an attribute of a XML tag using its name and return a u32.
fn rtshark_attr_by_name_u32<'a>(tag: &'a BytesStart, key: &[u8]) -> Result<u32> {
    match rtshark_attr_by_name(tag, key) {
        Err(e) => Err(e),
        Ok(v) => v.parse::<u32>().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error decoding u32 value: {e:?}"),
            )
        }),
    }
}

/// Build a metadata using attributes available on this XML "field" tag.
/// Sample XML line : <field name="frame.time" show="test time" pos="0" size="0" showname="test time display"/>
fn rtshark_build_metadata(tag: &BytesStart, filters: &[String]) -> Result<Option<Metadata>> {
    let name = rtshark_attr_by_name(tag, b"name")?;

    // skip "_ws.expert" info, not related to a packet metadata
    if name.starts_with("_ws.") {
        return Ok(None);
    }

    // skip data
    if filters.contains(&name) {
        return Ok(None);
    }

    let value = rtshark_attr_by_name(tag, b"show")?;

    let mut metadata = Metadata {
        name,
        value,
        display: String::new(),
        size: 0,
        position: 0,
    };

    if let Ok(position) = rtshark_attr_by_name_u32(tag, b"pos") {
        metadata.position = position;
    }
    if let Ok(size) = rtshark_attr_by_name_u32(tag, b"size") {
        metadata.size = size;
    }
    if let Ok(display) = rtshark_attr_by_name(tag, b"showname") {
        metadata.display = display;
    }
    Ok(Some(metadata))
}

/// Main parser function used to decode XML output from tshark
fn parse_xml<B: BufRead>(
    xml_reader: &mut quick_xml::Reader<B>,
    filters: &[String],
) -> Result<Output> {
    let mut buf = vec![];
    let mut packet = Packet::new();
    let mut store_metadata = false;

    loop {
        match xml_reader.read_event(&mut buf) {
            Ok(Event::Start(ref e)) => match e.name() {
                b"packet" => (),
                b"proto" => {
                    let proto = rtshark_attr_by_name(e, b"name")?;

                    if ["fake-field-wrapper", "geninfo"].contains(&proto.as_str()) {
                        store_metadata = false;
                        continue;
                    } else {
                        store_metadata = true;
                    }

                    packet.push(proto);
                }
                b"field" => {
                    if !store_metadata {
                        continue;
                    }

                    let metadata = rtshark_build_metadata(e, filters)?;
                    if let Some(metadata) = metadata {
                        packet.last_layer_mut().unwrap().add(metadata);
                    }
                }
                _ => (),
            },
            Ok(Event::Empty(ref e)) => match e.name() {
                b"packet" => (),
                b"proto" => (),
                b"field" => {
                    if !store_metadata {
                        continue;
                    }

                    let metadata = rtshark_build_metadata(e, filters)?;
                    if let Some(metadata) = metadata {
                        packet.last_layer_mut().unwrap().add(metadata);
                    }
                }
                _ => (),
            },
            Ok(Event::End(ref e)) => match e.name() {
                b"packet" => return Ok(Output::Packet(packet)),
                b"proto" => (),
                b"field" => (),
                _ => (),
            },

            Ok(Event::Eof) => {
                return Ok(Output::EOF);
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "xml parsing error: {} at tshark output offset {}",
                        e,
                        xml_reader.buffer_position()
                    ),
                ));
            }
            Ok(_) => (),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::io::Write;

    use super::*;

    #[test]
    fn test_parse_single_proto_metadata() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
           <field name="frame.time" show="test time" pos="0" size="0" showname="test time display"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 1);
        for layer in pkt.layers {
            for m in layer {
                assert!(m.name().eq("frame.time"));
                assert!(m.value().eq("test time"));
                assert!(m.display().eq("test time display"));
            }
        }
    }

    #[test]
    fn test_parse_missing_optional_size() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
          <field name="frame.time" show="test time" pos="0" showname="test time display"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 1);
    }

    #[test]
    fn test_parse_missing_optional_pos() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
          <field name="frame.time" show="test time" size="0" showname="test time display"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 1);
    }

    #[test]
    fn test_parse_missing_optional_display() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
          <field name="frame.time" show="test time" pos="0" size="0" />
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 1);
    }

    #[test]
    fn test_parse_missing_mandatory_name() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
          <field show="test time" pos="0" size="0" showname="test time display"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]);

        match msg {
            Err(_) => (),
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn test_parse_missing_mandatory_show() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
          <field name="frame.time" pos="0" size="0" showname="test time display"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]);
        match msg {
            Err(_) => (),
            _ => panic!("invalid result"),
        }
    }

    const XML_TCP: &'static str = r#"
    <pdml>
     <packet>
      <proto name="frame">
       <field name="frame.time" show="Mar  5, 2021 08:49:52.736275000 CET"/>
      </proto>
      <proto name="ip">
       <field name="ip.src" show="1.1.1.1" />
       <field name="ip.dst" show="1.1.1.2" />
      </proto>
      <proto name="tcp">
       <field name="tcp.srcport" show="52796" value="ce3c"/>
       <field name="tcp.dstport" show="5432" value="1538"/>
       <field name="tcp.seq_raw" show="1963007432" value="75011dc8"/>
       <field name="tcp.stream" show="4"/>
      </proto>
     </packet>
    </pdml>"#;

    #[test]
    fn test_access_packet_into_iter() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 3);

        let mut iter = pkt.into_iter();
        let frame = iter.next().unwrap();
        assert!(frame.name().eq("frame"));
        let ip = iter.next().unwrap();
        assert!(ip.name().eq("ip"));
        let tcp = iter.next().unwrap();
        assert!(tcp.name().eq("tcp"));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_access_packet_iter() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 3);

        let mut iter = pkt.iter();
        let frame = iter.next().unwrap();
        assert!(frame.name().eq("frame"));
        let ip = iter.next().unwrap();
        assert!(ip.name().eq("ip"));
        let tcp = iter.next().unwrap();
        assert!(tcp.name().eq("tcp"));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_access_layer_index() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 3);

        assert!(pkt.layer_index(0).unwrap().name().eq("frame"));
        assert!(pkt.layer_index(1).unwrap().name().eq("ip"));
        assert!(pkt.layer_index(2).unwrap().name().eq("tcp"));

        assert!(pkt.layer_index(3).is_none());
    }

    #[test]
    fn test_access_layer_name() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 3);

        assert!(pkt.layer_name("frame").unwrap().name().eq("frame"));
        assert!(pkt.layer_name("ip").unwrap().name().eq("ip"));
        assert!(pkt.layer_name("tcp").unwrap().name().eq("tcp"));

        assert!(pkt.layer_name("udp").is_none());
    }

    #[test]
    fn test_access_layer_name_with_tunnel() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
           <field name="frame.time" show="Mar  5, 2021 08:49:52.736275000 CET"/>
          </proto>
          <proto name="ip">
           <field name="ip.src" show="10.215.215.9" />
           <field name="ip.dst" show="10.215.215.10" />
          </proto>
          <proto name="ip">
           <field name="ip.src" show="10.10.215.9" />
           <field name="ip.dst" show="10.10.215.10" />
          </proto>
          <proto name="tcp">
           <field name="tcp.srcport" show="52796" value="ce3c"/>
           <field name="tcp.dstport" show="5432" value="1538"/>
           <field name="tcp.seq_raw" show="1963007432" value="75011dc8"/>
           <field name="tcp.stream" show="4"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers.len(), 4);

        assert!(pkt.layer_name("frame").unwrap().name().eq("frame"));
        assert!(pkt.layer_name("ip").unwrap().name().eq("ip"));
        assert!(pkt.layer_name("ip").unwrap().index() == 1usize);
        assert!(pkt.layer_index(1).unwrap().name().eq("ip"));
        assert!(pkt.layer_index(2).unwrap().name().eq("ip"));
        assert!(pkt.layer_name("tcp").unwrap().name().eq("tcp"));

        assert!(pkt.layer_name("udp").is_none());
    }

    #[test]
    fn test_access_layer_iter() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        let mut iter = ip.iter();
        assert!(iter.next().unwrap().name().eq("ip.src"));
        assert!(iter.next().unwrap().name().eq("ip.dst"));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_access_layer_into_iter() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap().clone();
        let mut iter = ip.into_iter();
        assert!(iter.next().unwrap().name().eq("ip.src"));
        assert!(iter.next().unwrap().name().eq("ip.dst"));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_access_layer_metadata() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &vec![]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        let src = ip.metadata("ip.src").unwrap();
        assert!(src.value().eq("1.1.1.1"));

        let dst = ip.metadata("ip.dst").unwrap();
        assert!(dst.value().eq("1.1.1.2"));
    }

    #[test]
    fn test_parser_filter_metadata() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &vec!["ip.src".to_string()]).unwrap();
        let pkt = match msg {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        assert!(ip.metadata("ip.src").is_none());
        assert!(ip.metadata("ip.dst").unwrap().value().eq("1.1.1.2"));
    }

    #[test]
    fn test_parser_multiple_packets() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="tcp"></proto>
         </packet>
         <packet>
          <proto name="udp"></proto>
         </packet>
         <packet>
          <proto name="igmp"></proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));
        match parse_xml(&mut reader, &vec![]).unwrap() {
            Output::Packet(p) => assert!(p.layer_name("tcp").is_some()),
            _ => panic!("invalid Output type"),
        }
        match parse_xml(&mut reader, &vec![]).unwrap() {
            Output::Packet(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }
        match parse_xml(&mut reader, &vec![]).unwrap() {
            Output::Packet(p) => assert!(p.layer_name("igmp").is_some()),
            _ => panic!("invalid Output type"),
        }
        match parse_xml(&mut reader, &vec![]).unwrap() {
            Output::EOF => (),
            _ => panic!("invalid Output type"),
        }
    }

    #[test]
    fn test_rtshark_input_pcap() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // run tshark on it
        let builder = RTSharkBuilder::builder().input_path(pcap_path.to_str().unwrap());

        let mut rtshark = builder.run().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Output::Packet(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        loop {
            match rtshark.read().unwrap() {
                Output::EOF => break,
                _ => (),
            }
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_blacklist() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // run tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .metadata_blacklist(&["ip.src"]);
        let mut rtshark = builder.run().unwrap();

        // read a packet
        let pkt = match rtshark.read().unwrap() {
            Output::Packet(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        assert!(ip.metadata("ip.src").is_none());
        assert!(ip.metadata("ip.dst").unwrap().value().eq("127.0.0.1"));

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_fifo() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture();
        let mut rtshark = builder.run().unwrap();

        // send packets in the fifo
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .expect("unable to open fifo");
        output.write_all(pcap).expect("unable to write in fifo");

        // get analysis
        match rtshark.read().unwrap() {
            Output::Packet(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        // stop tshark
        rtshark.kill();

        // verify tshark is stopped
        assert!(rtshark.pid().is_none());

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_filter_pcap() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // first, check with the right filter, we get the packet
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture()
            .pcap_filter("port 53");

        let mut rtshark = builder.run().unwrap();

        // send packets in the fifo
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .expect("unable to open fifo");
        output.write_all(pcap).expect("unable to write in fifo");

        // read a packet
        match rtshark.read().unwrap() {
            Output::Packet(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        // then, check with the bad filter, we don't get the packet
        // TODO (need a pcap with 2 packets, first will be filtered out)

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_drop() {
        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture();

        let pid = {
            let rtshark = builder.run().unwrap();
            let pid = rtshark.pid().unwrap();

            assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
            pid
        };

        // verify tshark is stopped
        assert!(std::path::Path::new(&format!("/proc/{pid}")).exists() == false);

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_killed() {
        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture();

        let mut rtshark = builder.run().unwrap();

        // killing badly
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(rtshark.pid().unwrap() as libc::pid_t),
            nix::sys::signal::Signal::SIGKILL,
        )
        .unwrap();

        // reading from process output should give EOF
        match rtshark.read().unwrap() {
            Output::EOF => (),
            _ => panic!("invalid Output type"),
        }

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_fifo_lost() {
        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture();

        let mut rtshark = builder.run().unwrap();

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");

        // reading from process output should give EOF
        match rtshark.read().unwrap() {
            Output::EOF => (),
            _ => panic!("invalid Output type"),
        }
    }

    #[test]
    fn test_rtshark_fifo_opened_then_closed() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .live_capture();

        let mut rtshark = builder.run().unwrap();

        // send packets in the fifo then close it immediately
        {
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .open(&fifo_path)
                .expect("unable to open fifo");
            output.write_all(pcap).expect("unable to write in fifo");
        }

        // get analysis
        match rtshark.read().unwrap() {
            Output::Packet(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        match rtshark.read().unwrap() {
            Output::EOF => (),
            _ => panic!("invalid Output type"),
        }

        // stop tshark
        rtshark.kill();

        // reading from process output should give EOF
        match rtshark.read().unwrap() {
            Output::EOF => (),
            _ => panic!("invalid Output type"),
        }

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_file_missing() {
        // start tshark on a missing fifo
        let builder = RTSharkBuilder::builder().input_path("/missing/rtshark/fifo");

        let ret = builder.run();

        match ret {
            Ok(_) => panic!("We can't start if file is missing"),
            Err(e) => println!("{e}"),
        }
    }

    #[test]
    fn test_rtshark_tshark_missing() {
        // start tshark on a missing fifo
        let builder = RTSharkBuilder::builder()
            .input_path("/missing/rtshark/fifo")
            .live_capture()
            .env_path("/invalid/path");

        let ret = builder.run();

        match ret {
            Ok(_) => panic!("We can't start if tshark is missing"),
            Err(e) => println!("{e}"),
        }
    }

    #[test]
    fn test_rtshark_input_pcap_output_pcap() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let in_path = tmp_dir.path().join("in.pcap");
        let mut output = std::fs::File::create(&in_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        let out_path = tmp_dir.path().join("out.pcap");

        // run tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(in_path.to_str().unwrap())
            .output_path(out_path.to_str().unwrap());

        let mut rtshark = builder.run().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Output::Packet(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        loop {
            match rtshark.read().unwrap() {
                Output::EOF => break,
                _ => (),
            }
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        // now check what was written
        let mut rtshark = RTSharkBuilder::builder()
            .input_path(out_path.to_str().unwrap())
            .run()
            .unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Output::Packet(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_fifo_output_pcap() {
        let pcap = include_bytes!("test.pcap");

        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path = tmp_dir.path().join("pcap.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        let out_path = tmp_dir.path().join("out.pcap");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path.to_str().unwrap())
            .output_path(out_path.to_str().unwrap())
            .live_capture();
        let mut rtshark = builder.run().unwrap();

        // send packets in the fifo
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .expect("unable to open fifo");
        output.write_all(pcap).expect("unable to write in fifo");

        // get analysis
        match rtshark.read().unwrap() {
            Output::Packet(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        // stop tshark
        rtshark.kill();

        // verify tshark is stopped
        assert!(rtshark.pid().is_none());

        // now check what was written
        let mut rtshark = RTSharkBuilder::builder()
            .input_path(out_path.to_str().unwrap())
            .run()
            .unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Output::Packet(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }
}
