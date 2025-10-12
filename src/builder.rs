use semver::Version;
use std::io::{BufRead, BufReader, Result};
use std::process::{Child, Command, Stdio};

use crate::rtshark::RTShark;

/// RTSharkBuilder is used to prepare arguments needed to start a TShark instance.
/// When the mandatory input_path is set, it creates a [RTSharkBuilderReady] object,
/// which can be used to add more optional parameters before spawning a [RTShark] instance.
/// RTSharkBuilder may be used to retrieve version information for the TShark executable.
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
    /// ## Example: Prepare an instance of TShark to read a PCAP file
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
    /// If you're using UNIX, "netstat -i", "ifconfig -a" or "ip link" might also work to list interface names,
    /// although not all versions of UNIX support the -a option to ifconfig.
    /// Pipe names should be the name of a FIFO (named pipe).
    ///
    /// On Windows systems, pipe names must be of the form "\\pipe\.*pipename*".
    ///
    /// "TCP@\<host\>:\<port\>" causes TShark to attempt to connect to the specified port on the specified host and read pcapng or pcap data.
    ///
    /// Data read from pipes must be in standard pcapng or pcap format. Pcapng data must have the same endianness as the capturing host.
    ///
    /// ## Example: Prepare an instance of TShark to read from a fifo
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.fifo")
    ///     .live_capture();
    /// ```
    /// ## Example: Prepare an instance of TShark to read from a network interface
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("eth0")
    ///     .live_capture();
    /// ```
    pub fn input_path(&mut self, path: &'a str) -> RTSharkBuilderReady<'a> {
        RTSharkBuilderReady::<'a> {
            input_path: vec![path],
            live_capture: false,
            metadata_blacklist: vec![],
            metadata_whitelist: None,
            capture_filter: "",
            display_filter: "",
            env_path: "",
            options: vec![],
            disabled_protocols: vec![],
            enabled_protocols: vec![],
            output_path: "",
            decode_as: vec![],
        }
    }

    /// Retrieve version information for the TShark executable.
    ///
    /// ## Example:
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder();
    /// if let Ok(version) = builder.version() {
    ///     println!("Version: {}", version.message());
    /// }
    /// ```
    pub fn version(&self) -> Result<RTSharkVersion> {
        let output = Command::new("tshark").args(["--version"]).output()?;
        let message = std::str::from_utf8(&output.stdout)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Version message not utf8: {e}"),
                )
            })?
            .to_owned();
        let version = message
            .split_whitespace()
            .find_map(|s| Version::parse(s).ok())
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unable to parse version from command output",
            ))?;
        Ok(RTSharkVersion { version, message })
    }
}

/// Version information for the TShark executable
pub struct RTSharkVersion {
    version: Version,
    message: String,
}

impl RTSharkVersion {
    /// The version of the TShark executable.
    ///
    /// This value may be logged or used to check for support for features
    /// not available from all versions of TShark.
    ///
    /// ## Example:
    /// ```
    /// use semver::Version;
    ///
    /// let min_version = Version::new(4, 0, 0);
    /// let builder = rtshark::RTSharkBuilder::builder();
    /// if let Ok(version) = builder.version() {
    ///     if version.version() < &min_version {
    ///         println!("Version requirements not met!");
    ///     }
    /// }
    /// ```
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The full versioning message printed by the TShark executable.
    ///
    /// The full message may include additional information about
    /// copyrights, the environment where the binary was compiled, and
    /// the environment where the binary is currently running.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// RTSharkBuilderReady is an object used to run to create a [RTShark] instance.
/// It is possible to use it to add more optional parameters before starting a TShark application.
#[derive(Clone)]
pub struct RTSharkBuilderReady<'a> {
    /// path to input source
    input_path: Vec<&'a str>,
    /// activate live streaming (fifo, network interface). This activates -i option instead of -r.
    live_capture: bool,
    /// filter out (blacklist) useless metadata names, to prevent storing them in output packet structure
    metadata_blacklist: Vec<String>,
    /// filter out (whitelist) useless metadata names, to prevent TShark to put them in PDML report
    metadata_whitelist: Option<Vec<String>>,
    /// capture_filter : string to be passed to libpcap to filter packets (let pass only packets matching this filter)
    capture_filter: &'a str,
    /// display filter : expression filter to match before TShark prints a packet
    display_filter: &'a str,
    /// custom environment path containing TShark application
    env_path: &'a str,
    /// any special options to configure protocol decoding
    options: Vec<String>,
    /// any protocols that should be explicitly disabled
    disabled_protocols: Vec<String>,
    /// any protocols that should be explicitly enabled
    enabled_protocols: Vec<String>,
    /// path to input source
    output_path: &'a str,
    /// decode_as : let TShark to decode as this expression
    decode_as: Vec<&'a str>,
}

impl<'a> RTSharkBuilderReady<'a> {
    /// Adds another input for tshark. It works only with live capture to read packets from
    /// multiple interfaces.
    /// Adding multiple pcap files will fail, since tshark will only read the last instance of "-r"
    /// option.
    ///
    /// ## Example: Prepare an instance of TShark to read from multiple network interfaces
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("eth0")
    ///     .input_path("eth1")
    ///     .live_capture();
    /// ```
    #[must_use]
    pub fn input_path(&self, path: &'a str) -> Self {
        let mut new = self.clone();
        new.input_path.push(path);
        new
    }

    /// Enables -i option of TShark.
    ///
    /// This option must be set to use network interface or pipe for live packet capture. See input_path() option of [RTSharkBuilder] for more details.
    ///
    #[must_use]
    pub fn live_capture(&self) -> Self {
        let mut new = self.clone();
        new.live_capture = true;
        new
    }

    /// Filter expression to be passed to libpcap to filter captured packets.
    ///
    /// Warning: these capture filters cannot be specified when reading a capture file.
    /// There are enabled only when using live_capture(). This filter will be ignored if live_capture() is not set.
    ///
    /// Packet capturing filter is performed with the pcap library.
    /// That library supports specifying a filter expression; packets that don't match that filter are discarded.
    /// The syntax of a capture filter is defined by the pcap library.
    /// This syntax is different from the TShark filter syntax.
    ///
    /// More information about libpcap filters here : <https://www.tcpdump.org/manpages/pcap-filter.7.html>
    ///
    /// ### Example: Prepare an instance of TShark with packet capture filter.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("eth0")
    ///     .live_capture()
    ///     .capture_filter("port 53");
    /// ```
    #[must_use]
    pub fn capture_filter(&self, filter: &'a str) -> Self {
        let mut new = self.clone();
        new.capture_filter = filter;
        new
    }

    /// Expression applied on analyzed packet metadata to print and write only matching packets.
    ///
    /// Cause the specified filter (which uses the syntax of read/display filters, rather than that of capture filters)
    /// to be applied before printing a decoded form of packets or writing packets to a file.
    /// Packets matching the filter are printed or written to file; packets that the matching packets depend upon (e.g., fragments),
    /// are not printed but are written to file; packets not matching the filter nor depended upon are discarded rather than being printed or written.
    ///
    /// ### Example: Prepare an instance of TShark with display filter.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .display_filter("udp.port == 53");
    /// ```
    #[must_use]
    pub fn display_filter(&self, filter: &'a str) -> Self {
        let mut new = self.clone();
        new.display_filter = filter;
        new
    }

    /// Filter out (blacklist) a list of useless metadata names extracted by TShark,
    /// to prevent storing them in [Packet] structure and consume extra memory.
    /// Filtered [Metadata] will not be available in [Packet]'s [Layer].
    ///
    /// This method can be called multiple times to add more metadata in the blacklist.
    ///
    /// ### Example: Prepare an instance of TShark with IP source and destination metadata filtered.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .metadata_blacklist("ip.src")
    ///     .metadata_blacklist("ip.dst");
    /// ```
    #[must_use]
    pub fn metadata_blacklist(&self, blacklist: &'a str) -> Self {
        let mut new = self.clone();
        new.metadata_blacklist.push(blacklist.to_owned());
        new
    }

    /// Filter out (whitelist) a list of needed metadata names to be extracted by TShark,
    /// to prevent it to extract and put everything in the PDML report.
    /// There is a huge performance gain for TShark if the whitelist is small.
    /// Filtered [Metadata] will not be available in [Packet]'s [Layer].
    ///
    /// This method can be called multiple times to add more metadata in the whitelist.
    ///
    /// In whitelist mode, TShark PDML does not encapsulate fields in a 'proto' tag anymore
    /// so it is not possible to build all packet's layers.
    ///
    /// ### Example: Prepare an instance of TShark to print only IP source and destination metadata.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .metadata_whitelist("ip.src")
    ///     .metadata_whitelist("ip.dst");
    /// ```
    #[must_use]
    pub fn metadata_whitelist(&self, whitelist: &'a str) -> Self {
        let mut new = self.clone();
        if let Some(wl) = &mut new.metadata_whitelist {
            wl.push(whitelist.to_owned());
        } else {
            new.metadata_whitelist = Some(vec![whitelist.to_owned()]);
        }
        new
    }

    /// Replace the PATH environment variable. This is used to specify where to look for tshark executable.
    ///
    /// Note that environment variable names are case-insensitive (but case-preserving) on Windows,
    /// and case-sensitive on all other platforms.
    ///
    /// ### Example: Prepare an instance of TShark when binary is installed in a custom path
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .env_path("/opt/local/tshark/");
    /// ```
    #[must_use]
    pub fn env_path(&self, path: &'a str) -> Self {
        let mut new = self.clone();
        new.env_path = path;
        new
    }

    /// Specify the key log file that enables decryption of TLS traffic.
    ///
    /// The key log file is generated by the browser when `SSLKEYLOGFILE` environment variable
    /// is set. See <https://wiki.wireshark.org/TLS#using-the-pre-master-secret> for more
    /// details.
    ///
    /// Note that you can embed the TLS key log file in a capture file:
    ///
    /// ```no_compile
    /// editcap --inject-secrets tls,keys.txt in.pcap out-dsb.pcapng
    /// ```
    #[must_use]
    pub fn keylog_file(&self, path: &'a str) -> Self {
        let mut new = self.clone();
        new.options.push(format!("tls.keylog_file:{path}"));
        new
    }

    /// Set custom protocol's option to tune the tshark decoding.
    /// This adds -o parameter to tshark command line.
    ///
    /// This method can be called multiple times to add more options.
    ///
    /// ### Example: Prepare an instance of TShark without ip defragmenting and custom inap args:
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .option("ip.defragment:false")
    ///     .option("inap.ssn:146");
    /// ```
    #[must_use]
    pub fn option(&self, option: &'a str) -> Self {
        let mut new = self.clone();
        new.options.push(option.to_owned());
        new
    }

    /// Provide protocol names that should be disabled in tshark decoding.
    ///
    /// This method can be called multiple times to add more protocols.
    ///
    /// ### Example: Prepare an instance of TShark where t30 and t38 protocols are not decoded:
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .disable_protocol("t30")
    ///     .disable_protocol("t38");
    /// ```
    #[must_use]
    pub fn disable_protocol(&self, protocol: &'a str) -> Self {
        let mut new = self.clone();
        new.disabled_protocols.push(protocol.to_owned());
        new
    }

    /// Provide protocol names that should be enabled in tshark decoding.
    ///
    /// This method can be called multiple times to add more protocols.
    ///
    /// ### Example: Prepare an instance of TShark where only ethernet and ip are decoded:
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .disable_protocol("ALL")
    ///     .enable_protocol("eth")
    ///     .enable_protocol("ip");
    /// ```
    #[must_use]
    pub fn enable_protocol(&self, protocol: &'a str) -> Self {
        let mut new = self.clone();
        new.enabled_protocols.push(protocol.to_owned());
        new
    }

    /// Write raw packet data to outfile or to the standard output if outfile is '-'.
    /// Note : this option provides raw packet data, not text.
    ///
    /// ### Example: Prepare an instance of TShark to store raw packet data
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/in.pcap")
    ///     .output_path("/tmp/out.pcap");
    /// ```
    #[must_use]
    pub fn output_path(&self, path: &'a str) -> Self {
        let mut new = self.clone();
        new.output_path = path;
        new
    }

    /// Let TShark to decode as the protocol which specified in the expression.
    ///
    /// This method can be called multiple times to add more expression in the decode_as list.
    ///
    /// ### Example: The packet which has TCP port 8080 or 8081 is decoded as HTTP/2.
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap")
    ///     .decode_as("tcp.port==8080,http2")
    ///     .decode_as("tcp.port==8081,http2");
    /// ```
    #[must_use]
    pub fn decode_as(&self, expr: &'a str) -> Self {
        let mut new = self.clone();
        new.decode_as.push(expr);
        new
    }

    fn prepare_args_unbuffered(&self) -> Result<Vec<&str>> {
        let mut tshark_params = self.prepare_args()?;

        tshark_params.extend(&[
            // Packet Details Markup Language, an XML-based format for the details of a decoded packet.
            // This information is equivalent to the packet details printed with the -V option.
            "-Tpdml", // -l activate unbuffered mode, useful to print packets as they come
            "-l",
        ]);

        Ok(tshark_params)
    }

    /// Starts a new TShark process given the provided parameters, mapped to a new [RTShark] instance.
    /// This function may fail if tshark binary is not in PATH or if there are some issues with input_path parameter : not found or no read permission...
    /// In other cases (output_path not writable, invalid syntax for pcap_filter or display_filter),
    /// TShark process will start but will stop a few moments later, leading to a EOF on rtshark.read function.
    /// # Example
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap");
    /// let tshark: std::io::Result<rtshark::RTShark> = builder.spawn();
    /// ```
    pub fn spawn(&self) -> Result<RTShark> {
        let tshark_params = self.prepare_args_unbuffered()?;
        let tshark_child = self.spawn_tshark(&tshark_params)?;
        Ok(RTShark::new(tshark_child, self.metadata_blacklist.clone()))
    }

    /// Starts an asynchronous TShark process given the provided parameters, mapped to a new [RTSharkAsync] instance.
    /// The feature "async" must be enabled in Cargo.toml to use this function.
    /// This function may fail if tshark binary is not in PATH or if there are some issues with input_path parameter : not found or no read permission...
    /// In other cases (output_path not writable, invalid syntax for pcap_filter or display_filter),
    /// TShark process will start but will stop a few moments later, leading to a EOF on rtshark.read function.
    /// # Example
    /// ```
    /// use tokio;
    /// use rtshark::RTSharkBuilder;
    /// #[tokio::main]
    /// async fn main() -> std::io::Result<()> {
    ///         let pcap_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    ///             .join("assets")
    ///             .join("test_tls.pcap");
    ///         assert!(pcap_path.exists());
    ///
    ///         let mut rtshark = RTSharkBuilder::builder()
    ///             .input_path(pcap_path.to_str().unwrap())
    ///            .capture_filter("tcp")
    ///             .spawn_async()
    ///             .unwrap();
    ///
    ///         let mut tls_counter = 0;
    ///         let mut time_counter = 0;
    ///         let mut running = true;
    ///
    ///         while running {
    ///             tokio::join!(
    ///                 // Process 1: Try to read a packet
    ///                 async {
    ///                     match rtshark.read().await {
    ///                         Ok(Some(packet)) => {
    ///                             if let Some(_tls) = packet.layer_name("tls") {
    ///                                 tls_counter += 1;
    ///                                 println!("TLS packet count: {}", tls_counter);
    ///                             }
    ///                         }
    ///                         Ok(None) => {
    ///                             println!("End of capture stream");
    ///                             running = false;
    ///                         }
    ///                         Err(e) => {
    ///                             eprintln!("Error parsing tshark output: {e}");
    ///                             running = false;
    ///                         }
    ///                     }
    ///                },
    ///                 // Process 2: Do something else that takes time (e.g., print a message every interval of time)
    ///                 async {
    ///                     tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    ///                     time_counter += 1;
    ///                     println!("Time elapsed: {} seconds", time_counter);
    ///                 }
    ///             );
    ///         }
    ///     Ok(())
    /// }
    /// ```
    #[cfg(feature = "async")]
    pub fn spawn_async(&self) -> Result<crate::RTSharkAsync> {
        let tshark_params = self.prepare_args_unbuffered()?;
        let tshark_child = self.spawn_tshark_async(&tshark_params)?;

        Ok(crate::RTSharkAsync::new(
            tshark_child,
            self.metadata_blacklist.clone(),
        ))
    }

    /// Starts a new TShark process given the provided parameters and runs it to completion. In
    /// contrast to [`RTSharkBuilderReady::spawn` ]no programmatic access to individual packets is
    /// provided.
    /// This function may fail if tshark binary is not in PATH or if there are some issues with input_path parameter : not found or no read permission...
    /// In other cases (output_path not writable, invalid syntax for pcap_filter or display_filter),
    /// TShark process will fail and the stderr will be reported.
    /// # Example
    ///
    /// ```
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap");
    /// let _: Result<(), std::io::Error> = builder.batch();
    /// ```
    pub fn batch(&self) -> Result<()> {
        let tshark_params = self.prepare_args()?;

        let mut tshark_child = self.spawn_tshark(&tshark_params)?;

        if !tshark_child.wait()?.success() {
            let mut stderr = BufReader::new(tshark_child.stderr.take().unwrap());
            // if process stops, there may be due to an error, we can get it in stderr
            let mut line = String::new();
            let size = stderr.read_line(&mut line)?;
            // if len is != 0 there is an error message
            if size != 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, line));
            }
        }

        Ok(())
    }

    #[cfg(feature = "async")]
    fn spawn_tshark_async(&self, tshark_params: &[&str]) -> Result<tokio::process::Child> {
        // piping from TShark, not to load the entire output in ram...
        // spawn may fail if TShark is not found in path

        let tshark_child = if self.env_path.is_empty() {
            tokio::process::Command::new("tshark")
                .args(tshark_params)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        } else {
            tokio::process::Command::new("tshark")
                .args(tshark_params)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env("PATH", self.env_path)
                .spawn()
        };

        tshark_child.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                std::io::Error::new(e.kind(), format!("Unable to find tshark: {e}"))
            }
            _ => e,
        })
    }

    fn spawn_tshark(&self, tshark_params: &[&str]) -> Result<Child> {
        // piping from TShark, not to load the entire output in ram...
        // spawn may fail if TShark is not found in path

        let tshark_child = if self.env_path.is_empty() {
            Command::new("tshark")
                .args(tshark_params)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        } else {
            Command::new("tshark")
                .args(tshark_params)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env("PATH", self.env_path)
                .spawn()
        };

        tshark_child.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                std::io::Error::new(e.kind(), format!("Unable to find tshark: {e}"))
            }
            _ => e,
        })
    }

    /// Prepare tshark command line parameters.
    fn prepare_args(&self) -> Result<Vec<&str>> {
        let mut tshark_params = if self.live_capture {
            let mut input = vec![];
            self.input_path
                .iter()
                .for_each(|i| input.extend(&["-i", i]));
            input
        } else {
            if self.input_path.len() > 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "tshark supports only one input pcap file",
                ));
            }

            // test if input file exists
            let input_path = self.input_path[0];
            std::fs::metadata(input_path).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    std::io::Error::new(e.kind(), format!("Unable to find {input_path}: {e}"))
                }
                _ => e,
            })?;

            vec!["-r", input_path]
        };

        tshark_params.extend(&[
            // Disable network object name resolution (such as hostname, TCP and UDP port names)
            "-n",
            // When capturing packets, TShark writes to the standard error an initial line listing the interfaces from which packets are being captured and,
            // if packet information isn’t being displayed to the terminal, writes a continuous count of packets captured to the standard output.
            // If the -Q option is specified, neither the initial line, nor the packet information, nor any packet counts will be displayed.
            "-Q",
        ]);

        if !self.output_path.is_empty() {
            tshark_params.extend(&["-w", self.output_path]);
        }

        if self.live_capture && !self.capture_filter.is_empty() {
            tshark_params.extend(&["-f", self.capture_filter]);
        }

        if !self.display_filter.is_empty() {
            tshark_params.extend(&["-Y", self.display_filter]);
        }

        if !self.decode_as.is_empty() {
            for elm in self.decode_as.iter() {
                tshark_params.extend(&["-d", elm]);
            }
        }

        for option in &self.options {
            tshark_params.extend(&["-o", option]);
        }

        if let Some(wl) = &self.metadata_whitelist {
            for whitelist_elem in wl {
                tshark_params.extend(&["-e", whitelist_elem]);
            }
        }

        for protocol in &self.disabled_protocols {
            tshark_params.extend(&["--disable-protocol", protocol]);
        }

        for protocol in &self.enabled_protocols {
            tshark_params.extend(&["--enable-protocol", protocol]);
        }

        Ok(tshark_params)
    }
}

#[cfg(test)]
mod tests {

    use crate::builder::RTSharkBuilder;

    #[test]
    fn test_tshark_version() {
        let builder = RTSharkBuilder::builder();
        builder.version().expect("Error getting tshark version");
    }
}
