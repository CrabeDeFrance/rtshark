use crate::{packet::Packet, xml::parse_xml};
use std::io::{BufRead, BufReader, Result};
#[cfg(target_family = "unix")]
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStderr, ChildStdout};

/// RTShark structure represents a TShark process.
/// It allows controlling the TShark process and reading from application's output.
/// It is created by [RTSharkBuilder].
pub struct RTShark {
    /// Contains the TShark process handle, when TShark is running
    process: Option<Child>,
    /// xml parser on TShark piped output
    parser: quick_xml::Reader<BufReader<ChildStdout>>,
    /// stderr
    stderr: BufReader<ChildStderr>,
    /// optional metadata blacklist, to prevent storing useless metadata in output packet structure
    filters: Vec<String>,
}

impl RTShark {
    /// create a new RTShark instance from a successful builder call.
    pub(crate) fn new(
        process: Child,
        parser: quick_xml::Reader<BufReader<ChildStdout>>,
        stderr: BufReader<ChildStderr>,
        filters: Vec<String>,
    ) -> Self {
        RTShark {
            process: Some(process),
            parser,
            stderr,
            filters,
        }
    }

    /// Read a packet from thsark output and map it to the [Packet] type.
    /// Reading packet can be done until 'None' is returned.
    /// Once 'None' is returned, no more packets can be read from this stream
    /// and TShark instance can be dropped.
    /// This could happen when TShark application dies or when this is the end of the PCAP file.
    ///
    /// # Example
    ///
    /// ```
    /// # // Creates a builder with needed TShark parameters
    /// # let builder = rtshark::RTSharkBuilder::builder()
    /// #     .input_path("/tmp/my.pcap");
    /// // Start a new TShark process
    /// let mut rtshark = match builder.spawn() {
    ///     Err(err) => { eprintln!("Error running tshark: {err}"); return; }
    ///     Ok(rtshark) => rtshark
    /// };
    ///
    /// // read packets until the end of the PCAP file
    /// loop {
    ///     let packet = match rtshark.read() {
    ///         Ok(p) => p,
    ///         Err(e) => { eprintln!("Got decoding error: {e}"); continue; }
    ///     };
    ///
    ///     // end of stream
    ///     if let None = packet {
    ///         break;
    ///     }
    ///
    ///     println!("Got a packet");
    /// }
    /// ```
    pub fn read(&mut self) -> Result<Option<Packet>> {
        let xml_reader = &mut self.parser;

        let msg = parse_xml(xml_reader, &self.filters);
        if let Ok(ref msg) = msg {
            let done = match msg {
                None => {
                    // Got None == EOF
                    match self.process {
                        Some(ref mut process) => RTShark::try_wait_has_exited(process),
                        _ => true,
                    }
                }
                _ => false,
            };

            if done {
                self.process = None;

                // if process stops, there may be due to an error, we can get it in stderr
                let mut line = String::new();
                let size = self.stderr.read_line(&mut line)?;
                // if len is != 0 there is an error message
                if size != 0 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, line));
                }
            }
        }

        msg
    }

    /// Kill the running TShark process associated to this rtshark instance.
    /// Once TShark is killed, there is no way to start it again using this object.
    /// Any new TShark instance has to be created using RTSharkBuilder.
    ///
    /// # Example
    ///
    /// ```
    /// // Creates a builder with needed TShark parameters
    /// let builder = rtshark::RTSharkBuilder::builder()
    ///     .input_path("/tmp/my.pcap");
    ///
    /// // Start a new TShark process
    /// let mut rtshark = match builder.spawn() {
    ///     Err(err) => { eprintln!("Error running tshark: {err}"); return; }
    ///     Ok(rtshark) => rtshark
    /// };
    ///
    /// // kill running TShark process
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
    /// let mut rtshark = match builder.spawn() {
    ///     Err(err) => { eprintln!("Error running tshark: {err}"); return; }
    ///     Ok(rtshark) => println!("tshark PID is {}", rtshark.pid().unwrap())
    /// };
    ///
    /// ```
    pub fn pid(&self) -> Option<u32> {
        self.process.as_ref().map(|p| p.id())
    }

    /// Check if process is stopped, get the exit code and return true if stopped.
    /// Why not doing a simple wait ?
    fn try_wait_has_exited(child: &mut Child) -> bool {
        let mut count = 3;
        while count != 0 {
            #[cfg(target_family = "unix")]
            if let Ok(Some(s)) = child.try_wait() {
                return s.code().is_some() || s.signal().is_some();
            }

            #[cfg(target_family = "windows")]
            if let Ok(Some(s)) = child.try_wait() {
                return s.code().is_some();
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
            count -= 1;
        }

        false
    }
}

impl Drop for RTShark {
    fn drop(&mut self) {
        self.kill()
    }
}
