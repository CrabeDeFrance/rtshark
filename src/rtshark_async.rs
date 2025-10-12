use crate::{
    packet::Packet,
    xml::{ParserResult, RTSharkParser},
};
use quick_xml::Reader;
#[cfg(target_family = "unix")]
use std::os::unix::process::ExitStatusExt;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt},
    process::Child,
};

/// Async version of RTShark
pub struct RTSharkAsync {
    process: Option<tokio::process::Child>,
    parser: quick_xml::Reader<tokio::io::BufReader<tokio::process::ChildStdout>>,
    stderr: tokio::io::BufReader<tokio::process::ChildStderr>,
    filters: Vec<String>,
}

impl RTSharkAsync {
    pub(crate) fn new(
        process: tokio::process::Child,
        parser: quick_xml::Reader<tokio::io::BufReader<tokio::process::ChildStdout>>,
        stderr: tokio::io::BufReader<tokio::process::ChildStderr>,
        filters: Vec<String>,
    ) -> Self {
        RTSharkAsync {
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
    /// use tokio;
    /// use rtshark::RTSharkBuilder;
    /// #[tokio::main]
    /// async fn main() {
    ///     let pcap_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    ///         .join("assets")
    ///         .join("test_tls.pcap");
    ///     assert!(pcap_path.exists());
    ///
    ///     # // Creates a builder with needed TShark parameters
    ///     # let builder = rtshark::RTSharkBuilder::builder()
    ///     #     .input_path("/tmp/my.pcap");
    ///     // Start a new TShark process
    ///     let mut rtshark = match builder.spawn_async() {
    ///         Err(err) => { eprintln!("Error running tshark: {err}"); return; }
    ///         Ok(rtshark) => rtshark
    ///     };
    ///
    ///     // read packets until the end of the PCAP file
    ///     loop {
    ///         let packet = match rtshark.read().await {
    ///             Ok(p) => p,
    ///             Err(e) => { eprintln!("Got decoding error: {e}"); continue; }
    ///         };
    ///
    ///         // end of stream
    ///         if let None = packet {
    ///             break;
    ///         }
    ///
    ///         println!("Got a packet");
    ///     }
    /// }
    /// ```
    pub async fn read(&mut self) -> std::io::Result<Option<Packet>> {
        let ret = RTSharkAsync::parse(&mut self.parser, &self.filters).await?;
        if ret.is_none() {
            self.on_eof().await?;
        }
        Ok(ret)
    }

    async fn on_eof(&mut self) -> std::io::Result<()> {
        let done = match self.process {
            Some(ref mut process) => RTSharkAsync::try_wait_has_exited(process),
            _ => true,
        };

        if done {
            self.process = None;

            // if process stops, there may be due to an error, we can get it in stderr
            let mut line = String::new();
            let size = self.stderr.read_line(&mut line).await?;
            // if len is != 0 there is an error message
            if size != 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, line));
            }
        }

        Ok(())
    }

    pub(crate) async fn parse<B: AsyncBufRead + Unpin>(
        reader: &mut Reader<B>,
        filters: &[String],
    ) -> std::io::Result<Option<Packet>> {
        let mut parser = RTSharkParser::new();
        let mut buf = vec![];

        loop {
            let event = reader.read_event_into_async(&mut buf).await.map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("cant parse xml: {e}"),
                )
            })?;

            match parser.parse(event, filters)? {
                ParserResult::Continue => (),
                ParserResult::Packet(packet) => return Ok(Some(packet)),
                ParserResult::Eof => return Ok(None),
            }
        }
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
    pub async fn kill(&mut self) {
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
                match process.kill().await {
                    Ok(()) => (),
                    Err(e) => eprintln!("Error while killing rtshark: kill: {e}"),
                }
                if let Err(e) = process.wait().await {
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
        self.process.as_ref().map(|p| p.id())?
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
#[cfg(test)]
mod tests {
    use crate::RTSharkBuilder;

    #[tokio::test]
    async fn test_async_read() {
        let pcap_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("assets")
            .join("test_tls.pcap");

        println!("{pcap_path:?}");
        assert!(pcap_path.exists());

        let mut rtshark = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .capture_filter("tcp")
            .spawn_async()
            .unwrap();

        let mut tls_counter = 0;
        let mut time_counter = 0;
        let mut running = true;

        while running {
            tokio::join!(
                // Process 1: Try to read a packet
                async {
                    match rtshark.read().await {
                        Ok(Some(packet)) => {
                            if let Some(_tls) = packet.layer_name("tls") {
                                tls_counter += 1;
                                println!("TLS packet count: {tls_counter}");
                            }
                        }
                        Ok(None) => {
                            println!("End of capture stream");
                            running = false;
                        }
                        Err(e) => {
                            eprintln!("Error parsing tshark output: {e}");
                            running = false;
                        }
                    }
                },
                // Process 2: Do something else that takes time (e.g., print a message every interval of time)
                async {
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    time_counter += 1;
                    println!("Time elapsed: {time_counter} seconds");
                }
            );
        }

        assert_eq!(tls_counter, 27);
        assert!(time_counter >= 49);
    }
}
