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
    use std::io::Write;

    use serial_test::serial;
    use tokio::runtime::Runtime;

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

    #[test]
    fn test_rtshark_input_pcap() {
        let pcap = include_bytes!("../assets/test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder().input_path(pcap_path.to_str().unwrap());

        Runtime::new().unwrap().block_on(async {
            let mut rtshark = builder.spawn_async().unwrap();

            // read a packet
            match rtshark.read().await.unwrap() {
                Some(p) => assert!(p.layer_name("udp").is_some()),
                _ => panic!("invalid Output type"),
            }

            loop {
                match rtshark.read().await.unwrap() {
                    None => break,
                    Some(_) => todo!(),
                }
            }

            rtshark.kill().await;

            assert!(rtshark.pid().is_none());
        });

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_decode_as() {
        // 0. prepare pcap
        let pcap = include_bytes!("../assets/rtp.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("rtp.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // 1. a first run without decode_as option

        // spawn tshark on it
        let builder = RTSharkBuilder::builder().input_path(pcap_path.to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read a packet, must be tcp without http2
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("rtp").is_none()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        // 2. a second run with decode_as option
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .decode_as("udp.port==6000,rtp");

        let mut rtshark = builder.spawn().unwrap();

        // read a packet, must be http2
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("rtp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        // 3. cleanup
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_display_filter() {
        let pcap = include_bytes!("../assets/test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // first pass: get a udp packet
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .display_filter("udp.port == 53");

        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        // second pass: try a tcp packet
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .display_filter("tcp.port == 80");

        let mut rtshark = builder.spawn().unwrap();

        // we should get EOF since no packet is matching
        match rtshark.read().unwrap() {
            None => (),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_blacklist() {
        let pcap = include_bytes!("../assets/test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .metadata_blacklist("ip.src");
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        let pkt = match rtshark.read().unwrap() {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        assert!(ip.metadata("ip.src").is_none());
        assert!(ip.metadata("ip.dst").unwrap().value().eq("127.0.0.1"));

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_whitelist() {
        let pcap = include_bytes!("../assets/test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .metadata_whitelist("ip.dst");
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        let pkt = match rtshark.read().unwrap() {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        assert!(ip.metadata("ip.src").is_none());
        assert!(ip.metadata("ip.dst").unwrap().value().eq("127.0.0.1"));

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_multiple_whitelist() {
        let pcap = include_bytes!("../assets/test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .metadata_whitelist("ip.src")
            .metadata_whitelist("ip.dst");
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        let pkt = match rtshark.read().unwrap() {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        assert!(ip.metadata("ip.src").unwrap().value().eq("127.0.0.1"));
        assert!(ip.metadata("ip.dst").unwrap().value().eq("127.0.0.1"));

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_input_pcap_whitelist_multiple_layer() {
        let pcap = include_bytes!("../assets/test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .metadata_whitelist("ip.src")
            .metadata_whitelist("udp.dstport");
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        let pkt = match rtshark.read().unwrap() {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        let ip = pkt.layer_name("ip").unwrap();
        assert!(ip.metadata("ip.src").unwrap().value().eq("127.0.0.1"));
        let ip = pkt.layer_name("udp").unwrap();
        assert!(ip.metadata("udp.dstport").unwrap().value().eq("53"));

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    // this test may fail if executed in parallel with other tests. Run it with --test-threads=1 option.
    #[test]
    fn test_rtshark_input_pcap_whitelist_missing_attr() {
        let pcap = include_bytes!("../assets/test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .metadata_whitelist("nosuchproto.nosuchmetadata");
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        let ret = rtshark.read();
        assert!(ret.is_err());

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_input_fifo() {
        let pcap = include_bytes!("../assets/test.pcap");

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
        let mut rtshark = builder.spawn().unwrap();

        // send packets in the fifo
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .expect("unable to open fifo");
        output.write_all(pcap).expect("unable to write in fifo");

        // get analysis
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        // stop tshark
        rtshark.kill();

        // verify tshark is stopped
        assert!(rtshark.pid().is_none());

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_input_multiple_fifo() {
        let pcap = include_bytes!("../assets/test.pcap");

        // create temp dir
        let tmp_dir = tempdir::TempDir::new("test_fifo").unwrap();
        let fifo_path1 = tmp_dir.path().join("pcap1.pipe");
        let fifo_path2 = tmp_dir.path().join("pcap2.pipe");

        // create new fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path1, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // create another fifo and give read, write and execute rights to the owner
        nix::unistd::mkfifo(&fifo_path2, nix::sys::stat::Mode::S_IRWXU)
            .expect("Error creating fifo");

        // start tshark on the fifo
        let builder = RTSharkBuilder::builder()
            .input_path(fifo_path1.to_str().unwrap())
            .input_path(fifo_path2.to_str().unwrap())
            .live_capture();
        let mut rtshark = builder.spawn().unwrap();

        // send one packet in the fifo1
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path1)
            .expect("unable to open fifo");
        output.write_all(pcap).expect("unable to write in fifo");

        // send one packet in the fifo2
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path2)
            .expect("unable to open fifo");
        output.write_all(pcap).expect("unable to write in fifo");

        // get analysis from first packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        // get analysis for second packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        // stop tshark
        rtshark.kill();

        // verify tshark is stopped
        assert!(rtshark.pid().is_none());

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_input_pcap_filter_pcap() {
        let pcap = include_bytes!("../assets/test.pcap");

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
            .capture_filter("port 53");

        let mut rtshark = builder.spawn().unwrap();

        // send packets in the fifo
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .expect("unable to open fifo");
        output.write_all(pcap).expect("unable to write in fifo");

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        // then, check with the bad filter, we don't get the packet
        // TODO (need a pcap with 2 packets, first will be filtered out)

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
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
            let rtshark = builder.spawn().unwrap();
            let pid = rtshark.pid().unwrap();

            assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
            pid
        };

        // verify tshark is stopped
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
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

        let mut rtshark = builder.spawn().unwrap();

        // killing badly
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(rtshark.pid().unwrap() as libc::pid_t),
            nix::sys::signal::Signal::SIGKILL,
        )
        .unwrap();

        // reading from process output should give EOF
        match rtshark.read().unwrap() {
            None => (),
            _ => panic!("invalid Output type"),
        }

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
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

        let mut rtshark = builder.spawn().unwrap();

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");

        // reading from process output should give 2 error messages then EOF
        loop {
            match rtshark.read() {
                Ok(e) if e.is_some() => panic!("invalid Output type"),
                Ok(e) if e.is_none() => break,
                _ => (),
            }
        }
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_fifo_opened_then_closed() {
        let pcap = include_bytes!("../assets/test.pcap");

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

        let mut rtshark = builder.spawn().unwrap();

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
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        // disable this check for now - fails due to "normal" error message on stderr when tshark stops:
        // ---- tests::test_rtshark_fifo_opened_then_closed stdout ----
        // thread 'tests::test_rtshark_fifo_opened_then_closed' panicked at 'called `Result::unwrap()` on an `Err` value: Custom { kind: InvalidInput, error: "1 packet captured\n" }', src/lib.rs:1924:30
        // note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
        /*
        match rtshark.read().unwrap() {
            None => (),
            _ => panic!("invalid Output type"),
        }
        */

        // stop tshark
        rtshark.kill();

        // reading from process output should give EOF
        // disable this check for now - fails due to "normal" error message on stderr when tshark stops:
        // ---- tests::test_rtshark_fifo_opened_then_closed stdout ----
        // thread 'tests::test_rtshark_fifo_opened_then_closed' panicked at 'called `Result::unwrap()` on an `Err` value: Custom { kind: InvalidInput, error: "tshark: \n" }', src/lib.rs:1969:30
        // note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

        /*
        match rtshark.read().unwrap() {
            None => (),
            _ => panic!("invalid Output type"),
        }
        */

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_file_missing() {
        // start tshark on a missing fifo
        let builder = RTSharkBuilder::builder().input_path("/missing/rtshark/fifo");

        let ret = builder.spawn();

        match ret {
            Ok(_) => panic!("We can't start if file is missing"),
            Err(e) => eprintln!("{e}"),
        }
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_set_options() {
        let pcap = include_bytes!("../assets/tcp_fragmentation.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // second pass: turn on relative sequence numbers
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .option("tcp.relative_sequence_numbers:true");

        let mut rtshark = builder.spawn().unwrap();

        match rtshark.read().unwrap() {
            Some(p) => {
                let tcp = p.layer_name("tcp").expect("tcp layer");
                if !tcp.iter().any(|md| {
                    if let Some(display) = md.display() {
                        display.contains("relative sequence number")
                    } else {
                        false
                    }
                }) {
                    panic!("expected relative sequence number")
                }
            }
            e => panic!("invalid Output type: {e:?}"),
        }

        rtshark.kill();

        // second pass: turn off relative sequence numbers
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .option("tcp.relative_sequence_numbers:false");

        let mut rtshark = builder.spawn().unwrap();

        // we should not see any relative sequence numbers
        match rtshark.read().unwrap() {
            Some(p) => {
                let tcp = p.layer_name("tcp").expect("tcp layer");
                if tcp.iter().any(|md| {
                    if let Some(display) = md.display() {
                        display.contains("relative sequence number")
                    } else {
                        false
                    }
                }) {
                    panic!("expected no relative sequence numbers")
                }
            }
            e => panic!("invalid Output type: {e:?}"),
        }

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_set_disabled_protocols() {
        let pcap = include_bytes!("../assets/tcp_fragmentation.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // turn off tcp and sip protocols
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .disable_protocol("tcp")
            .disable_protocol("sip");

        let mut rtshark = builder.spawn().unwrap();

        match rtshark.read().unwrap() {
            Some(p) => {
                assert!(p.layer_name("tcp").is_none());
                assert!(p.layer_name("sip").is_none());
            }
            e => panic!("invalid Output type: {e:?}"),
        }

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_set_enabled_protocols() {
        let pcap = include_bytes!("../assets/tcp_fragmentation.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // turn off everything except eth and ip
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .disable_protocol("ALL")
            .enable_protocol("eth")
            .enable_protocol("ip");

        let mut rtshark = builder.spawn().unwrap();

        match rtshark.read().unwrap() {
            Some(p) => {
                assert!(p.layer_name("tcp").is_none());
                assert!(p.layer_name("sip").is_none());
                assert!(p.layer_name("ip").is_some());
            }
            e => panic!("invalid Output type: {e:?}"),
        }

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    #[serial] // Run test serially since its modifying env PATH
    fn test_rtshark_tshark_missing() {
        // clear PATH env (if tshark is already in PATH)
        let path = match std::env::var("PATH") {
            Ok(v) => {
                std::env::remove_var("PATH");
                Some(v)
            }
            Err(_) => None,
        };

        // start tshark on a missing fifo
        let builder = RTSharkBuilder::builder()
            .input_path("/missing/rtshark/fifo")
            .live_capture()
            .env_path("/invalid/path");

        let ret = builder.spawn();

        // restore PATH env (for other tests)
        if let Some(v) = path {
            std::env::set_var("PATH", v);
        }

        match ret {
            Ok(_) => panic!("We can't start if tshark is missing"),
            Err(e) => eprintln!("{e}"),
        }
    }

    #[test]
    fn test_rtshark_input_pcap_output_pcap() {
        let pcap = include_bytes!("../assets/test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let in_path = tmp_dir.path().join("in.pcap");
        let mut output = std::fs::File::create(&in_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        let out_path = tmp_dir.path().join("out.pcap");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(in_path.to_str().unwrap())
            .output_path(out_path.to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        loop {
            match rtshark.read().unwrap() {
                None => break,
                Some(_) => todo!(),
            }
        }

        rtshark.kill();

        assert!(rtshark.pid().is_none());

        // now check what was written
        let mut rtshark = RTSharkBuilder::builder()
            .input_path(out_path.to_str().unwrap())
            .spawn()
            .unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_rtshark_input_fifo_output_pcap() {
        let pcap = include_bytes!("../assets/test.pcap");

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
        let mut rtshark = builder.spawn().unwrap();

        // send packets in the fifo
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_path)
            .expect("unable to open fifo");
        output.write_all(pcap).expect("unable to write in fifo");

        // get analysis
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        // stop tshark
        rtshark.kill();

        // verify tshark is stopped
        assert!(rtshark.pid().is_none());

        // now check what was written
        let mut rtshark = RTSharkBuilder::builder()
            .input_path(out_path.to_str().unwrap())
            .spawn()
            .unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }
    #[test]
    #[serial] // Run test serially to limit check to multiple spawns in test
    fn test_rtshark_multiple_spawn_pcap() {
        let pcap = include_bytes!("../assets/test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let in_path = tmp_dir.path().join("in.pcap");
        let mut output = std::fs::File::create(&in_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        let out_path = tmp_dir.path().join("out.pcap");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(in_path.to_str().unwrap())
            .output_path(out_path.to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        // retry
        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_timestamp_micros() {
        let pcap = include_bytes!("../assets/test.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let in_path = tmp_dir.path().join("in.pcap");
        let mut output = std::fs::File::create(&in_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        let out_path = tmp_dir.path().join("out.pcap");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(in_path.to_str().unwrap())
            .output_path(out_path.to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read a packet
        match rtshark.read().unwrap() {
            Some(p) => assert_eq!(p.timestamp_micros(), Some(1652011560275852)),
            _ => panic!("invalid Output type"),
        }

        rtshark.kill();

        /* remove fifo & tempdir */
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_rtshark_tls_keylogfile_pcap() {
        let pcap = include_bytes!("../assets/test_tls.pcap");
        let keylog = include_bytes!("../assets/test_tlskeylogfile.txt");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder().input_path(pcap_path.to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read packets
        loop {
            match rtshark.read().unwrap() {
                None => break,
                Some(p) => {
                    // we check there is no visible http2
                    assert!(p.layer_name("tcp").is_some());
                    assert!(p.layer_name("http2").is_none())
                }
            }
        }

        rtshark.kill();

        let keylog_path = tmp_dir.path().join("keylogfile.txt");
        let mut output = std::fs::File::create(&keylog_path).expect("unable to open file");
        output.write_all(keylog).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            .keylog_file(keylog_path.as_os_str().to_str().unwrap());

        let mut rtshark = builder.spawn().unwrap();

        // read packets and search for http2 get
        let mut http2_found = false;
        loop {
            match rtshark.read().unwrap() {
                None => break,
                Some(p) => {
                    // we check there is a http2 method GET
                    assert!(p.layer_name("tcp").is_some());
                    if p.layer_name("http2").is_some() {
                        http2_found = true;
                    }
                }
            }
        }

        assert!(http2_found);

        rtshark.kill();

        assert!(rtshark.pid().is_none());
        tmp_dir.close().expect("Error deleting fifo dir");
    }

    #[test]
    fn test_reassembled_tcp() {
        let pcap = include_bytes!("../assets/tcp_fragmentation.pcap");

        // create temp dir and copy pcap in it
        let tmp_dir = tempdir::TempDir::new("test_pcap").unwrap();
        let pcap_path = tmp_dir.path().join("file.pcap");
        let mut output = std::fs::File::create(&pcap_path).expect("unable to open file");
        output.write_all(pcap).expect("unable to write pcap");
        output.flush().expect("unable to flush");

        // spawn tshark on it
        let builder = RTSharkBuilder::builder()
            .input_path(pcap_path.to_str().unwrap())
            // The ClientHello is the fragmented message
            .display_filter("tls.handshake.type == 1");

        let mut rtshark = builder.spawn().unwrap();

        // read packets
        loop {
            match rtshark.read().unwrap() {
                None => break,
                Some(p) => {
                    let tcp = p.layer_name("tcp").expect("Missing tcp layer");
                    tcp.metadata("tcp.reassembled.data")
                        .expect("Missing metadata");
                }
            }
        }

        rtshark.kill();
        assert!(rtshark.pid().is_none());
        tmp_dir.close().expect("Error deleting fifo dir");
    }
}
