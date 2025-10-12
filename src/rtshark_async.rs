use crate::{packet::Packet, xml::parse_xml_async};
use std::io::{Error, ErrorKind, Result};
#[cfg(target_family = "unix")]
use std::os::unix::process::ExitStatusExt;
use tokio::io::AsyncBufReadExt;

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

    pub async fn read(&mut self) -> Result<Option<Packet>> {
        let xml_reader = &mut self.parser;

        let msg_future = parse_xml_async(xml_reader, &self.filters);
        let msg = msg_future.await?;
        let done = match &msg {
            None => {
                // Got None == EOF
                match self.process {
                    Some(ref mut process) => RTSharkAsync::try_wait_has_exited(process),
                    _ => true,
                }
            }
            _ => false,
        };
        if done {
            self.process = None;
            // if process stops, there may be due to an error, we can get it in stderr
            let mut line = String::new();
            let size = self.stderr.read_line(&mut line).await?;
            if size != 0 {
                return Err(Error::new(ErrorKind::InvalidInput, line));
            }
        }

        Ok(msg)
    }

    fn try_wait_has_exited(child: &mut tokio::process::Child) -> bool {
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
