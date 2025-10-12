use crate::packet::Packet;
use std::io::{BufRead, Error, ErrorKind, Result};
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
    fn new(
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
