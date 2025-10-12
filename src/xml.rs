use quick_xml::events::{BytesStart, Event};
use std::io::{BufRead, Error, ErrorKind, Result};

use crate::{metadata::Metadata, packet::Packet};

/// search for an attribute of a XML tag using its name and return a string.
fn rtshark_attr_by_name(tag: &BytesStart, key: &[u8]) -> Result<String> {
    let attrs = &mut tag.attributes();
    for attr in attrs {
        let attr = attr.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error decoding xml attribute: {e:?}"),
            )
        })?;
        if attr.key.as_ref() == key {
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
fn rtshark_attr_by_name_u32(tag: &BytesStart, key: &[u8]) -> Result<u32> {
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
    if name.is_empty() || name.starts_with("_ws.") {
        return Ok(None);
    }

    // skip data
    if filters.contains(&name) {
        return Ok(None);
    }

    // Issue #1 : uses pyshark-like algorithm to display the best 'value' for this field
    // https://github.com/KimiNewt/pyshark/blob/master/src/pyshark/packet/fields.py#L14
    // try first "show", then "value", finally "showname"
    let value = match rtshark_attr_by_name(tag, b"show") {
        Ok(value) => Ok(value),
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            match rtshark_attr_by_name(tag, b"value") {
                Ok(value) => Ok(value),
                Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                    if let Ok(value) = rtshark_attr_by_name(tag, b"showname") {
                        Ok(value)
                    } else {
                        Err(err)
                    }
                }
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }?;

    let mut metadata = Metadata::new(name, value, None, None, None);

    if let Ok(position) = rtshark_attr_by_name_u32(tag, b"pos") {
        *metadata.position_mut() = Some(position);
    }
    if let Ok(size) = rtshark_attr_by_name_u32(tag, b"size") {
        *metadata.size_mut() = Some(size);
    }
    if let Ok(display) = rtshark_attr_by_name(tag, b"showname") {
        *metadata.display_mut() = Some(display);
    }
    if let Ok(raw_value) = rtshark_attr_by_name(tag, b"value") {
        if raw_value != metadata.value() {
            *metadata.raw_value_mut() = Some(raw_value);
        }
    }
    Ok(Some(metadata))
}

/// Process specific metadata in geninfo to fill the packet structure
fn geninfo_metadata(tag: &BytesStart, packet: &mut Packet) -> Result<()> {
    use chrono::{LocalResult, TimeZone as _, Utc};

    let name = rtshark_attr_by_name(tag, b"name")?;
    if name != "timestamp" {
        return Ok(());
    }
    let value = rtshark_attr_by_name(tag, b"value")?;

    let bad_timestamp = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Error decoding timestamp: {value}"),
        )
    };

    let (secs, nsecs) = value.split_once('.').ok_or_else(bad_timestamp)?;
    let secs = secs.parse().map_err(|_| bad_timestamp())?;
    let nsecs = nsecs.parse().map_err(|_| bad_timestamp())?;

    let LocalResult::Single(dt) = Utc.timestamp_opt(secs, nsecs) else {
        return Err(bad_timestamp());
    };
    packet.timestamp_micros_mut().replace(dt.timestamp_micros());

    Ok(())
}

/// list of protocols in tshark output but not in packet data
fn ignored_protocols(name: &str) -> bool {
    name.eq("geninfo") || name.eq("fake-field-wrapper")
}

#[cfg(feature = "async")]
pub(crate) async fn parse_xml_async(
    xml_reader: &mut quick_xml::Reader<tokio::io::BufReader<tokio::process::ChildStdout>>,
    filters: &[String],
) -> Result<Option<Packet>> {
    let mut buf = vec![];
    let mut packet = Packet::new();

    let mut protoname = None;

    /// Create a new layer if required and add metadata to the given packet.
    fn _add_metadata(packet: &mut Packet, metadata: Metadata) -> Result<()> {
        // Create a new layer if the field's protocol does not exist yet as a layer.
        if let Some(proto) = metadata.name().split('.').next() {
            packet.push_if_not_exist(proto.to_owned());
        }

        if let Some(layer) = packet.last_layer_mut() {
            layer.add(metadata);
        } else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Cannot find protocol name to push a metadata",
            ));
        }

        Ok(())
    }

    loop {
        // THIS IS THE ONLY DIFFERENCE WITH parse_xml() FUNCTION
        match xml_reader.read_event_into_async(&mut buf).await {
            Ok(Event::Start(ref e)) => {
                if b"proto" == e.name().as_ref() {
                    let proto = rtshark_attr_by_name(e, b"name")?;
                    protoname = Some(proto.to_owned());

                    if !ignored_protocols(proto.as_str()) {
                        packet.push(proto);
                    }
                }

                if b"field" == e.name().as_ref() {
                    if let Some(metadata) = rtshark_build_metadata(e, filters)? {
                        _add_metadata(&mut packet, metadata)?;
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                if b"field" == e.name().as_ref() {
                    if let Some(name) = protoname.as_ref() {
                        if name == "geninfo" {
                            // Put geninfo metadata in packet's object (timestamp ...).
                            geninfo_metadata(e, &mut packet)?;
                        } else if let Some(metadata) = rtshark_build_metadata(e, filters)? {
                            if name == "fake-field-wrapper" {
                                let proto_from_name =
                                    metadata.name().split('.').next().unwrap_or("");
                                let proto_layer = packet
                                    .last_layer_mut()
                                    .filter(|layer| layer.name == proto_from_name);
                                if let Some(layer) = proto_layer {
                                    layer.add(metadata);
                                }
                            } else {
                                // We can unwrap because we must have a layer : it was pushed in Event::Start
                                packet.last_layer_mut().unwrap().add(metadata);
                            }
                        }
                    } else if let Some(metadata) = rtshark_build_metadata(e, filters)? {
                        _add_metadata(&mut packet, metadata)?;
                    }
                }
            }
            Ok(Event::End(ref e)) => match e.name().as_ref() {
                b"packet" => return Ok(Some(packet)),
                b"proto" => protoname = None,
                _ => (),
            },

            Ok(Event::Eof) => {
                return Ok(None);
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
            Ok(_) => {}
        }
    }
}

/// Main parser function used to decode XML output from tshark
pub(crate) fn parse_xml<B: BufRead>(
    xml_reader: &mut quick_xml::Reader<B>,
    filters: &[String],
) -> Result<Option<Packet>> {
    let mut buf = vec![];
    let mut packet = Packet::new();

    let mut protoname = None;

    // tshark pdml is something like : (default mode)
    //
    // <!-- You can find pdml2html.xsl in /usr/share/wireshark or at https://gitlab.com/wireshark/wireshark/-/raw/master/pdml2html.xsl. -->
    // <pdml version="0" creator="wireshark/4.0.6" time="Sat Oct  7 09:51:54 2023" capture_file="src/test.pcap">
    // <packet>
    //   <proto name="geninfo" pos="0" showname="General information" size="28">
    //     <field name="num" pos="0" show="1" showname="Number" value="1" size="28"/>
    //   </proto>
    //   <proto name="frame" pos="0" showname="General information" size="28">
    //   ...
    //
    // or, if using "whitelist" with -e option
    //
    // <pdml version="0" creator="wireshark/4.0.6" time="Sat Oct  7 09:51:54 2023" capture_file="src/test.pcap">
    // <packet>
    //   <proto name="geninfo" pos="0" showname="General information" size="28">
    //     <field name="num" pos="0" show="1" showname="Number" value="1" size="28"/>
    // </proto>
    // <field name="num" pos="0" show="1" showname="Number" value="1" size="28"/>
    // ...

    /// Create a new layer if required and add metadata to the given packet.
    fn _add_metadata(packet: &mut Packet, metadata: Metadata) -> Result<()> {
        // Create a new layer if the field's protocol does not exist yet as a layer.
        if let Some(proto) = metadata.name().split('.').next() {
            packet.push_if_not_exist(proto.to_owned());
        }

        if let Some(layer) = packet.last_layer_mut() {
            layer.add(metadata);
        } else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Cannot find protocol name to push a metadata",
            ));
        }

        Ok(())
    }

    loop {
        // NOTE TO SELF: The next thing is probably to make an asyc version of xml_reader. So it would ue the read_event_into_async method.
        match xml_reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                // Here we have "packet" and "proto" and sometimes "field" tokens. Only "proto" and "field" are interesting today.
                if b"proto" == e.name().as_ref() {
                    let proto = rtshark_attr_by_name(e, b"name")?;
                    protoname = Some(proto.to_owned());

                    // If we face a new protocol, add it in the packet layers stack.
                    if !ignored_protocols(proto.as_str()) {
                        packet.push(proto);
                    }
                }

                // There are cases where fields are mapped in fields. So check if there is any parent field and extract its metadata.
                if b"field" == e.name().as_ref() {
                    if let Some(metadata) = rtshark_build_metadata(e, filters)? {
                        _add_metadata(&mut packet, metadata)?;
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                // Here we should not have anything else than "field" but do a test anyway.
                if b"field" == e.name().as_ref() {
                    // Here we have two cases : with or without encapsuling "proto"
                    // We have a protocol if "whitelist" mode is disabled.
                    // Protocol "geninfo" is always here.
                    if let Some(name) = protoname.as_ref() {
                        if name == "geninfo" {
                            // Put geninfo metadata in packet's object (timestamp ...).
                            geninfo_metadata(e, &mut packet)?;
                        } else if let Some(metadata) = rtshark_build_metadata(e, filters)? {
                            // Some dissectors place field items at the top level instead
                            // of inside a protocol. In these cases, in the PDML output the
                            // field items are placed inside a fake "<proto>" element named
                            // "fake-field-wrapper" in order to maximize compliance.
                            // See https://github.com/wireshark/wireshark/blob/master/doc/README.xml-output
                            //
                            // An example is "tcp.reassembled". We should try to add these
                            // items to the correct layer so that they are accessible.
                            if name == "fake-field-wrapper" {
                                let proto_from_name =
                                    metadata.name().split('.').next().unwrap_or("");
                                let proto_layer = packet
                                    .last_layer_mut()
                                    .filter(|layer| layer.name() == proto_from_name);
                                if let Some(layer) = proto_layer {
                                    layer.add(metadata);
                                }
                            } else {
                                // We can unwrap because we must have a layer : it was pushed in Event::Start
                                packet.last_layer_mut().unwrap().add(metadata);
                            }
                        }
                    } else if let Some(metadata) = rtshark_build_metadata(e, filters)? {
                        _add_metadata(&mut packet, metadata)?;
                    }
                }
            }
            Ok(Event::End(ref e)) => match e.name().as_ref() {
                b"packet" => return Ok(Some(packet)),
                b"proto" => protoname = None,
                _ => (),
            },

            Ok(Event::Eof) => {
                return Ok(None);
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
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use crate::xml::parse_xml;

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

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers().len(), 1);
        for layer in pkt.layers() {
            for m in layer.iter() {
                assert!(m.name().eq("frame.time"));
                assert!(m.value().eq("test time"));
                assert_eq!(m.display(), Some("test time display"));
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

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers().len(), 1);
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

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers().len(), 1);
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

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers().len(), 1);
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

        let msg = parse_xml(&mut reader, &[]);

        match msg {
            Err(_) => (),
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn test_parse_all_value_fields_available() {
        // Issue #1 : uses pyshark-like algorithm to display the best 'value' for this field
        // https://github.com/KimiNewt/pyshark/blob/master/src/pyshark/packet/fields.py#L14
        // try first "show", then "value", finally "showname"

        let xml = r#"
        <pdml>
         <packet>
          <proto name="icmp">
           <field name="data" show="data is aa" value="0a" showname="data: a0"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let pkt = parse_xml(&mut reader, &[]).unwrap().unwrap();

        let icmp = pkt.layer_name("icmp").unwrap();
        let data = icmp.metadata("data").unwrap();
        assert!(data.value().eq("data is aa"));
        assert!(data.raw_value().eq("0a"));
        assert_eq!(data.display(), Some("data: a0"));
    }

    #[test]
    fn test_parse_missing_show_attribute() {
        // Issue #1 : uses pyshark-like algorithm to display the best 'value' for this field
        // https://github.com/KimiNewt/pyshark/blob/master/src/pyshark/packet/fields.py#L14
        // try first "show", then "value", finally "showname"

        let xml = r#"
        <pdml>
         <packet>
          <proto name="icmp">
           <field name="data" value="0a" showname="data: a0"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let pkt = parse_xml(&mut reader, &[]).unwrap().unwrap();

        let icmp = pkt.layer_name("icmp").unwrap();
        let data = icmp.metadata("data").unwrap();
        assert!(data.value().eq("0a"));
        assert!(data.raw_value() == data.value());
    }

    #[test]
    fn test_parse_missing_show_and_value_attributes() {
        // Issue #1 : uses pyshark-like algorithm to display the best 'value' for this field
        // https://github.com/KimiNewt/pyshark/blob/master/src/pyshark/packet/fields.py#L14
        // try first "show", then "value", finally "showname"

        let xml = r#"
        <pdml>
         <packet>
          <proto name="icmp">
           <field name="data" showname="data: a0"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let pkt = parse_xml(&mut reader, &[]).unwrap().unwrap();

        let icmp = pkt.layer_name("icmp").unwrap();
        let data = icmp.metadata("data").unwrap();
        assert!(data.value().eq("data: a0"));
        assert!(data.raw_value() == data.value());
    }

    #[test]
    fn test_parse_missing_any_show() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="frame">
          <field name="frame.time" pos="0" size="0"/>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));

        let msg = parse_xml(&mut reader, &[]);
        match msg {
            Err(_) => (),
            _ => panic!("invalid result"),
        }
    }

    const XML_TCP: &str = r#"
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

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers().len(), 3);

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

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers().len(), 3);

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

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers().len(), 3);

        assert!(pkt.layer_index(0).unwrap().name().eq("frame"));
        assert!(pkt.layer_index(1).unwrap().name().eq("ip"));
        assert!(pkt.layer_index(2).unwrap().name().eq("tcp"));

        assert!(pkt.layer_index(3).is_none());
    }

    #[test]
    fn test_access_layer_name() {
        let mut reader = quick_xml::Reader::from_reader(BufReader::new(XML_TCP.as_bytes()));

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers().len(), 3);

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

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
            _ => panic!("invalid Output type"),
        };

        assert_eq!(pkt.layers().len(), 4);

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

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
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

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
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

        let msg = parse_xml(&mut reader, &[]).unwrap();
        let pkt = match msg {
            Some(p) => p,
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

        let msg = parse_xml(&mut reader, &["ip.src".to_string()]).unwrap();
        let pkt = match msg {
            Some(p) => p,
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
        match parse_xml(&mut reader, &[]).unwrap() {
            Some(p) => assert!(p.layer_name("tcp").is_some()),
            _ => panic!("invalid Output type"),
        }
        match parse_xml(&mut reader, &[]).unwrap() {
            Some(p) => assert!(p.layer_name("udp").is_some()),
            _ => panic!("invalid Output type"),
        }
        match parse_xml(&mut reader, &[]).unwrap() {
            Some(p) => assert!(p.layer_name("igmp").is_some()),
            _ => panic!("invalid Output type"),
        }
        match parse_xml(&mut reader, &[]).unwrap() {
            None => (),
            _ => panic!("invalid Output type"),
        }
    }

    #[test]
    fn test_rtshark_field_in_field() {
        let xml = r#"
        <pdml>
         <packet>
          <proto name="btcommon">
            <field name="btcommon.eir_ad.entry.data" showname="Data: <data>" size="8" pos="39" show="<some data>" value="<some data>">
              <field name="_ws.expert" showname="Expert Info (Note/Undecoded): Undecoded" size="0" pos="39">
                <field name="btcommon.eir_ad.undecoded" showname="Undecoded" size="0" pos="0" show="" value=""/>
                <field name="_ws.expert.message" showname="Message: Undecoded" hide="yes" size="0" pos="0" show="Undecoded"/>
                <field name="_ws.expert.severity" showname="Severity level: Note" size="0" pos="0" show="4194304"/>
                <field name="_ws.expert.group" showname="Group: Undecoded" size="0" pos="0" show="83886080"/>
              </field>
            </field>
          </proto>
         </packet>
        </pdml>"#;

        let mut reader = quick_xml::Reader::from_reader(BufReader::new(xml.as_bytes()));
        match parse_xml(&mut reader, &[]).unwrap() {
            Some(p) => match p.layer_name("btcommon") {
                Some(layer) => {
                    layer
                        .metadata("btcommon.eir_ad.entry.data")
                        .unwrap_or_else(|| panic!("Missing btcommon.eir_ad.entry.data"));

                    layer
                        .metadata("btcommon.eir_ad.undecoded")
                        .unwrap_or_else(|| panic!("Missing btcommon.eir_ad.undecoded"));
                }
                None => panic!("missing protocol"),
            },
            _ => panic!("invalid Output type"),
        }
    }
}
