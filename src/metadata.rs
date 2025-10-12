/// A metadata belongs to one [Layer]. It describes one particular information about a [Packet] (example: IP source address).
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Metadata {
    /// Name displayed by TShark
    name: String,
    /// Value displayed by TShark, in a human readable format
    /// It uses pyshark-like algorithm to display the best 'value' :
    /// it looks for "show" first, then "value", finally "showname"
    value: String,
    /// Value displayed by TShark, if different from human readable format
    raw_value: Option<String>,
    /// Both name and value, as displayed by thshark
    display: Option<String>,
    /// Size of this data extracted from packet header protocol, in bytes
    size: Option<u32>,
    /// Offset of this data in the packet, in bytes
    position: Option<u32>,
}

/// This is one metadata from a given layer of the packet returned by TShark application.
impl Metadata {
    /// Creates a new metadata. This function is useless for most applications.
    pub fn new(
        name: String,
        value: String,
        display: Option<String>,
        size: Option<u32>,
        position: Option<u32>,
    ) -> Metadata {
        Metadata {
            name,
            value,
            raw_value: None,
            display,
            size,
            position,
        }
    }

    /// Get the name of this metadata. The name is returned by TShark.
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), None, None, None);
    /// assert_eq!(ip_src.name(), "ip.src")
    /// ```
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Value for this metadata, displayed by TShark, in a human readable format.
    /// It uses pyshark-like algorithm to display the best 'value' :
    /// it looks for "show" first, then "value", finally "showname".
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), None, None, None);
    /// assert_eq!(ip_src.value(), "127.0.0.1")
    /// ```
    pub fn value(&self) -> &str {
        self.value.as_str()
    }

    /// Raw value for this metadata, displayed by TShark.
    ///
    /// This value is not set when using metadata whitelist filtering.
    ///
    /// When `value` is set to "show" instead of "value", "value" can still
    /// be retrieved from `raw_value`.
    pub fn raw_value(&self) -> &str {
        self.raw_value.as_ref().unwrap_or(&self.value).as_str()
    }

    /// Set "raw value", from by TShark output.
    pub(crate) fn raw_value_mut(&mut self) -> &mut Option<String> {
        &mut self.raw_value
    }

    /// Both name and value, as displayed by TShark
    ///
    /// This value is not set when using metadata whitelist filtering.
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), Some("Source: 127.0.0.1".to_string()), None, None);
    /// assert_eq!(ip_src.display(), Some("Source: 127.0.0.1"))
    /// ```
    pub fn display(&self) -> Option<&str> {
        self.display.as_deref()
    }

    /// Set "display", from by TShark output.
    pub(crate) fn display_mut(&mut self) -> &mut Option<String> {
        &mut self.display
    }

    /// Size of this data extracted from packet header protocol, in bytes
    ///
    /// This value is not set when using metadata whitelist filtering.
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), Some("Source: 127.0.0.1".to_string()), Some(4), Some(12));
    /// assert_eq!(ip_src.size(), Some(4))
    /// ```
    pub fn size(&self) -> Option<u32> {
        self.size
    }

    /// Set "size", from by TShark output.
    pub(crate) fn size_mut(&mut self) -> &mut Option<u32> {
        &mut self.size
    }

    /// Offset of this data in the packet, in bytes
    ///
    /// This value is not set when using metadata whitelist filtering.
    ///
    /// # Examples
    ///
    /// ```
    /// let ip_src = rtshark::Metadata::new("ip.src".to_string(), "127.0.0.1".to_string(), Some("Source: 127.0.0.1".to_string()), Some(4), Some(12));
    /// assert_eq!(ip_src.position(), Some(12))
    /// ```
    pub fn position(&self) -> Option<u32> {
        self.position
    }

    /// Set "position", from by TShark output.
    pub(crate) fn position_mut(&mut self) -> &mut Option<u32> {
        &mut self.position
    }
}
#[cfg(test)]
mod tests {}
