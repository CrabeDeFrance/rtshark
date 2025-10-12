use crate::layer::Layer;

/// The [Packet] object represents a network packet, a formatted unit of data carried by a packet-switched network. It may contain multiple [Layer].
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Packet {
    /// Stack of layers for a packet
    layers: Vec<Layer>,
    /// Packet capture timestamp --- the number of non-leap-microseconds since
    /// January 1, 1970 UTC
    timestamp_micros: Option<i64>,
}

impl Packet {
    /// Creates a new empty layer. This function is useless for most applications.
    /// # Examples
    ///
    /// ```
    /// let packet = rtshark::Packet::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns this packet's capture time as the number of non-leap-microseconds since
    /// January 1, 1970 UTC.
    pub fn timestamp_micros(&self) -> Option<i64> {
        self.timestamp_micros
    }

    /// Set timestamp_micros, from Tshark output.
    pub(crate) fn timestamp_micros_mut(&mut self) -> &mut Option<i64> {
        &mut self.timestamp_micros
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

    /// Push a new layer at the end of the layer stack if the given layer does not exist yet.
    pub fn push_if_not_exist(&mut self, name: String) {
        if let Some(last_layer) = self.last_layer_mut() {
            // ignore the layer if it already exists
            if last_layer.name().eq(&name) {
                return;
            }
        }

        self.push(name);
    }

    /// Get the last layer as mutable reference. It is used to push incoming metadata in the current packet.
    pub(crate) fn last_layer_mut(&mut self) -> Option<&mut Layer> {
        self.layers.last_mut()
    }

    /// Get the layer for the required index. Indexes start at 0.
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
        self.layers.iter().find(|&layer| layer.name().eq(name))
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

    /// Return the list of [Layer] for this packet.
    pub fn layers(&self) -> &Vec<Layer> {
        &self.layers
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
#[cfg(test)]
mod tests {}
