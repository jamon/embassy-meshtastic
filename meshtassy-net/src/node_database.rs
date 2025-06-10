#[cfg(feature = "defmt")]
use defmt;

use femtopb::{self, Message as _};
use heapless::String;
use meshtastic_protobufs::meshtastic::{PortNum, Telemetry};

/// Simplified User struct mimicking UserLite with heapless strings
/// Only contains essential fields needed for node identification
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct User {
    pub long_name: String<40>, // Max 40 characters for long name
    pub short_name: String<4>, // Max 4 characters for short name
    pub hw_model: femtopb::EnumValue<meshtastic_protobufs::meshtastic::HardwareModel>,
    pub role: femtopb::EnumValue<meshtastic_protobufs::meshtastic::config::device_config::Role>,
    pub is_licensed: bool,
}

/// Simplified Position struct mimicking PositionLite
/// Only contains essential location data
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Position {
    pub latitude_i: i32,  // latitude in 1e-7 degrees
    pub longitude_i: i32, // longitude in 1e-7 degrees
    pub altitude: i32,    // altitude in meters
    pub time: u32,        // Unix timestamp
    pub location_source: femtopb::EnumValue<meshtastic_protobufs::meshtastic::position::LocSource>,
}

/// Simplified device metrics for telemetry data
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceMetrics {
    pub battery_level: u32,       // Battery percentage (0-100)
    pub voltage: f32,             // Battery voltage
    pub channel_utilization: f32, // Channel utilization percentage
    pub air_util_tx: f32,         // Airtime utilization for transmit
    pub uptime_seconds: u32,      // Device uptime in seconds
}

/// Simplified NodeInfo struct
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NodeInfo {
    pub num: u32, // Node number (source address)
    pub user: Option<User>,
    pub position: Option<Position>,
    pub snr: f32,        // Signal-to-noise ratio
    pub last_heard: u32, // Unix timestamp of last message
    pub device_metrics: Option<DeviceMetrics>,
}

/// Node database containing up to 50 nodes
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NodeDatabase {
    pub nodes: [Option<NodeInfo>; 50], // Array of up to 50 nodes
    pub node_count: usize,             // Current number of active nodes
}

// Default implementations
impl Default for User {
    fn default() -> Self {
        Self {
            long_name: String::new(),
            short_name: String::new(),
            hw_model: femtopb::EnumValue::Unknown(0),
            role: femtopb::EnumValue::Unknown(0),
            is_licensed: false,
        }
    }
}

impl Default for Position {
    fn default() -> Self {
        Self {
            latitude_i: 0,
            longitude_i: 0,
            altitude: 0,
            time: 0,
            location_source: femtopb::EnumValue::Unknown(0),
        }
    }
}

impl Default for DeviceMetrics {
    fn default() -> Self {
        Self {
            battery_level: 0,
            voltage: 0.0,
            channel_utilization: 0.0,
            air_util_tx: 0.0,
            uptime_seconds: 0,
        }
    }
}

impl Default for NodeInfo {
    fn default() -> Self {
        Self {
            num: 0,
            user: None,
            position: None,
            snr: 0.0,
            last_heard: 0,
            device_metrics: None,
        }
    }
}

impl Default for NodeDatabase {
    fn default() -> Self {
        // Initialize array with None values using core::array::from_fn
        let nodes = core::array::from_fn(|_| None);
        Self {
            nodes,
            node_count: 0,
        }
    }
}

// Conversion methods for User
impl User {
    /// Convert from protobuf User to our custom User
    pub fn from_protobuf(pb_user: &meshtastic_protobufs::meshtastic::User) -> Self {
        let mut long_name = String::new();
        let mut short_name = String::new();

        // Safely convert strings with length limits
        for ch in pb_user.long_name.chars().take(40) {
            let _ = long_name.push(ch);
        }
        for ch in pb_user.short_name.chars().take(4) {
            let _ = short_name.push(ch);
        }

        Self {
            long_name,
            short_name,
            hw_model: pb_user.hw_model,
            role: pb_user.role,
            is_licensed: pb_user.is_licensed,
        }
    }
}

// Conversion methods for Position
impl Position {
    /// Convert from protobuf Position to our custom Position
    pub fn from_protobuf(pb_pos: &meshtastic_protobufs::meshtastic::Position) -> Self {
        Self {
            latitude_i: pb_pos.latitude_i.unwrap_or(0),
            longitude_i: pb_pos.longitude_i.unwrap_or(0),
            altitude: pb_pos.altitude.unwrap_or(0),
            time: pb_pos.time,
            location_source: pb_pos.location_source,
        }
    }
}

// Conversion methods for DeviceMetrics
impl DeviceMetrics {
    /// Convert from protobuf Telemetry to our custom DeviceMetrics
    pub fn from_protobuf(pb_tel: &meshtastic_protobufs::meshtastic::Telemetry) -> Option<Self> {
        if let Some(device_metrics) = &pb_tel.variant {
            if let meshtastic_protobufs::meshtastic::telemetry::Variant::DeviceMetrics(dm) =
                device_metrics
            {
                return Some(Self {
                    battery_level: dm.battery_level.unwrap_or(0),
                    voltage: dm.voltage.unwrap_or(0.0),
                    channel_utilization: dm.channel_utilization.unwrap_or(0.0),
                    air_util_tx: dm.air_util_tx.unwrap_or(0.0),
                    uptime_seconds: dm.uptime_seconds.unwrap_or(0),
                });
            }
        }
        None
    }
}

// Conversion methods for NodeInfo
impl NodeInfo {
    /// Convert from protobuf NodeInfo to our custom NodeInfo
    pub fn from_protobuf(
        pb_node: &meshtastic_protobufs::meshtastic::NodeInfo,
        source_addr: u32,
    ) -> Self {
        let user = pb_node.user.as_ref().map(User::from_protobuf);
        let position = pb_node.position.as_ref().map(Position::from_protobuf);

        Self {
            num: source_addr,
            user,
            position,
            snr: pb_node.snr,
            last_heard: pb_node.last_heard,
            device_metrics: None, // Will be updated separately from telemetry packets
        }
    }
}

// Methods for NodeDatabase
impl NodeDatabase {
    /// Initialize a new empty node database
    pub fn new() -> Self {
        Self::default()
    }
    /// Add or update a node in the database
    pub fn add_or_update_node(&mut self, node_info: NodeInfo) {
        // Look for existing node with same number
        // defmt::info!("[NODE_DATABASE] Adding or updating node {}:", node_info.num);
        for existing_node in &mut self.nodes {
            if let Some(existing) = existing_node {
                if existing.num == node_info.num {
                    // // Log the before state
                    // defmt::info!("Updating existing node {}:", node_info.num);
                    // defmt::info!("  Before: {:?}", existing);

                    // Update existing node
                    *existing = node_info;

                    // Log the after state
                    // defmt::info!("  After: {:?}", existing);
                    return;
                }
            }
        }

        // Add new node if there's space
        for slot in &mut self.nodes {
            if slot.is_none() {
                #[cfg(feature = "defmt")]
                defmt::info!("Adding new node {}: {:?}", node_info.num, node_info);

                *slot = Some(node_info);
                self.node_count += 1;
                return;
            }
        }

        // If we reach here, the database is full
        #[cfg(feature = "defmt")]
        defmt::info!("Database is full, cannot add node {}", node_info.num);
        // Could implement LRU eviction here if needed
    }
    /// Update telemetry data for a specific node
    pub fn update_node_telemetry(&mut self, node_num: u32, device_metrics: DeviceMetrics) {
        for node in &mut self.nodes {
            if let Some(existing) = node {
                if existing.num == node_num {
                    // defmt::info!("Updating telemetry for node {}:", node_num);
                    // defmt::info!("  Before: metrics = {:?}", existing.device_metrics);

                    existing.device_metrics = Some(device_metrics);

                    // defmt::info!("  After: metrics = {:?}", existing.device_metrics);
                    return;
                }
            }
        }
        #[cfg(feature = "defmt")]
        defmt::info!("Node {} not found for telemetry update", node_num);
    }
    /// Update SNR and last heard timestamp for a node
    pub fn update_node_signal(&mut self, node_num: u32, snr: f32, last_heard: u32) {
        for node in &mut self.nodes {
            if let Some(existing) = node {
                if existing.num == node_num {
                    // defmt::info!("Updating signal info for node {}:", node_num);
                    // defmt::info!(
                    //     "  Before: SNR = {}, last_heard = {}",
                    //     existing.snr,
                    //     existing.last_heard
                    // );

                    existing.snr = snr;
                    existing.last_heard = last_heard;

                    // defmt::info!(
                    //     "  After: SNR = {}, last_heard = {}",
                    //     existing.snr,
                    //     existing.last_heard
                    // );
                    return;
                }
            }
        }
        #[cfg(feature = "defmt")]
        defmt::info!("Node {} not found for signal update", node_num);
    }

    /// Get a node by its number
    pub fn get_node(&self, node_num: u32) -> Option<&NodeInfo> {
        for node in &self.nodes {
            if let Some(existing) = node {
                if existing.num == node_num {
                    return Some(existing);
                }
            }
        }
        None
    }

    /// Get user info for a specific node by its number
    pub fn get_node_user(&self, node_num: u32) -> Option<&User> {
        self.get_node(node_num)?.user.as_ref()
    }

    /// Get the short name for a specific node, or return a default if not available
    pub fn get_node_short_name(&self, node_num: u32) -> &str {
        if let Some(user) = self.get_node_user(node_num) {
            if !user.short_name.is_empty() {
                return user.short_name.as_str();
            }
        }
        "UNK" // Unknown/default short name
    }

    /// Get all active nodes
    pub fn get_nodes(&self) -> impl Iterator<Item = &NodeInfo> {
        self.nodes.iter().filter_map(|n| n.as_ref())
    }    /// Add or update a node from a received packet
    /// This method handles the packet decoding and node database update
    pub fn add_or_update_node_from_packet(
        &mut self,
        packet: &crate::DecodedPacket,
    ) -> bool {
        let node_num = packet.header.source;
        let port_num = packet.port_num();

        // Get the owned data from the decoded packet
        let owned_data = match packet.data() {
            Ok(data) => data,
            Err(_) => return false,
        };

        match port_num {
            femtopb::EnumValue::Known(PortNum::NodeinfoApp) => {
                // Decode payload as User message
                if let Ok(user_info) = meshtastic_protobufs::meshtastic::User::decode(
                    &owned_data.payload[..owned_data.payload_len],
                ) {
                    // Create a NodeInfo with the user information
                    let mut node_info = self.get_node(node_num).cloned().unwrap_or_else(|| {
                        let mut new_node = NodeInfo::default();
                        new_node.num = node_num;
                        new_node
                    });

                    // Update user info using conversion method
                    node_info.user = Some(User::from_protobuf(&user_info));

                    // Update SNR and add to database
                    node_info.snr = packet.snr as f32;
                    self.add_or_update_node(node_info);

                    #[cfg(feature = "defmt")]
                    defmt::info!("Node {} user info updated", node_num);
                    true
                } else {
                    false
                }
            }
            femtopb::EnumValue::Known(PortNum::PositionApp) => {
                if let Ok(position) = meshtastic_protobufs::meshtastic::Position::decode(
                    &owned_data.payload[..owned_data.payload_len],
                ) {
                    // Create a NodeInfo with the position information
                    let mut node_info = self.get_node(node_num).cloned().unwrap_or_else(|| {
                        let mut new_node = NodeInfo::default();
                        new_node.num = node_num;
                        new_node
                    });

                    // Update position info using conversion method
                    node_info.position = Some(Position::from_protobuf(&position));

                    // Update SNR and add to database
                    node_info.snr = packet.snr as f32;
                    self.add_or_update_node(node_info);

                    #[cfg(feature = "defmt")]
                    defmt::info!("Node {} position updated", node_num);
                    true
                } else {
                    false
                }
            }
            femtopb::EnumValue::Known(PortNum::TelemetryApp) => {
                if let Ok(telemetry) =
                    Telemetry::decode(&owned_data.payload[..owned_data.payload_len])
                {
                    // Handle telemetry data
                    if let Some(device_metrics) = DeviceMetrics::from_protobuf(&telemetry) {
                        // Update or create node with telemetry data
                        let mut node_info = self.get_node(node_num).cloned().unwrap_or_else(|| {
                            let mut new_node = NodeInfo::default();
                            new_node.num = node_num;
                            new_node
                        });

                        node_info.device_metrics = Some(device_metrics);
                        node_info.snr = packet.snr as f32;
                        self.add_or_update_node(node_info);

                        #[cfg(feature = "defmt")]
                        defmt::info!("Node {} telemetry updated", node_num);
                        true
                    } else {
                        // For other telemetry types, just update basic info
                        let mut node_info = self.get_node(node_num).cloned().unwrap_or_else(|| {
                            let mut new_node = NodeInfo::default();
                            new_node.num = node_num;
                            new_node
                        });

                        node_info.snr = packet.snr as f32;
                        self.add_or_update_node(node_info);

                        #[cfg(feature = "defmt")]
                        defmt::info!("Node {} basic info updated from telemetry", node_num);
                        true
                    }
                } else {
                    false
                }
            }
            _ => {
                // For other packet types, just update the basic info (SNR, last_heard)
                let mut node_info = self.get_node(node_num).cloned().unwrap_or_else(|| {
                    let mut new_node = NodeInfo::default();
                    new_node.num = node_num;
                    new_node
                });

                node_info.snr = packet.snr as f32;
                self.add_or_update_node(node_info);

                #[cfg(feature = "defmt")]
                defmt::info!("Node {} basic info updated (SNR: {})", node_num, packet.snr);
                true
            }
        }
    }
}
