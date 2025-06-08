use heapless::String;
use femtopb;
use defmt;

/// Simplified User struct mimicking UserLite with heapless strings
/// Only contains essential fields needed for node identification
#[derive(defmt::Format, Clone, Debug)]
pub struct User {
    pub long_name: String<40>,  // Max 40 characters for long name
    pub short_name: String<4>,  // Max 4 characters for short name
    pub hw_model: femtopb::EnumValue<meshtastic_protobufs::meshtastic::HardwareModel>,
    pub role: femtopb::EnumValue<meshtastic_protobufs::meshtastic::config::device_config::Role>,
    pub is_licensed: bool,
}

/// Simplified Position struct mimicking PositionLite
/// Only contains essential location data
#[derive(defmt::Format, Clone, Debug)]
pub struct Position {
    pub latitude_i: i32,    // latitude in 1e-7 degrees
    pub longitude_i: i32,   // longitude in 1e-7 degrees
    pub altitude: i32,      // altitude in meters
    pub time: u32,          // Unix timestamp
    pub location_source: femtopb::EnumValue<meshtastic_protobufs::meshtastic::position::LocSource>,
}

/// Simplified device metrics for telemetry data
#[derive(defmt::Format, Clone, Debug)]
pub struct DeviceMetrics {
    pub battery_level: u32,     // Battery percentage (0-100)
    pub voltage: f32,           // Battery voltage
    pub channel_utilization: f32, // Channel utilization percentage
    pub air_util_tx: f32,       // Airtime utilization for transmit
    pub uptime_seconds: u32,    // Device uptime in seconds
}

/// Simplified NodeInfo struct
#[derive(defmt::Format, Clone, Debug)]
pub struct NodeInfo {
    pub num: u32,               // Node number (source address)
    pub user: Option<User>,
    pub position: Option<Position>,
    pub snr: f32,               // Signal-to-noise ratio
    pub last_heard: u32,        // Unix timestamp of last message
    pub device_metrics: Option<DeviceMetrics>,
}

/// Node database containing up to 50 nodes
#[derive(defmt::Format, Clone, Debug)]
pub struct NodeDatabase {
    pub nodes: [Option<NodeInfo>; 50], // Array of up to 50 nodes
    pub node_count: usize,      // Current number of active nodes
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
    
    /// Convert from protobuf UserLite to our custom User
    pub fn from_protobuf_lite(pb_user: &meshtastic_protobufs::meshtastic::UserLite) -> Self {
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
    
    /// Convert from protobuf PositionLite to our custom Position
    pub fn from_protobuf_lite(pb_pos: &meshtastic_protobufs::meshtastic::PositionLite) -> Self {
        Self {
            latitude_i: pb_pos.latitude_i,
            longitude_i: pb_pos.longitude_i,
            altitude: pb_pos.altitude,
            time: pb_pos.time,
            location_source: pb_pos.location_source,
        }
    }
}

// Conversion methods for DeviceMetrics
impl DeviceMetrics {
    /// Convert from protobuf Telemetry to our custom DeviceMetrics
    pub fn from_protobuf_telemetry(pb_tel: &meshtastic_protobufs::meshtastic::Telemetry) -> Option<Self> {
        if let Some(device_metrics) = &pb_tel.variant {
            if let meshtastic_protobufs::meshtastic::telemetry::Variant::DeviceMetrics(dm) = device_metrics {
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
    pub fn from_protobuf(pb_node: &meshtastic_protobufs::meshtastic::NodeInfo, source_addr: u32) -> Self {
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
        for existing_node in &mut self.nodes {
            if let Some(existing) = existing_node {
                if existing.num == node_info.num {
                    // Log the before state
                    defmt::info!("Updating existing node {}:", node_info.num);
                    defmt::info!("  Before: {:?}", existing);
                    
                    // Update existing node
                    *existing = node_info;
                    
                    // Log the after state
                    defmt::info!("  After: {:?}", existing);
                    return;
                }
            }
        }
        
        // Add new node if there's space
        for slot in &mut self.nodes {
            if slot.is_none() {
                defmt::info!("Adding new node {}:", node_info.num);
                defmt::info!("  New node: {:?}", node_info);
                
                *slot = Some(node_info);
                self.node_count += 1;
                return;
            }
        }
        
        // If we reach here, the database is full
        defmt::warn!("Database is full, cannot add node {}", node_info.num);
        // Could implement LRU eviction here if needed
    }
      /// Update telemetry data for a specific node
    pub fn update_node_telemetry(&mut self, node_num: u32, device_metrics: DeviceMetrics) {
        for node in &mut self.nodes {
            if let Some(existing) = node {
                if existing.num == node_num {
                    defmt::info!("Updating telemetry for node {}:", node_num);
                    defmt::info!("  Before: metrics = {:?}", existing.device_metrics);
                    
                    existing.device_metrics = Some(device_metrics);
                    
                    defmt::info!("  After: metrics = {:?}", existing.device_metrics);
                    return;
                }
            }
        }
        defmt::warn!("Node {} not found for telemetry update", node_num);
    }
      /// Update SNR and last heard timestamp for a node
    pub fn update_node_signal(&mut self, node_num: u32, snr: f32, last_heard: u32) {
        for node in &mut self.nodes {
            if let Some(existing) = node {
                if existing.num == node_num {
                    defmt::info!("Updating signal info for node {}:", node_num);
                    defmt::info!("  Before: SNR = {}, last_heard = {}", existing.snr, existing.last_heard);
                    
                    existing.snr = snr;
                    existing.last_heard = last_heard;
                    
                    defmt::info!("  After: SNR = {}, last_heard = {}", existing.snr, existing.last_heard);
                    return;
                }
            }
        }
        defmt::warn!("Node {} not found for signal update", node_num);
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
      /// Get all active nodes
    pub fn get_active_nodes(&self) -> impl Iterator<Item = &NodeInfo> {
        self.nodes.iter().filter_map(|n| n.as_ref())
    }
}
