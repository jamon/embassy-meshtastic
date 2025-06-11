#![no_std]
#![no_main]

use core::u32;

use crate::usb_framer::Framer;
use defmt::*;
use embassy_executor::Spawner;
use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
use embassy_nrf::{bind_interrupts, pac, peripherals, rng, spim, usb};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::pubsub::{PubSubBehavior, PubSubChannel};
use embassy_time::Delay;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embedded_hal_bus::spi::ExclusiveDevice;
use femtopb::Message as _;
use lora_phy::iv::GenericSx126xInterfaceVariant;
use lora_phy::sx126x::{Sx1262, Sx126x, Sx126xVariant, TcxoCtrlVoltage};
use lora_phy::{mod_params::*, sx126x};
use lora_phy::{LoRa, RxMode};
use static_cell::StaticCell;

use {defmt_rtt as _, panic_probe as _};

use embassy_futures::join::join;
use embassy_futures::select::{select, Either};
use embassy_nrf::usb::vbus_detect::{HardwareVbusDetect, VbusDetect};
use embassy_nrf::usb::{Driver, Instance};
use embassy_usb::driver::EndpointError;
use embassy_usb::{Builder, Config};

use meshtassy_net::header::HeaderFlags;
use meshtassy_net::key::ChannelKey;
use meshtassy_net::{DecodedPacket, Decrypted, Encrypted, Header, Packet};
use meshtastic_protobufs::meshtastic::{Data, FromRadio, MyNodeInfo, PortNum, ToRadio, NodeInfo, User};
mod usb_framer;

static PACKET_CHANNEL: PubSubChannel<CriticalSectionRawMutex, DecodedPacket, 8, 8, 1> =
    PubSubChannel::<CriticalSectionRawMutex, DecodedPacket, 8, 8, 1>::new();

static NODE_DATABASE: Mutex<
    CriticalSectionRawMutex,
    Option<meshtassy_net::node_database::NodeDatabase>,
> = Mutex::new(None);

// USB static allocations for Embassy's Forever pattern
static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
static MSOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
static STATE: StaticCell<State> = StaticCell::new();

// Meshtastic LoRa parameters
const LORA_PREAMBLE_LENGTH: u16 = 16;
const LORA_SYNCWORD: u8 = 0x2B;

// Meshtastic US Default Frequency
const LORA_FREQUENCY_IN_HZ: u32 = 906_875_000;

// Meshtastic LongFast LoRa parameters
const LORA_SF: SpreadingFactor = SpreadingFactor::_11;
const LORA_BANDWIDTH: Bandwidth = Bandwidth::_250KHz;
const LORA_CODINGRATE: CodingRate = CodingRate::_4_5;

bind_interrupts!(struct Irqs {
    TWISPI0 => spim::InterruptHandler<peripherals::TWISPI0>;
    RNG => rng::InterruptHandler<peripherals::RNG>;
    USBD => usb::InterruptHandler<peripherals::USBD>;
    CLOCK_POWER => usb::vbus_detect::InterruptHandler;
});

// This example task processes incoming packets from the Meshtastic radio.
// It subscribes to the PACKET_CHANNEL and handles each packet as it arrives.
#[embassy_executor::task]
async fn packet_processor_task() {
    info!("Starting packet processor task");
    let mut subscriber = PACKET_CHANNEL.subscriber().unwrap();
    loop {
        let wait_result = subscriber.next_message().await;
        let packet = match wait_result {
            embassy_sync::pubsub::WaitResult::Message(msg) => msg,
            embassy_sync::pubsub::WaitResult::Lagged(_) => {
                info!("Packet processor lagged, continuing...");
                continue;
            }
        }; // Process the received packet

        // Add or update the node in the database using the packet
        let mut db_guard = NODE_DATABASE.lock().await;
        if let Some(ref mut db) = *db_guard {
            let _success = db.add_or_update_node_from_packet(&packet);
        }
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());

    // USB
    info!("Enabling ext hfosc...");
    pac::CLOCK.tasks_hfclkstart().write_value(1);
    while pac::CLOCK.events_hfclkstarted().read() != 1 {}
    info!("Ext hfosc enabled");
    let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

    let mut config = Config::new(0xc0de, 0xcafe);
    config.manufacturer = Some("Embassy");
    config.product = Some("USB-serial example");
    config.serial_number = Some("12345678");
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    // Use static allocations for USB descriptors and buffers
    let config_descriptor = CONFIG_DESCRIPTOR.init([0; 256]);
    let bos_descriptor = BOS_DESCRIPTOR.init([0; 256]);
    let msos_descriptor = MSOS_DESCRIPTOR.init([0; 256]);
    let control_buf = CONTROL_BUF.init([0; 64]);
    let state = STATE.init(State::new());

    let mut builder = Builder::new(
        driver,
        config,
        config_descriptor,
        bos_descriptor,
        msos_descriptor,
        control_buf,
    );

    let cdc = CdcAcmClass::new(&mut builder, state, 64);
    let usb = builder.build();

    let nss = Output::new(p.P0_04, Level::High, OutputDrive::Standard);
    let reset = Output::new(p.P0_28, Level::High, OutputDrive::Standard);
    let dio1 = Input::new(p.P0_03, Pull::Down);
    let busy = Input::new(p.P0_29, Pull::None);

    let mut spi_config = spim::Config::default();
    spi_config.frequency = spim::Frequency::M16;
    let spi_sck = p.P1_13;
    let spi_miso = p.P1_14;
    let spi_mosi = p.P1_15;
    let spim = spim::Spim::new(p.TWISPI0, Irqs, spi_sck, spi_miso, spi_mosi, spi_config);
    let spi = ExclusiveDevice::new(spim, nss, Delay);

    // are we configured to use DIO2 as RF switch?  (This should be true for Sx1262)
    info!("Use dio2 as RFSwitch? {:?}", Sx1262.use_dio2_as_rfswitch());

    let config = sx126x::Config {
        chip: Sx1262,
        tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V7),
        use_dcdc: true,
        rx_boost: true,
    };

    let iv = GenericSx126xInterfaceVariant::new(reset, dio1, busy, None, None).unwrap();
    let radio = Sx126x::new(spi, iv, config);

    let mut lora = LoRa::with_syncword(radio, LORA_SYNCWORD, Delay)
        .await
        .unwrap();

    let mut led_red = Output::new(p.P0_26, Level::Low, OutputDrive::Standard);
    let mut led_green = Output::new(p.P0_30, Level::Low, OutputDrive::Standard);
    let mut led_blue = Output::new(p.P0_06, Level::Low, OutputDrive::Standard);
    led_green.set_high();
    led_blue.set_high();
    led_red.set_high(); // Spawn the packet processor task
    spawner.spawn(packet_processor_task()).unwrap();

    // Spawn the USB serial task
    spawner.spawn(usb_serial_task(usb, cdc)).unwrap();

    // Initialize the node databases
    initialize_node_database().await;

    info!(
        "Starting Meshtastic Radio on frequency {} Hz with syncword 0x{:02X}",
        LORA_FREQUENCY_IN_HZ, LORA_SYNCWORD
    );

    let mut receiving_buffer = [0u8; 256];

    let mdltn_params = {
        match lora.create_modulation_params(
            LORA_SF,
            LORA_BANDWIDTH,
            LORA_CODINGRATE,
            LORA_FREQUENCY_IN_HZ,
        ) {
            Ok(mp) => mp,
            Err(err) => {
                info!("Radio error = {}", err);
                return;
            }
        }
    };

    let rx_pkt_params = {
        match lora.create_rx_packet_params(
            LORA_PREAMBLE_LENGTH,
            false,
            receiving_buffer.len() as u8,
            true,
            false,
            &mdltn_params,
        ) {
            Ok(pp) => pp,
            Err(err) => {
                info!("Radio error = {}", err);
                return;
            }
        }
    };

    let _tx_pkt_params = {
        match lora.create_tx_packet_params(LORA_PREAMBLE_LENGTH, false, true, false, &mdltn_params)
        {
            Ok(pp) => pp,
            Err(err) => {
                info!("Radio error = {}", err);
                return;
            }
        }
    };
    let mut rng = embassy_nrf::rng::Rng::new(p.RNG, Irqs);
    let mut bytes = [0u8; 4];
    rng.blocking_fill_bytes(&mut bytes);
    let tx_packet_id = u32::from_le_bytes(bytes); // Create the transmission header
    let tx_header = Header {
        source: 0xDEADBEEF,
        destination: 0xFFFFFFFF,
        packet_id: tx_packet_id,
        flags: HeaderFlags {
            hop_limit: 7,
            hop_start: 7,
            want_ack: false,
            via_mqtt: false,
        },
        channel_hash: 0x08, // calculate this at some point
        next_hop: 0x00,
        relay_node: 0x00,
    };

    info!("TX Header: {}", tx_header);

    // Create and send a test message
    let mut tx_buffer = [0u8; 256];
    if let Some(packet_len) =
        create_text_message_packet(&tx_header, "Hello, world!", &[0x01u8], 1, &mut tx_buffer)
    {
        info!("Created message packet with length: {}", packet_len);

        // Test our packet decoding by processing it through handle_received_packet
        info!("Testing packet decoding with our created packet:");
        handle_received_packet(
            &tx_buffer, packet_len, 10,  // Mock SNR value
            -50, // Mock RSSI value
        );

        // match lora
        //     .prepare_for_tx(
        //         &mdltn_params,
        //         &mut tx_pkt_params,
        //         packet_len as i32,
        //         &tx_buffer[..packet_len],
        //     )
        //     .await
        // {
        //     Ok(()) => {
        //         info!("Radio prepared for TX");
        //         match lora.tx().await {
        //             Ok(()) => info!("TX DONE - Packet transmitted successfully!"),
        //             Err(err) => info!("Radio TX error: {}", err),
        //         }
        //     }
        //     Err(err) => info!("Radio prepare_for_tx error: {}", err),
        // }
    } else {
        info!("Failed to create message packet");
    }

    // RX
    match lora
        .prepare_for_rx(RxMode::Continuous, &mdltn_params, &rx_pkt_params)
        .await
    {
        Ok(()) => {}
        Err(err) => {
            info!("Radio error = {}", err);
            return;
        }
    };

    loop {
        receiving_buffer.fill(0);

        match lora.rx(&rx_pkt_params, &mut receiving_buffer).await {
            Ok((received_len, rx_pkt_status)) => {
                trace!("rx successful, len = {}, {}", received_len, rx_pkt_status);

                let received_len = received_len as usize;
                trace!("Received packet: {:02X}", &receiving_buffer[..received_len]); // decode header
                let _header = Header::from_bytes(&receiving_buffer[..16]).unwrap();
                handle_received_packet(
                    &receiving_buffer,
                    received_len,
                    rx_pkt_status.snr,
                    rx_pkt_status.rssi,
                );
            }
            Err(err) => info!("rx unsuccessful = {}", err),
        }
    }
}

fn log_packet_info(
    header: &Header,
    node_info: Option<&meshtassy_net::node_database::NodeInfo>,
    rssi: i16,
    snr: i16,
    port_name: &str,
) {
    match node_info {
        Some(source) => {
            info!(
                "\n{} ({:?}) - RSSI: {}, SNR: {} - {}",
                header, source, rssi, snr, port_name
            );
        }
        None => {
            info!(
                "\n{} - RSSI: {}, SNR: {} - {}",
                header, rssi, snr, port_name
            );
        }
    }
}

fn handle_received_packet(receiving_buffer: &[u8], received_len: usize, snr: i16, rssi: i16) {
    // Create channel key from raw bytes (1-byte key with default key + LSB replacement)
    // @TODO need to replace this with a proper key management system
    let Some(key) = ChannelKey::from_bytes(&[0x01; 1], 1) else {
        error!("✗ Failed to create channel key");
        return;
    };
    trace!("✓ Successfully created channel key for decryption");

    info!("=== Processing received packet ===");
    info!(
        "Received {} bytes, SNR: {}, RSSI: {}",
        received_len, snr, rssi
    );
    trace!("Raw packet: {:02X}", &receiving_buffer[..received_len]);

    // High Level overview of packet processing:
    // 1. Packet::<Encrypted>::from_bytes(buffer)  => Packet<Encrypted>
    // 2. .decrypt(&ChannelKey)                    => Packet<Decrypted>
    // 3. .decode()                                => DecodedPacket
    // the decoded packet is equivalent to the `Data` protobuf message, but also has the header, rssi, and snr fields

    // 1. Create encrypted packet from received bytes
    let Some(encrypted_pkt) =
        Packet::<Encrypted>::from_bytes(&receiving_buffer[..received_len], rssi as i8, snr as i8)
    else {
        warn!("✗ Failed to parse encrypted packet from bytes");
        return;
    };
    trace!(
        "✓ Successfully parsed encrypted packet: {:?}",
        encrypted_pkt
    );

    // 2. Decrypt the packet
    let Ok(decrypted_pkt) = encrypted_pkt.decrypt(&key) else {
        warn!("✗ Failed to decrypt packet");
        return;
    };
    trace!("✓ Successfully decrypted packet: {:?}", decrypted_pkt);

    // 3. Try to decode the packet into structured data
    let Ok(decoded_pkt) = decrypted_pkt.decode() else {
        warn!("✗ Failed to decode packet to structured data");
        return;
    };
    trace!(
        "✓ Successfully decoded packet to structured data {:?}",
        decoded_pkt
    );

    // Publish the decoded packet to the channel
    PACKET_CHANNEL.publish_immediate(decoded_pkt.clone());

    // Try to get the owned data for logging
    let Ok(owned_data) = decoded_pkt.data() else {
        warn!("✗ Failed to get owned data from decoded packet");
        return;
    };

    trace!("Decoded packet data: {:?}", owned_data);
    let portnum = owned_data.portnum;

    // Log the packet based on port type
    let port_name = match portnum {
        femtopb::EnumValue::Known(PortNum::TelemetryApp) => "TELEMETRY",
        femtopb::EnumValue::Known(PortNum::NodeinfoApp) => "NODEINFO",
        femtopb::EnumValue::Known(PortNum::PositionApp) => "POSITION",
        femtopb::EnumValue::Known(PortNum::NeighborinfoApp) => "NEIGHBORINFO",
        femtopb::EnumValue::Known(PortNum::TextMessageApp) => "TEXT",
        femtopb::EnumValue::Known(PortNum::RoutingApp) => "ROUTING",
        femtopb::EnumValue::Known(PortNum::TracerouteApp) => "TRACEROUTE",
        _ => "OTHER",
    };

    // Log packet with optional node info from database
    if let Ok(db_guard) = NODE_DATABASE.try_lock() {
        let node_info = db_guard
            .as_ref()
            .and_then(|db| db.get_node(decoded_pkt.header.source));

        log_packet_info(&decoded_pkt.header, node_info, rssi, snr, port_name);
    } else {
        log_packet_info(&decoded_pkt.header, None, rssi, snr, port_name);
    }
}

// temporary function just to test sending text messages
// This will be replaced with a proper Meshtastic API call in the future
fn create_text_message_packet(
    header: &Header,
    message: &str,
    key: &[u8],
    key_len: usize,
    tx_buffer: &mut [u8; 256],
) -> Option<usize> {
    use meshtassy_net::key::ChannelKey;

    // Create the data payload
    let data = Data {
        portnum: femtopb::EnumValue::Known(PortNum::TextMessageApp),
        payload: message.as_bytes(),
        want_response: false,
        dest: 0,
        source: 0,
        request_id: 0,
        reply_id: 0,
        emoji: 0,
        bitfield: Some(0),
        unknown_fields: Default::default(),
    };

    // Encode the data payload to protobuf
    let mut payload_buffer = [0u8; 240]; // Leave room for header (256 - 16)
    let buffer_len = payload_buffer.len();
    let mut slice = payload_buffer.as_mut_slice();

    if let Err(_) = data.encode(&mut slice) {
        info!("Failed to encode data");
        return None;
    }

    let encoded_payload_len = buffer_len - slice.len();
    info!("Encoded payload length: {} bytes", encoded_payload_len);
    info!(
        "Encoded payload: {:02X}",
        &payload_buffer[..encoded_payload_len]
    );

    // Create channel key
    if let Some(channel_key) = ChannelKey::from_bytes(key, key_len) {
        // Create a decrypted packet first
        let mut full_payload = [0u8; 240];
        full_payload[..encoded_payload_len].copy_from_slice(&payload_buffer[..encoded_payload_len]);
        let _decrypted_packet = Packet::<Decrypted>::new(
            header.clone(),
            0, // rssi placeholder
            0, // snr placeholder
            full_payload,
            encoded_payload_len,
        );

        // Now we need to encrypt this. For now, let's manually do the encryption
        // Copy header to output buffer
        tx_buffer[..16].copy_from_slice(&header.to_bytes());

        // Copy payload to output buffer
        tx_buffer[16..16 + encoded_payload_len]
            .copy_from_slice(&payload_buffer[..encoded_payload_len]);
        // Generate IV from header using the correct Meshtastic protocol format
        let iv = header.create_iv();

        // Encrypt in place
        match channel_key.transform(&mut tx_buffer[16..16 + encoded_payload_len], &iv) {
            Ok(()) => {
                let total_len = 16 + encoded_payload_len;
                info!("Successfully encrypted packet! Length: {} bytes", total_len);
                info!("Encrypted packet: {:02X}", &tx_buffer[..total_len]);
                Some(total_len)
            }
            Err(_) => {
                info!("Failed to encrypt packet");
                None
            }
        }
    } else {
        info!("Failed to create channel key");
        None
    }
}

fn format_packet_for_serial<'a>(packet: &DecodedPacket, buffer: &'a mut [u8]) -> Option<&'a [u8]> {
    let mut pos = 0;

    // Helper function to append string to buffer
    let append_str = |buf: &mut [u8], position: &mut usize, s: &str| -> bool {
        let bytes = s.as_bytes();
        if *position + bytes.len() > buf.len() {
            return false;
        }
        buf[*position..*position + bytes.len()].copy_from_slice(bytes);
        *position += bytes.len();
        true
    };

    // Helper function to append hex byte
    let append_hex = |buf: &mut [u8], position: &mut usize, byte: u8| -> bool {
        if *position + 2 > buf.len() {
            return false;
        }
        let hex_chars = b"0123456789ABCDEF";
        buf[*position] = hex_chars[(byte >> 4) as usize];
        buf[*position + 1] = hex_chars[(byte & 0x0F) as usize];
        *position += 2;
        true
    };

    // Format packet information
    if !append_str(buffer, &mut pos, "{\"source\":\"0x") {
        return None;
    }
    for i in (0..4).rev() {
        if !append_hex(buffer, &mut pos, (packet.header.source >> (i * 8)) as u8) {
            return None;
        }
    }
    if !append_str(buffer, &mut pos, "\",\"dest\":\"0x") {
        return None;
    }
    for i in (0..4).rev() {
        if !append_hex(
            buffer,
            &mut pos,
            (packet.header.destination >> (i * 8)) as u8,
        ) {
            return None;
        }
    }
    if !append_str(buffer, &mut pos, "\",\"id\":\"0x") {
        return None;
    }
    for i in (0..4).rev() {
        if !append_hex(buffer, &mut pos, (packet.header.packet_id >> (i * 8)) as u8) {
            return None;
        }
    }

    // Add port type
    if !append_str(buffer, &mut pos, "\",\"port\":\"") {
        return None;
    }
    let port_str = match packet.port_num() {
        femtopb::EnumValue::Known(PortNum::TextMessageApp) => "TEXT",
        femtopb::EnumValue::Known(PortNum::TelemetryApp) => "TELEMETRY",
        femtopb::EnumValue::Known(PortNum::NodeinfoApp) => "NODEINFO",
        femtopb::EnumValue::Known(PortNum::PositionApp) => "POSITION",
        femtopb::EnumValue::Unknown(_) => "UNKNOWN",
        _ => "OTHER",
    };
    if !append_str(buffer, &mut pos, port_str) {
        return None;
    }

    if !append_str(buffer, &mut pos, "\",\"payload\":\"") {
        return None;
    }

    // Add payload as hex string from the owned data if possible
    if let Ok(owned_data) = packet.data() {
        let payload_limit = owned_data.payload_len.min(32);
        for i in 0..payload_limit {
            if !append_hex(buffer, &mut pos, owned_data.payload[i]) {
                break;
            }
        }
    }

    if !append_str(buffer, &mut pos, "\"}\r\n") {
        return None;
    }

    Some(&buffer[..pos])
}

struct Disconnected {}

impl From<EndpointError> for Disconnected {
    fn from(val: EndpointError) -> Self {
        match val {
            EndpointError::BufferOverflow => {
                info!("Buffer overflow");
                Disconnected {}
            }
            EndpointError::Disabled => Disconnected {},
        }
    }
}

// Helper function to encode and send a FromRadio packet over USB
async fn send_packet_to_usb<'d, T: Instance + 'd, P: VbusDetect + 'd>(
    class: &mut CdcAcmClass<'d, Driver<'d, T, P>>,
    from_radio_packet: &FromRadio<'_>,
    buffer: &mut [u8; 256],
) -> Result<(), Disconnected> {
    // Encode the FromRadio packet
    let Some(encoded_len) = encode_from_radio_packet(from_radio_packet, buffer) else {
        info!("✗ Failed to encode FromRadio packet");
        return Err(Disconnected {});
    };

    info!("Preparing to send FromRadio packet over USB serial...");

    // Create header with magic bytes and length
    let mut header = [0u8; 4];
    header[0] = 0x94;
    header[1] = 0xc3;
    let length_bytes = (encoded_len as u16).to_be_bytes();
    header[2] = length_bytes[0];
    header[3] = length_bytes[1];

    info!("Sending packet with header: {:02X}", &header);
    class.write_packet(&header).await?;

    // Send the encoded packet data in 64-byte chunks
    info!("Sending encoded packet: {:02X}", &buffer[..encoded_len]);
    for chunk in buffer[..encoded_len].chunks(64) {
        class.write_packet(chunk).await?;
    }

    info!("FromRadio packet sent successfully");
    Ok(())
}

async fn packet_forwarder<'d, T: Instance + 'd, P: VbusDetect + 'd>(
    class: &mut CdcAcmClass<'d, Driver<'d, T, P>>,
) -> Result<(), Disconnected> {
    let mut subscriber = PACKET_CHANNEL.subscriber().unwrap();

    // Simple state machine for packet reception
    info!("Waiting for command packet from USB serial...");

    let mut buf = [0u8; 64]; // USB packet buffer
    let mut packet_buffer = [0u8; 512]; // Buffer to store the complete packet
    let mut framer = Framer::new();

    loop {
        // Use embassy-futures select function to handle both USB reads and subscriber messages
        match select(class.read_packet(&mut buf), subscriber.next_message()).await {
            Either::First(_) => {
                // Handle USB CDC ACM read
                // @TODO two requests in single packet could fail, this should be a while loop
                if let Some(packet) = framer.push_bytes(&buf) {
                    let packet_len = packet.len().min(packet_buffer.len());
                    packet_buffer[..packet_len].copy_from_slice(&packet[..packet_len]);
                    info!(
                        "Received command packet: {:02X}",
                        &packet_buffer[..packet_len]
                    );

                    info!("Received command packet: {:02X}", packet);
                    let Ok(decoded_packet) = ToRadio::decode(&packet) else {
                        info!("✗ Failed to decode ToRadio packet");
                        return Err(Disconnected {});
                    };
                    info!(
                        "✓ Successfully decoded ToRadio packet: {:?}",
                        decoded_packet
                    );

                    // Declare encoded_buffer outside the match statement so it can be used in all arms
                    let mut encoded_buffer = [0u8; 256];

                    match decoded_packet.payload_variant {
                        Some(meshtastic_protobufs::meshtastic::to_radio::PayloadVariant::WantConfigId(config_id)) => {
                            info!("Client requesting config with ID: {}", config_id);
                            
                            let mut packet_id = 0x10000000u32;
                            
                            // Send MyNodeInfo packet
                            let from_radio_packet = create_my_node_info_packet(packet_id);
                            send_packet_to_usb(class, &from_radio_packet, &mut encoded_buffer).await?;
                            packet_id += 1;

                            // Send NodeInfo packet for our own node
                            let from_radio_packet = create_node_info_packet(packet_id);
                            send_packet_to_usb(class, &from_radio_packet, &mut encoded_buffer).await?;
                            packet_id += 1;

                            // Send NodeInfo packets for all nodes in the database
                            if let Ok(db_guard) = NODE_DATABASE.try_lock() {
                                if let Some(ref database) = *db_guard {
                                    let node_count = database.get_nodes().count();
                                    info!("Sending NodeInfo for {} nodes from database", node_count);
                                    
                                    for node in database.get_nodes() {
                                        // Skip our own node (already sent above)
                                        if node.num != 0xDEADBEEF {
                                            let from_radio_packet = create_node_info_packet_from_db(packet_id, node);
                                            send_packet_to_usb(class, &from_radio_packet, &mut encoded_buffer).await?;
                                            packet_id += 1;
                                        }
                                    }
                                }
                            }

                            // Send Config packet  
                            let from_radio_packet = create_config_packet(packet_id);
                            send_packet_to_usb(class, &from_radio_packet, &mut encoded_buffer).await?;
                            packet_id += 1;

                            // Send ModuleConfig packet
                            let from_radio_packet = create_module_config_packet(packet_id);
                            send_packet_to_usb(class, &from_radio_packet, &mut encoded_buffer).await?;
                            packet_id += 1;

                            // Send Channel packet
                            let from_radio_packet = create_channel_packet(packet_id);
                            send_packet_to_usb(class, &from_radio_packet, &mut encoded_buffer).await?;
                            packet_id += 1;

                            // Send ConfigComplete packet
                            let from_radio_packet = create_config_complete_packet(packet_id, config_id);
                            send_packet_to_usb(class, &from_radio_packet, &mut encoded_buffer).await?;

                        },
                        Some(meshtastic_protobufs::meshtastic::to_radio::PayloadVariant::Heartbeat(_)) => {
                            info!("Received heartbeat request - connection kept alive");
                            // Heartbeat requests typically don't require a response
                            // The device just acknowledges by staying awake and continuing the connection
                        },
                        _ => {
                            info!("Received unsupported ToRadio payload variant");
                            continue;
                        }
                    }
                } else {
                    info!("Invalid command packet received");
                    continue;
                }
            }
            Either::Second(wait_result) => {
                // Handle subscriber messages
                let packet = match wait_result {
                    embassy_sync::pubsub::WaitResult::Message(msg) => msg,
                    embassy_sync::pubsub::WaitResult::Lagged(_) => {
                        let lag_msg = b"[PACKET FORWARDER LAGGED]\n";
                        let _ = class.write_packet(lag_msg).await;
                        continue;
                    }
                };

                // Format packet as JSON-like string for serial output
                let mut buffer = [0u8; 512];
                let formatted = format_packet_for_serial(&packet, &mut buffer);

                if let Some(data) = formatted {
                    // Split data into 64-byte chunks to stay within USB packet limits
                    for chunk in data.chunks(64) {
                        match class.write_packet(chunk).await {
                            Ok(_) => {}
                            Err(_) => return Err(Disconnected {}),
                        }
                    }
                }
            }
        }
    }
}

// USB Serial task - handles USB CDC ACM communication
// This task will manage the USB serial interface for debugging and communication
#[embassy_executor::task]
async fn usb_serial_task(
    mut usb: embassy_usb::UsbDevice<
        'static,
        Driver<'static, peripherals::USBD, HardwareVbusDetect>,
    >,
    mut cdc: CdcAcmClass<'static, Driver<'static, peripherals::USBD, HardwareVbusDetect>>,
) {
    info!("Starting USB serial task");
    let usb_fut = usb.run();

    let packet_forwarder_fut = async {
        info!("Waiting for USB connection...");
        loop {
            cdc.wait_connection().await;
            info!("USB Connected - Starting packet forwarding");
            let _ = packet_forwarder(&mut cdc).await;
            info!("USB Disconnected - Stopping packet forwarding");
        }
    };
    join(usb_fut, packet_forwarder_fut).await;
}

async fn initialize_node_database() {
    // Initialize the node database
    let mut database_guard = NODE_DATABASE.lock().await;
    *database_guard = Some(meshtassy_net::node_database::NodeDatabase::new());
    info!("Node database initialized");
}

/// Create a FromRadio packet containing MyNodeInfo with hardcoded values
/// This demonstrates how to construct a basic MyNodeInfo packet for device identification
fn create_my_node_info_packet(packet_id: u32) -> FromRadio<'static> {
    FromRadio {
        id: packet_id,
        payload_variant: Some(
            meshtastic_protobufs::meshtastic::from_radio::PayloadVariant::MyInfo(MyNodeInfo {
                my_node_num: 0xDEADBEEF, // Hardcoded node number - should be unique device ID
                reboot_count: 42,        // Number of reboots (hardcoded for demo)
                min_app_version: 30200,  // Minimum app version (3.2.0)
                device_id: b"EMBASSY_NRF52", // 16-byte device identifier
                pio_env: "embassy_nrf52", // Platform environment name
                unknown_fields: Default::default(),
            }),
        ),
        unknown_fields: Default::default(),
    }
}

/// Create a FromRadio packet containing NodeInfo for our own node
fn create_node_info_packet(packet_id: u32) -> FromRadio<'static> {
    use meshtastic_protobufs::meshtastic::{config, HardwareModel};
    
    let user = User {
        id: "!deadbeef",  // Use the same node ID as in MyNodeInfo
        long_name: "Embassy NRF52",
        short_name: "ENRF",
        macaddr: &[],  // Deprecated field
        hw_model: femtopb::EnumValue::Known(HardwareModel::Unset),
        is_licensed: false,
        role: femtopb::EnumValue::Known(config::device_config::Role::Client),
        public_key: &[],  // No public key for now
        is_unmessagable: Some(false),
        unknown_fields: Default::default(),
    };

    let node_info = NodeInfo {
        num: 0xDEADBEEF,  // Same as MyNodeInfo.my_node_num
        user: Some(user),
        position: None,  // No position info for now
        snr: 0.0,
        last_heard: 0,  // Current timestamp would be better
        device_metrics: None,
        channel: 0,
        via_mqtt: false,
        hops_away: Some(0),  // We are 0 hops from ourselves
        is_favorite: false,
        is_ignored: false,
        is_key_manually_verified: false,
        unknown_fields: Default::default(),
    };

    FromRadio {
        id: packet_id,
        payload_variant: Some(
            meshtastic_protobufs::meshtastic::from_radio::PayloadVariant::NodeInfo(node_info),
        ),
        unknown_fields: Default::default(),
    }
}

/// Create a FromRadio packet containing ConfigComplete with hardcoded values
/// This demonstrates how to construct a basic ConfigComplete packet for device identification
fn create_config_complete_packet(packet_id: u32, config_complete_id: u32) -> FromRadio<'static> {
    FromRadio {
        id: packet_id,
        payload_variant: Some(
            meshtastic_protobufs::meshtastic::from_radio::PayloadVariant::ConfigCompleteId(
                config_complete_id,
            ),
        ),
        unknown_fields: Default::default(),
    }
}

/// Create a FromRadio packet containing Config with minimal placeholder data
fn create_config_packet(packet_id: u32) -> FromRadio<'static> {
    use meshtastic_protobufs::meshtastic::{Config, config};
    
    let device_config = config::DeviceConfig {
        role: femtopb::EnumValue::Known(config::device_config::Role::Client),
        serial_enabled: false,
        button_gpio: 0,
        buzzer_gpio: 0,
        rebroadcast_mode: femtopb::EnumValue::Known(config::device_config::RebroadcastMode::All),
        node_info_broadcast_secs: 900,
        double_tap_as_button_press: false,
        is_managed: false,
        disable_triple_click: false,
        tzdef: "",
        led_heartbeat_disabled: false,
        unknown_fields: Default::default(),
    };

    let config = Config {
        payload_variant: Some(config::PayloadVariant::Device(device_config)),
        unknown_fields: Default::default(),
    };

    FromRadio {
        id: packet_id,
        payload_variant: Some(
            meshtastic_protobufs::meshtastic::from_radio::PayloadVariant::Config(config),
        ),
        unknown_fields: Default::default(),
    }
}

/// Create a FromRadio packet containing ModuleConfig with minimal placeholder data
fn create_module_config_packet(packet_id: u32) -> FromRadio<'static> {
    use meshtastic_protobufs::meshtastic::{ModuleConfig, module_config};
    
    let mqtt_config = module_config::MqttConfig {
        enabled: false,
        address: "",
        username: "",
        password: "",
        encryption_enabled: false,
        json_enabled: false,
        tls_enabled: false,
        root: "",
        proxy_to_client_enabled: false,
        map_reporting_enabled: false,
        map_report_settings: None,
        unknown_fields: Default::default(),
    };

    let module_config = ModuleConfig {
        payload_variant: Some(module_config::PayloadVariant::Mqtt(mqtt_config)),
        unknown_fields: Default::default(),
    };

    FromRadio {
        id: packet_id,
        payload_variant: Some(
            meshtastic_protobufs::meshtastic::from_radio::PayloadVariant::ModuleConfig(module_config),
        ),
        unknown_fields: Default::default(),
    }
}

/// Create a FromRadio packet containing Channel with minimal placeholder data
fn create_channel_packet(packet_id: u32) -> FromRadio<'static> {
    use meshtastic_protobufs::meshtastic::{Channel, ChannelSettings, channel};
    
    let channel_settings = ChannelSettings {
        channel_num: 0, // Deprecated but required
        psk: &[0x01], // Default AES key
        name: "LongFast",
        id: 0,
        uplink_enabled: false,
        downlink_enabled: false,
        module_settings: None,
        unknown_fields: Default::default(),
    };

    let channel = Channel {
        index: 0,
        settings: Some(channel_settings),
        role: femtopb::EnumValue::Known(channel::Role::Primary),
        unknown_fields: Default::default(),
    };

    FromRadio {
        id: packet_id,
        payload_variant: Some(
            meshtastic_protobufs::meshtastic::from_radio::PayloadVariant::Channel(channel),
        ),
        unknown_fields: Default::default(),
    }
}

// fn create_channels_packet(packet_id: u32) -> FromRadio<'static> {
//     FromRadio {
//         id: packet_id,
//         payload_variant: Some(
//             meshtastic_protobufs::meshtastic::from_radio::PayloadVariant::Channels(
//                 meshtastic_protobufs::meshtastic::Channels {
//                     channels: vec![],
//                     unknown_fields: Default::default(),
//                 },
//             ),
//         ),
//         unknown_fields: Default::default(),
//     }
// }
/// Encode a FromRadio packet to bytes for transmission over serial/BLE/etc
fn encode_from_radio_packet(packet: &FromRadio, buffer: &mut [u8]) -> Option<usize> {
    let buffer_len = buffer.len();
    let mut slice = &mut buffer[..];

    match packet.encode(&mut slice) {
        Ok(_) => {
            let encoded_len = buffer_len - slice.len();
            Some(encoded_len)
        }
        Err(_) => None,
    }
}

/// Create a FromRadio packet containing NodeInfo from our internal node database
fn create_node_info_packet_from_db(packet_id: u32, node: &meshtassy_net::node_database::NodeInfo) -> FromRadio {
    // For now, we'll create a basic NodeInfo packet without user details
    // since the string lifetime management is complex
    let node_info = NodeInfo {
        num: node.num,
        user: None,  // TODO: Add user conversion when we solve string lifetime issues
        position: None,  // TODO: Convert position if we add position support
        snr: node.snr,
        last_heard: node.last_heard,
        device_metrics: None,  // TODO: Convert device metrics if needed
        channel: 0,
        via_mqtt: false,
        hops_away: Some(1),  // Other nodes are at least 1 hop away
        is_favorite: false,
        is_ignored: false,
        is_key_manually_verified: false,
        unknown_fields: Default::default(),
    };

    FromRadio {
        id: packet_id,
        payload_variant: Some(
            meshtastic_protobufs::meshtastic::from_radio::PayloadVariant::NodeInfo(node_info),
        ),
        unknown_fields: Default::default(),
    }
}
