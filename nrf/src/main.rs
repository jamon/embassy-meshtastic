#![no_std]
#![no_main]

use core::u32;

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
use embassy_nrf::usb::vbus_detect::{HardwareVbusDetect, VbusDetect};
use embassy_nrf::usb::{Driver, Instance};
use embassy_usb::driver::EndpointError;
use embassy_usb::{Builder, Config};

use meshtassy_net::header::MeshtasticHeaderFlags;
use meshtassy_net::{
    decrypt_meshtastic_packet, encrypt_meshtastic_packet, DecodedPacket, MeshtasticHeader, Packet,
};
use meshtastic_protobufs::meshtastic::{
    Data, NeighborInfo, PortNum, Position, RouteDiscovery, Routing, Telemetry, User,
};

static PACKET_CHANNEL: PubSubChannel<CriticalSectionRawMutex, Packet, 8, 8, 1> =
    PubSubChannel::<CriticalSectionRawMutex, Packet, 8, 8, 1>::new();

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
    let mut decrypted_buffer = [0u8; 240]; // 256 - 16 for header

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
            16,
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
    let tx_header = MeshtasticHeader {
        source: 0xDEADBEEF,
        destination: 0xFFFFFFFF,
        packet_id: tx_packet_id,
        flags: MeshtasticHeaderFlags {
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
            &tx_buffer,
            packet_len,
            &mut decrypted_buffer,
            &tx_header,
            -50, // Mock RSSI value
            10,  // Mock SNR value
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
                trace!("Received packet: {:02X}", &receiving_buffer[..received_len]);

                // decode header
                let header = MeshtasticHeader::from_bytes(&receiving_buffer[..16]).unwrap();

                handle_received_packet(
                    &receiving_buffer,
                    received_len,
                    &mut decrypted_buffer,
                    &header,
                    rx_pkt_status.rssi,
                    rx_pkt_status.snr,
                );
            }
            Err(err) => info!("rx unsuccessful = {}", err),
        }
    }
}

fn handle_received_packet(
    receiving_buffer: &[u8],
    received_len: usize,
    decrypted_buffer: &mut [u8],
    header: &MeshtasticHeader,
    rssi: i16,
    snr: i16,
) {
    match decrypt_meshtastic_packet(
        &receiving_buffer[..received_len],
        received_len,
        decrypted_buffer,
        &[0x01; 1],
        1, // Use 16-byte key length for AES-128
    ) {
        Some(payload_len) => {
            trace!("Header: {:02X}", &receiving_buffer[..16]);
            trace!(
                "Decrypted payload: {:02X}",
                &decrypted_buffer[..payload_len]
            );
            // Try to decode the protobuf message
            match Data::decode(&decrypted_buffer[..payload_len]) {
                Ok(mp) => {
                    trace!("Decoded packet {:?} ", mp);
                    let portnum = mp.portnum;
                    // publish the packet to the channel - probably need to handle when decryption fails better
                    let mut packet = Packet {
                        header: header.clone(),
                        port_num: portnum,
                        rssi,
                        snr,
                        payload: [0; 240],
                        payload_len: mp.payload.len(),
                    };
                    packet.payload[..mp.payload.len()].copy_from_slice(&mp.payload);
                    PACKET_CHANNEL.publish_immediate(packet);

                    // Decode into our enum
                    let decoded_packet = match portnum {
                        femtopb::EnumValue::Known(PortNum::TelemetryApp) => {
                            match Telemetry::decode(&mp.payload) {
                                Ok(telemetry) => DecodedPacket::Telemetry(telemetry),
                                Err(_) => DecodedPacket::TelemetryDecodeError,
                            }
                        }
                        femtopb::EnumValue::Known(PortNum::NodeinfoApp) => {
                            match User::decode(&mp.payload) {
                                Ok(user_info) => DecodedPacket::NodeInfo(user_info),
                                Err(_) => DecodedPacket::NodeInfoDecodeError,
                            }
                        }
                        femtopb::EnumValue::Known(PortNum::PositionApp) => {
                            match Position::decode(&mp.payload) {
                                Ok(position) => DecodedPacket::Position(position),
                                Err(_) => DecodedPacket::PositionDecodeError,
                            }
                        }
                        femtopb::EnumValue::Known(PortNum::NeighborinfoApp) => {
                            match NeighborInfo::decode(&mp.payload) {
                                Ok(neighbor_info) => DecodedPacket::NeighborInfo(neighbor_info),
                                Err(_) => DecodedPacket::NeighborInfoDecodeError,
                            }
                        }
                        femtopb::EnumValue::Known(PortNum::TextMessageApp) => {
                            match core::str::from_utf8(&mp.payload) {
                                Ok(text_message) => DecodedPacket::TextMessage(text_message),
                                Err(_) => DecodedPacket::TextMessageDecodeError,
                            }
                        }
                        femtopb::EnumValue::Known(PortNum::RoutingApp) => {
                            match Routing::decode(&mp.payload) {
                                Ok(routing) => DecodedPacket::Routing(routing),
                                Err(_) => DecodedPacket::RoutingDecodeError,
                            }
                        }
                        femtopb::EnumValue::Known(PortNum::TracerouteApp) => {
                            match RouteDiscovery::decode(&mp.payload) {
                                Ok(route_discovery) => {
                                    DecodedPacket::RouteDiscovery(route_discovery)
                                }
                                Err(_) => DecodedPacket::RouteDiscoveryDecodeError,
                            }
                        }
                        femtopb::EnumValue::Unknown(_) => DecodedPacket::Unknown(portnum),
                        _ => DecodedPacket::Other(portnum),
                    };

                    // Helper function to do logging while holding the database lock
                    let log_packet =
                        |source_opt: Option<&meshtassy_net::node_database::NodeInfo>| {
                            if let Some(source) = source_opt {
                                info!(
                                    "\n{} ({:?}) - RSSI: {}, SNR: {}\n    {:?}",
                                    header, source, rssi, snr, decoded_packet
                                );
                            } else {
                                info!(
                                    "\n{} - RSSI: {}, SNR: {}\n    {:?}",
                                    header, rssi, snr, decoded_packet
                                );
                            }
                        };

                    // Do the logging while holding the database lock to avoid cloning
                    if let Ok(db_guard) = NODE_DATABASE.try_lock() {
                        if let Some(db) = db_guard.as_ref() {
                            log_packet(db.get_node(header.source));
                        } else {
                            log_packet(None);
                        }
                    } else {
                        // If we can't get the lock, just log without source info
                        log_packet(None);
                    }
                }
                Err(err) => {
                    info!("Failed to decode protobuf: {:?}", err);
                }
            }
        }
        None => {
            info!("Failed to decrypt packet");
        }
    }
}

// temporary function just to test sending text messages
// This will be replaced with a proper Meshtastic API call in the future
fn create_text_message_packet(
    header: &MeshtasticHeader,
    message: &str,
    key: &[u8],
    key_len: usize,
    tx_buffer: &mut [u8; 256],
) -> Option<usize> {
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

    // Encrypt the packet
    let encrypted_packet_len = encrypt_meshtastic_packet(
        header,
        &payload_buffer[..encoded_payload_len],
        tx_buffer,
        key,
        key_len,
    );

    match encrypted_packet_len {
        Some(packet_len) => {
            info!(
                "Successfully encrypted packet! Length: {} bytes",
                packet_len
            );
            info!("Encrypted packet: {:02X}", &tx_buffer[..packet_len]);
            Some(packet_len)
        }
        None => {
            info!("Failed to encrypt packet");
            None
        }
    }
}

fn format_packet_for_serial<'a>(packet: &Packet, buffer: &'a mut [u8]) -> Option<&'a [u8]> {
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
    let port_str = match packet.port_num {
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

    // Add payload as hex string (limit to avoid buffer overflow)
    let payload_limit = packet.payload_len.min(32);
    for i in 0..payload_limit {
        if !append_hex(buffer, &mut pos, packet.payload[i]) {
            break;
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

async fn packet_forwarder<'d, T: Instance + 'd, P: VbusDetect + 'd>(
    class: &mut CdcAcmClass<'d, Driver<'d, T, P>>,
) -> Result<(), Disconnected> {
    let mut subscriber = PACKET_CHANNEL.subscriber().unwrap();

    loop {
        let wait_result = subscriber.next_message().await;
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
