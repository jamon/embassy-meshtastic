#![no_std]
#![no_main]

use core::u32;

use defmt::*;
use embassy_executor::Spawner;
use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
use embassy_nrf::twim::{self, Twim};
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
use lora_phy::{mod_params::*, sx126x, DelayNs};
use lora_phy::{LoRa, RxMode};
use static_cell::{ConstStaticCell, StaticCell};
use {defmt_rtt as _, panic_probe as _};

use embassy_futures::join::join;
use embassy_nrf::usb::vbus_detect::{HardwareVbusDetect, VbusDetect};
use embassy_nrf::usb::{Driver, Instance};
use embassy_usb::driver::EndpointError;
use embassy_usb::{Builder, Config};

use meshtassy_net::header::HeaderFlags;
use meshtassy_net::key::ChannelKey;
use meshtassy_net::{Decoded, Decrypted, Encrypted, Header, Packet};
use meshtastic_protobufs::meshtastic::{Data, PortNum};

mod environmental_telemetry;
use environmental_telemetry::EnvironmentalData;

static PACKET_CHANNEL: PubSubChannel<CriticalSectionRawMutex, Packet<Decoded>, 8, 8, 1> =
    PubSubChannel::<CriticalSectionRawMutex, Packet<Decoded>, 8, 8, 1>::new();

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
    TWISPI0 => twim::InterruptHandler<peripherals::TWISPI0>;
    TWISPI1 => spim::InterruptHandler<peripherals::TWISPI1>;
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

    let nss = Output::new(p.P1_10, Level::High, OutputDrive::Standard);
    let reset = Output::new(p.P1_06, Level::High, OutputDrive::Standard);
    let dio1 = Input::new(p.P1_15, Pull::Down);
    let busy = Input::new(p.P1_14, Pull::None);

    let mut spi_config = spim::Config::default();
    spi_config.frequency = spim::Frequency::M16;
    let spi_sck = p.P1_11;
    let spi_miso = p.P1_13;
    let spi_mosi = p.P1_12;
    let spim = spim::Spim::new(p.TWISPI1, Irqs, spi_sck, spi_miso, spi_mosi, spi_config);
    let spi = ExclusiveDevice::new(spim, nss, Delay);

    // Try initializing the I2C bus
    info!("Try initializing the RAM buffer for I2C");
    static RAM_BUFFER: ConstStaticCell<[u8; 16]> = ConstStaticCell::new([0; 16]);
    info!("Try initializing the I2C bus");
    let i2c_config = twim::Config::default();
    let mut twi = Twim::new(
        p.TWISPI0,
        Irqs,
        p.P0_13,
        p.P0_14,
        i2c_config,
        RAM_BUFFER.take(),
    );

    // Try initializing a BME
    //todo: throw this in an embassy task that eventually scans a given i2c bus
    info!("Try initializing a BME on the I2C bus");
    let bme_config = bosch_bme680::Configuration::default();
    let mut bme = bosch_bme680::AsyncBme680::new(
        twi,
        bosch_bme680::DeviceAddress::Secondary,
        Delay,
        24, // wrong initial temperature, is it in C?
    );
    bme.setup().await;
    let metrics = bme.get_metrics().await;

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
    payload: &[u8],
) {
    match node_info {
        Some(source) => {
            info!(
                "\n{} ({:?}) - RSSI: {}, SNR: {} - {}\n    Payload: {:02X}",
                header, source, rssi, snr, port_name, payload
            );
        }
        None => {
            info!(
                "\n{} - RSSI: {}, SNR: {} - {}\n    Payload: {:02X}",
                header, rssi, snr, port_name, payload
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
    info!("Raw packet: {:02X}", &receiving_buffer[..received_len]);

    // High Level overview of packet processing:
    // 1. Packet::<Encrypted>::from_bytes(buffer)  => Packet<Encrypted>
    // 2. .decrypt(&ChannelKey)                    => Packet<Decrypted>
    // 3. .decode()                                => Packet<Decoded>
    // the decoded packet is equivalent to the `Data` protobuf message, but also has the header, rssi, and snr fields

    // 1. Create encrypted packet from received bytes
    let Some(encrypted_pkt) =
        Packet::<Encrypted>::from_bytes(&receiving_buffer[..received_len], rssi as i8, snr as i8)
    else {
        warn!("✗ Failed to parse encrypted packet from bytes");
        return;
    };
    trace!("✓ Successfully parsed encrypted packet");

    // 2. Decrypt the packet
    let Ok(decrypted_pkt) = encrypted_pkt.decrypt(&key) else {
        info!("✗ Failed to decrypt packet");
        return;
    };
    info!("✓ Successfully decrypted packet!");
    trace!("Header: {:?}", decrypted_pkt.header);
    trace!(
        "Decrypted payload: {:02X}",
        decrypted_pkt.payload[..decrypted_pkt.payload_len]
    );

    // 3. Try to decode the packet into structured data
    let Ok(decoded_pkt) = decrypted_pkt.decode() else {
        info!("✗ Failed to decode packet to structured data");
        return;
    };
    trace!("✓ Successfully decoded packet to structured data");

    // Publish the decoded packet to the channel
    PACKET_CHANNEL.publish_immediate(decoded_pkt.clone());

    // Try to get the owned data for logging
    let Ok(owned_data) = decoded_pkt.data() else {
        info!("✗ Failed to get owned data from decoded packet");
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

        log_packet_info(
            &decoded_pkt.header,
            node_info,
            rssi,
            snr,
            port_name,
            &owned_data.payload[..owned_data.payload_len],
        );
    } else {
        log_packet_info(
            &decoded_pkt.header,
            None,
            rssi,
            snr,
            port_name,
            &owned_data.payload[..owned_data.payload_len],
        );
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

fn format_packet_for_serial<'a>(
    packet: &Packet<Decoded>,
    buffer: &'a mut [u8],
) -> Option<&'a [u8]> {
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
