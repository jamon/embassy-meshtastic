#![no_std]
#![no_main]

use core::u32;

use defmt::*;
use embassy_executor::Spawner;
use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
use embassy_nrf::{bind_interrupts, peripherals, rng, spim};
use embassy_time::Delay;
use embedded_hal_bus::spi::ExclusiveDevice;
use femtopb::Message as _;
use lora_phy::iv::GenericSx126xInterfaceVariant;
use lora_phy::sx126x::{Sx1262, Sx126x, Sx126xVariant, TcxoCtrlVoltage};
use lora_phy::{mod_params::*, sx126x};
use lora_phy::{LoRa, RxMode};
use meshtastic_crypto::header::MeshtasticHeaderFlags;
use {defmt_rtt as _, panic_probe as _};

use meshtastic_crypto::{decrypt_meshtastic_packet, encrypt_meshtastic_packet, MeshtasticHeader};
use meshtastic_protobufs::meshtastic::{
    Data, NeighborInfo, PortNum, Position, RouteDiscovery, Routing, Telemetry, User,
};

#[derive(defmt::Format)]
enum DecodedPacket<'a> {
    Telemetry(Telemetry<'a>),
    NodeInfo(User<'a>),
    Position(Position<'a>),
    NeighborInfo(NeighborInfo<'a>),
    TextMessage(&'a str),
    Routing(Routing<'a>),
    RouteDiscovery(RouteDiscovery<'a>),
    Unknown(femtopb::EnumValue<PortNum>),
    Other(femtopb::EnumValue<PortNum>),
    TelemetryDecodeError,
    NodeInfoDecodeError,
    PositionDecodeError,
    NeighborInfoDecodeError,
    TextMessageDecodeError,
    RoutingDecodeError,
    RouteDiscoveryDecodeError,
}

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
});

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());

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
    led_red.set_high();

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

    let mut tx_pkt_params = {
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

                    // Single log statement for all packet types
                    info!(
                        "\n{} - RSSI: {}, SNR: {}\n    {:?}",
                        header, rssi, snr, decoded_packet
                    );
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
