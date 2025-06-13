//! Board-specific configurations and pin assignments
//! 
//! This module provides board-specific abstractions that isolate
//! hardware dependencies from the main application logic.

use embassy_nrf::gpio::{Input, Output};
use embassy_nrf::spim::Spim;
use embassy_nrf::{peripherals, rng, usb};
use embassy_nrf::mode::Blocking;
use embassy_time::Delay;
use embedded_hal_bus::spi::ExclusiveDevice;

// Import board-specific modules based on features
#[cfg(feature = "board-seeed-xiao-nrf52840")]
pub mod seeed_xiao_nrf52840;

/// Board-specific peripheral configuration
pub struct BoardPeripherals {
    /// LoRa radio peripherals and pins
    pub lora: LoRaPeripherals,
    /// LED outputs (optional - not all boards have LEDs)
    pub leds: Option<LedPeripherals>,
    /// USB driver
    pub usb_driver: usb::Driver<'static, peripherals::USBD, embassy_nrf::usb::vbus_detect::HardwareVbusDetect>,
    /// Random number generator
    pub rng: rng::Rng<'static, peripherals::RNG, Blocking>,
}

/// LoRa radio-related peripherals
pub struct LoRaPeripherals {
    /// SPI device for communicating with the LoRa radio
    pub spi: ExclusiveDevice<Spim<'static, peripherals::TWISPI0>, Output<'static>, Delay>,
    /// Reset pin (active low)
    pub reset: Output<'static>,
    /// DIO1 interrupt pin
    pub dio1: Input<'static>,
    /// Busy status pin
    pub busy: Input<'static>,
}

/// LED peripheral outputs
pub struct LedPeripherals {
    /// Red LED output
    pub red: Output<'static>,
    /// Green LED output  
    pub green: Output<'static>,
    /// Blue LED output
    pub blue: Output<'static>,
}

/// Initialize board-specific peripherals
/// 
/// This function takes the raw nRF52840 peripherals and configures them
/// according to the selected board's pin assignment and requirements.
#[cfg(feature = "board-seeed-xiao-nrf52840")]
pub fn init_board(p: embassy_nrf::Peripherals) -> BoardPeripherals {
    seeed_xiao_nrf52840::init_board(p)
}

// Default fallback if no board is selected
#[cfg(not(any(feature = "board-seeed-xiao-nrf52840")))]
compile_error!("No board selected! Please enable a board feature like 'board-seeed-xiao-nrf52840'");