use bosch_bme680::{AsyncBme680, BmeError};
use defmt::*;
use embassy_nrf::{
    peripherals::{self, TWISPI0},
    twim::{self, Twim},
};
use embassy_time::Delay;
use femtopb::UnknownFields;
use lora_phy::DelayNs;
use meshtastic_protobufs::meshtastic::EnvironmentMetrics;

//todo: create a task that handles polling sensors and assembling the protobufs for
//telemetry data, read the configuration protobufs stored on the device to determine
//behavior of the task

/// Environmental Telemetry source data trait
///
/// Sensors providing environmental telemetry data must implment this trait
pub trait EnvironmentalData {
    /// Setup an environmental sensor
    async fn setup(&mut self) {}
    /// Get metrics for the environmental telemetry payload from a given sensor
    ///
    /// # Returns
    /// * Optional `EnvironmentMetrics` struct with data from a given sensor
    async fn get_metrics<'a>(&mut self) -> Option<EnvironmentMetrics<'a>> {
        None
    }
}

/// Try implementing environmentaldata trait on bme
impl EnvironmentalData for AsyncBme680<Twim<'_, TWISPI0>, Delay> {
    async fn setup(&mut self) {
        let bme_config = bosch_bme680::Configuration::default();
        match self.initialize(&bme_config).await {
            Ok(_) => info!("BME680 Configured"),
            Err(e) => {
                let re = RemoteError { inner: e };
                error!("Error configuring BME680: {:?}", re)
            }
        }
        // 12 second delay after configuration
        Delay.delay_ms(12000).await;
    }
    async fn get_metrics<'a>(&mut self) -> Option<EnvironmentMetrics<'a>> {
        match self.measure().await {
            Ok(data) => {
                info!("Temperature: {:?}", data.temperature);
                info!("Humidity: {:?}%", data.humidity);
                info!("Pressure: {:?}", data.pressure);
                if let Some(gr) = data.gas_resistance {
                    info!("Gas Resistance: {:?}", gr);
                }
                info!("IAQ: N/A");
                Some(EnvironmentMetrics {
                    temperature: Some(data.temperature),
                    relative_humidity: Some(data.humidity),
                    barometric_pressure: Some(data.pressure),
                    gas_resistance: data.gas_resistance,
                    voltage: None,
                    current: None,
                    iaq: None, // C++ firmware shows IAQ from a BME, perhaps this crate is not great
                    distance: None,
                    lux: None,
                    white_lux: None,
                    ir_lux: None,
                    uv_lux: None,
                    wind_direction: None,
                    wind_speed: None,
                    weight: None,
                    wind_gust: None,
                    wind_lull: None,
                    radiation: None,
                    rainfall_1h: None,
                    rainfall_24h: None,
                    soil_moisture: None,
                    soil_temperature: None,
                    unknown_fields: UnknownFields::default(),
                })
            }
            Err(e) => {
                let re = RemoteError { inner: e };
                error!("Error fetching data from BME: {:?}", re);
                None
            }
        }
    }
}

/// impls on remote types are not allowed, but you can proxy them
/// todo: find way to force proxying if need be in the trait
struct RemoteError<'a> {
    inner: BmeError<Twim<'a, TWISPI0>>,
}

/// Implement defmt formatting for errors that do not already implement it
impl defmt::Format for RemoteError<'_> {
    fn format(&self, fmt: Formatter) {
        match self.inner {
            BmeError::WriteError(e) => defmt::write!(fmt, "Write Error: {:#?}", e),
            BmeError::WriteReadError(e) => defmt::write!(fmt, "Write Read Error: {:#?}", e),
            BmeError::UnexpectedChipId(e) => defmt::write!(fmt, "Unexpected Chip ID: {}", e),
            BmeError::MeasuringTimeOut => defmt::write!(fmt, "Measuring Timeout"),
            BmeError::Uninitialized => defmt::write!(fmt, "Uninitialized"),
        }
    }
}
