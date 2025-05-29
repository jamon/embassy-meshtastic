#![no_std]
#![allow(dead_code)]
pub mod meshtastic {
    include!(concat!(env!("OUT_DIR"), "/meshtastic.rs"));
}
