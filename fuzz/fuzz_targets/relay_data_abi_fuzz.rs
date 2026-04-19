#![no_main]

use alloy_primitives::Bytes;
use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk_chain::decode_relay_data;

fuzz_target!(|data: &[u8]| {
    let _ = decode_relay_data(&Bytes::copy_from_slice(data));
});
