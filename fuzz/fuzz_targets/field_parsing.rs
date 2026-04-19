#![no_main]

use libfuzzer_sys::fuzz_target;
use privacy_pools_sdk_core::{field_to_decimal, parse_decimal_field};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data)
        && let Ok(field) = parse_decimal_field(value)
    {
        let exported = field_to_decimal(field);
        let reparsed = parse_decimal_field(&exported).expect("exported field should parse");
        assert_eq!(field, reparsed);
    }
});
