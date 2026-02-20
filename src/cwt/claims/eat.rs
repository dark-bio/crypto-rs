// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! EAT (Entity Attestation Token) claims.
//!
//! <https://datatracker.ietf.org/doc/html/rfc9711>

use crate::cbor::{
    self, Cbor, Decode, Encode, MapDecode, MapEncode, MapEncodeBuffer, MapEntryAccess,
};

/// UEID is a globally unique device identifier such as a serial number
/// or IMEI (key 256). The value is an opaque byte string including a
/// type prefix byte per RFC 9711 Section 4.2.1.
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct Ueid {
    #[cbor(key = 256)]
    pub ueid: Vec<u8>,
}

/// OEMID identifies the hardware manufacturer (key 258, RFC 9711 Section 4.2.3).
/// The OEM can be identified by a random ID, an IEEE OUI, or an IANA PEN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Oemid {
    value: OemidValue,
}

impl Oemid {
    /// Creates an OEMID from a 16-byte random manufacturer identifier.
    pub fn new_random(id: [u8; 16]) -> Self {
        Self {
            value: OemidValue::Random(id),
        }
    }

    /// Creates an OEMID from a 3-byte IEEE OUI/MA-L.
    pub fn new_ieee(id: [u8; 3]) -> Self {
        Self {
            value: OemidValue::Ieee(id),
        }
    }

    /// Creates an OEMID from an IANA Private Enterprise Number.
    pub fn new_pen(pen: u64) -> Self {
        Self {
            value: OemidValue::Pen(pen),
        }
    }

    /// Returns the 16-byte random OEM ID, or None if this is not a random OEM ID.
    pub fn random(&self) -> Option<[u8; 16]> {
        match self.value {
            OemidValue::Random(id) => Some(id),
            _ => None,
        }
    }

    /// Returns the 3-byte IEEE OUI/MA-L, or None if this is not an IEEE OEM ID.
    pub fn ieee(&self) -> Option<[u8; 3]> {
        match self.value {
            OemidValue::Ieee(id) => Some(id),
            _ => None,
        }
    }

    /// Returns the IANA Private Enterprise Number, or None if this is not a PEN OEM ID.
    pub fn pen(&self) -> Option<u64> {
        match self.value {
            OemidValue::Pen(pen) => Some(pen),
            _ => None,
        }
    }
}

/// Internal representation of the three OEM ID formats.
#[derive(Clone, Debug, PartialEq, Eq)]
enum OemidValue {
    Random([u8; 16]),
    Ieee([u8; 3]),
    Pen(u64),
}

impl Encode for OemidValue {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), cbor::Error> {
        match self {
            OemidValue::Random(id) => id.as_slice().encode_cbor_to(buf),
            OemidValue::Ieee(id) => id.as_slice().encode_cbor_to(buf),
            OemidValue::Pen(pen) => pen.encode_cbor_to(buf),
        }
    }
}

impl Decode for OemidValue {
    fn decode_cbor(data: &[u8]) -> Result<Self, cbor::Error> {
        let mut dec = cbor::Decoder::new(data);
        let result = Self::decode_cbor_notrail(&mut dec)?;
        dec.finish()?;
        Ok(result)
    }

    fn decode_cbor_notrail(dec: &mut cbor::Decoder<'_>) -> Result<Self, cbor::Error> {
        // Peek at major type to determine format: uint -> PEN, bytes -> Random or IEEE
        if dec.peek_uint().is_ok() {
            let pen = dec.decode_uint()?;
            return Ok(OemidValue::Pen(pen));
        }
        // Not an integer, must be bytes
        let bytes = dec.decode_bytes()?;
        match bytes.len() {
            3 => {
                let mut id = [0u8; 3];
                id.copy_from_slice(&bytes);
                Ok(OemidValue::Ieee(id))
            }
            16 => {
                let mut id = [0u8; 16];
                id.copy_from_slice(&bytes);
                Ok(OemidValue::Random(id))
            }
            n => Err(cbor::Error::DecodeFailed(format!(
                "oemid: unexpected bstr length {n}"
            ))),
        }
    }
}

impl Encode for Oemid {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), cbor::Error> {
        let mut enc = MapEncodeBuffer::new(1);
        <Self as MapEncode>::encode_map(self, &mut enc)?;
        enc.finish_to(buf)
    }
}

impl Decode for Oemid {
    fn decode_cbor(data: &[u8]) -> Result<Self, cbor::Error> {
        let mut dec = cbor::Decoder::new(data);
        let result = Self::decode_cbor_notrail(&mut dec)?;
        dec.finish()?;
        Ok(result)
    }

    fn decode_cbor_notrail(dec: &mut cbor::Decoder<'_>) -> Result<Self, cbor::Error> {
        let entries = cbor::decode_map_entries_slices_notrail(dec)?;
        let mut remaining = cbor::MapEntries::new(entries);
        let value = <Self as MapDecode>::decode_map(&mut remaining)?;
        if !remaining.is_empty() {
            let unknown: Vec<i64> = remaining.remaining_keys();
            return Err(cbor::Error::DecodeFailed(format!(
                "unknown CBOR map keys: {unknown:?}"
            )));
        }
        Ok(value)
    }
}

impl MapEncode for Oemid {
    fn encode_map(&self, enc: &mut MapEncodeBuffer) -> Result<(), cbor::Error> {
        enc.push(258, &self.value)
    }
}

impl MapDecode for Oemid {
    fn cbor_map_keys() -> &'static [i64] {
        &[258]
    }

    fn decode_map<'a, E: MapEntryAccess<'a>>(entries: &mut E) -> Result<Self, cbor::Error> {
        let raw = entries
            .take(258)
            .ok_or(cbor::Error::DecodeFailed("missing required key 258".into()))?;
        let value = OemidValue::decode_cbor(raw)?;
        Ok(Self { value })
    }
}

/// HwModel is the product or board model identifier (key 259).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct HwModel {
    #[cbor(key = 259)]
    pub hw_model: Vec<u8>,
}

/// HwVersion is the hardware revision identifier (key 260).
/// CBOR-encodes as a 1-element array per RFC 9711 Section 4.2.5:
/// `[version: tstr]`. The optional scheme is not supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HwVersion {
    version: String,
}

impl HwVersion {
    /// Creates an HwVersion with the given version string.
    pub fn new(version: String) -> Self {
        Self { version }
    }

    /// Returns the hardware version string.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// Internal 1-element array for HW/SW version encoding.
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
#[cbor(array)]
struct VersionArray {
    version: String,
}

impl Encode for HwVersion {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), cbor::Error> {
        let mut enc = MapEncodeBuffer::new(1);
        <Self as MapEncode>::encode_map(self, &mut enc)?;
        enc.finish_to(buf)
    }
}

impl Decode for HwVersion {
    fn decode_cbor(data: &[u8]) -> Result<Self, cbor::Error> {
        let mut dec = cbor::Decoder::new(data);
        let result = Self::decode_cbor_notrail(&mut dec)?;
        dec.finish()?;
        Ok(result)
    }

    fn decode_cbor_notrail(dec: &mut cbor::Decoder<'_>) -> Result<Self, cbor::Error> {
        let entries = cbor::decode_map_entries_slices_notrail(dec)?;
        let mut remaining = cbor::MapEntries::new(entries);
        let value = <Self as MapDecode>::decode_map(&mut remaining)?;
        if !remaining.is_empty() {
            let unknown: Vec<i64> = remaining.remaining_keys();
            return Err(cbor::Error::DecodeFailed(format!(
                "unknown CBOR map keys: {unknown:?}"
            )));
        }
        Ok(value)
    }
}

impl MapEncode for HwVersion {
    fn encode_map(&self, enc: &mut MapEncodeBuffer) -> Result<(), cbor::Error> {
        let arr = VersionArray {
            version: self.version.clone(),
        };
        enc.push(260, &arr)
    }
}

impl MapDecode for HwVersion {
    fn cbor_map_keys() -> &'static [i64] {
        &[260]
    }

    fn decode_map<'a, E: MapEntryAccess<'a>>(entries: &mut E) -> Result<Self, cbor::Error> {
        let raw = entries
            .take(260)
            .ok_or(cbor::Error::DecodeFailed("missing required key 260".into()))?;
        let arr = VersionArray::decode_cbor(raw)?;
        Ok(Self {
            version: arr.version,
        })
    }
}

/// Uptime is the number of seconds since the last boot (key 261).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct Uptime {
    #[cbor(key = 261)]
    pub uptime: u64,
}

/// OemBoot indicates whether the boot chain is OEM-authorized,
/// i.e. secure boot passed (key 262).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct OemBoot {
    #[cbor(key = 262)]
    pub oem_boot: bool,
}

/// DebugState represents the debug port state per RFC 9711 Section 4.2.9.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum DebugState {
    /// Debug is currently enabled.
    Enabled = 0,
    /// Debug is currently disabled.
    Disabled = 1,
    /// Debug was disabled at boot and has not been enabled since.
    DisabledSinceBoot = 2,
    /// Debug is disabled and cannot be re-enabled.
    DisabledPermanently = 3,
    /// All debug, including DMA-based, is permanently disabled.
    DisabledFullyPermanently = 4,
}

impl Encode for DebugState {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), cbor::Error> {
        (*self as u64).encode_cbor_to(buf)
    }
}

impl Decode for DebugState {
    fn decode_cbor(data: &[u8]) -> Result<Self, cbor::Error> {
        let mut dec = cbor::Decoder::new(data);
        let result = Self::decode_cbor_notrail(&mut dec)?;
        dec.finish()?;
        Ok(result)
    }

    fn decode_cbor_notrail(dec: &mut cbor::Decoder<'_>) -> Result<Self, cbor::Error> {
        let value = dec.decode_uint()?;
        match value {
            0 => Ok(DebugState::Enabled),
            1 => Ok(DebugState::Disabled),
            2 => Ok(DebugState::DisabledSinceBoot),
            3 => Ok(DebugState::DisabledPermanently),
            4 => Ok(DebugState::DisabledFullyPermanently),
            _ => Err(cbor::Error::DecodeFailed(format!(
                "invalid debug state: {value}"
            ))),
        }
    }
}

/// DebugStatus is the debug port state (key 263).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct DebugStatus {
    #[cbor(key = 263)]
    pub debug_status: DebugState,
}

/// BootCount is the number of times the device has booted,
/// as a monotonic counter (key 267).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct BootCount {
    #[cbor(key = 267)]
    pub boot_count: u64,
}

/// BootSeed is a random value unique to the current boot cycle (key 268).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct BootSeed {
    #[cbor(key = 268)]
    pub boot_seed: Vec<u8>,
}

/// SwName is the name of the firmware or software running on the
/// device (key 270).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct SwName {
    #[cbor(key = 270)]
    pub sw_name: String,
}

/// SwVersion is the software version identifier (key 271).
/// CBOR-encodes as a 1-element array per RFC 9711 Section 4.2.7:
/// `[version: tstr]`. The optional scheme is not supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwVersion {
    version: String,
}

impl SwVersion {
    /// Creates a SwVersion with the given version string.
    pub fn new(version: String) -> Self {
        Self { version }
    }

    /// Returns the software version string.
    pub fn version(&self) -> &str {
        &self.version
    }
}

impl Encode for SwVersion {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), cbor::Error> {
        let mut enc = MapEncodeBuffer::new(1);
        <Self as MapEncode>::encode_map(self, &mut enc)?;
        enc.finish_to(buf)
    }
}

impl Decode for SwVersion {
    fn decode_cbor(data: &[u8]) -> Result<Self, cbor::Error> {
        let mut dec = cbor::Decoder::new(data);
        let result = Self::decode_cbor_notrail(&mut dec)?;
        dec.finish()?;
        Ok(result)
    }

    fn decode_cbor_notrail(dec: &mut cbor::Decoder<'_>) -> Result<Self, cbor::Error> {
        let entries = cbor::decode_map_entries_slices_notrail(dec)?;
        let mut remaining = cbor::MapEntries::new(entries);
        let value = <Self as MapDecode>::decode_map(&mut remaining)?;
        if !remaining.is_empty() {
            let unknown: Vec<i64> = remaining.remaining_keys();
            return Err(cbor::Error::DecodeFailed(format!(
                "unknown CBOR map keys: {unknown:?}"
            )));
        }
        Ok(value)
    }
}

impl MapEncode for SwVersion {
    fn encode_map(&self, enc: &mut MapEncodeBuffer) -> Result<(), cbor::Error> {
        let arr = VersionArray {
            version: self.version.clone(),
        };
        enc.push(271, &arr)
    }
}

impl MapDecode for SwVersion {
    fn cbor_map_keys() -> &'static [i64] {
        &[271]
    }

    fn decode_map<'a, E: MapEntryAccess<'a>>(entries: &mut E) -> Result<Self, cbor::Error> {
        let raw = entries
            .take(271)
            .ok_or(cbor::Error::DecodeFailed("missing required key 271".into()))?;
        let arr = VersionArray::decode_cbor(raw)?;
        Ok(Self {
            version: arr.version,
        })
    }
}

/// Use represents the token's intended purpose per RFC 9711 Section 4.3.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Use {
    /// General-purpose attestation.
    Generic = 1,
    /// Attestation for service registration.
    Registration = 2,
    /// Attestation prior to key/config provisioning.
    Provisioning = 3,
    /// Attestation for certificate signing requests.
    CertIssuance = 4,
    /// Attestation accompanying a proof-of-possession.
    ProofOfPossession = 5,
}

impl Encode for Use {
    fn encode_cbor_to(&self, buf: &mut Vec<u8>) -> Result<(), cbor::Error> {
        (*self as u64).encode_cbor_to(buf)
    }
}

impl Decode for Use {
    fn decode_cbor(data: &[u8]) -> Result<Self, cbor::Error> {
        let mut dec = cbor::Decoder::new(data);
        let result = Self::decode_cbor_notrail(&mut dec)?;
        dec.finish()?;
        Ok(result)
    }

    fn decode_cbor_notrail(dec: &mut cbor::Decoder<'_>) -> Result<Self, cbor::Error> {
        let value = dec.decode_uint()?;
        match value {
            1 => Ok(Use::Generic),
            2 => Ok(Use::Registration),
            3 => Ok(Use::Provisioning),
            4 => Ok(Use::CertIssuance),
            5 => Ok(Use::ProofOfPossession),
            _ => Err(cbor::Error::DecodeFailed(format!(
                "invalid intended use: {value}"
            ))),
        }
    }
}

/// IntendedUse is the token's purpose (key 275).
#[derive(Clone, Debug, PartialEq, Eq, Cbor)]
pub struct IntendedUse {
    #[cbor(key = 275)]
    pub intended_use: Use,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies round-trip encoding of a random OEM ID.
    #[test]
    fn test_oemid_random() {
        let id: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            oemid: Oemid,
        }
        let orig = Token {
            oemid: Oemid::new_random(id),
        };
        let data = cbor::encode(&orig).expect("encode");
        let got = Token::decode_cbor(&data).expect("decode");

        assert_eq!(got.oemid.random(), Some(id));
    }

    /// Verifies round-trip encoding of an IEEE OEM ID.
    #[test]
    fn test_oemid_ieee() {
        let id: [u8; 3] = [0xAC, 0xDE, 0x48];

        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            oemid: Oemid,
        }
        let orig = Token {
            oemid: Oemid::new_ieee(id),
        };
        let data = cbor::encode(&orig).expect("encode");
        let got = Token::decode_cbor(&data).expect("decode");

        assert_eq!(got.oemid.ieee(), Some(id));
    }

    /// Verifies round-trip encoding of a PEN OEM ID.
    #[test]
    fn test_oemid_pen() {
        let pen: u64 = 76543;

        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            oemid: Oemid,
        }
        let orig = Token {
            oemid: Oemid::new_pen(pen),
        };
        let data = cbor::encode(&orig).expect("encode");
        let got = Token::decode_cbor(&data).expect("decode");

        assert_eq!(got.oemid.pen(), Some(pen));
    }

    /// Verifies that accessors return None for mismatched types.
    #[test]
    fn test_oemid_wrong_accessor() {
        let o = Oemid::new_pen(42);
        assert_eq!(o.random(), None);
        assert_eq!(o.ieee(), None);
    }

    /// Verifies round-trip encoding of a hardware version.
    #[test]
    fn test_hw_version() {
        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            hw: HwVersion,
        }
        let orig = Token {
            hw: HwVersion::new("1.2.3".into()),
        };
        let data = cbor::encode(&orig).expect("encode");
        let got = Token::decode_cbor(&data).expect("decode");

        assert_eq!(got.hw.version(), "1.2.3");
    }

    /// Verifies round-trip encoding of a software version.
    #[test]
    fn test_sw_version() {
        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            sw: SwVersion,
        }
        let orig = Token {
            sw: SwVersion::new("4.5.6".into()),
        };
        let data = cbor::encode(&orig).expect("encode");
        let got = Token::decode_cbor(&data).expect("decode");

        assert_eq!(got.sw.version(), "4.5.6");
    }

    /// Verifies round-trip encoding of the simple EAT claims.
    #[test]
    fn test_simple_claims() {
        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            ueid: Ueid,
            #[cbor(embed)]
            hw_model: HwModel,
            #[cbor(embed)]
            uptime: Uptime,
            #[cbor(embed)]
            oem_boot: OemBoot,
            #[cbor(embed)]
            debug_status: DebugStatus,
            #[cbor(embed)]
            boot_count: BootCount,
            #[cbor(embed)]
            boot_seed: BootSeed,
            #[cbor(embed)]
            sw_name: SwName,
            #[cbor(embed)]
            intended_use: IntendedUse,
        }
        let orig = Token {
            ueid: Ueid {
                ueid: vec![0x01, 0x02, 0x03],
            },
            hw_model: HwModel {
                hw_model: b"board-v2".to_vec(),
            },
            uptime: Uptime { uptime: 3600 },
            oem_boot: OemBoot { oem_boot: true },
            debug_status: DebugStatus {
                debug_status: DebugState::DisabledPermanently,
            },
            boot_count: BootCount { boot_count: 42 },
            boot_seed: BootSeed {
                boot_seed: vec![0xDE, 0xAD],
            },
            sw_name: SwName {
                sw_name: "firmware-v3".into(),
            },
            intended_use: IntendedUse {
                intended_use: Use::CertIssuance,
            },
        };
        let data = cbor::encode(&orig).expect("encode");
        let got = Token::decode_cbor(&data).expect("decode");

        assert_eq!(got.ueid.ueid, vec![0x01, 0x02, 0x03]);
        assert_eq!(got.hw_model.hw_model, b"board-v2");
        assert_eq!(got.uptime.uptime, 3600);
        assert!(got.oem_boot.oem_boot);
        assert_eq!(
            got.debug_status.debug_status,
            DebugState::DisabledPermanently
        );
        assert_eq!(got.boot_count.boot_count, 42);
        assert_eq!(got.boot_seed.boot_seed, vec![0xDE, 0xAD]);
        assert_eq!(got.sw_name.sw_name, "firmware-v3");
        assert_eq!(got.intended_use.intended_use, Use::CertIssuance);
    }

    /// Tests that a byte string of invalid length is rejected for OEMID.
    #[test]
    fn test_oemid_invalid_length() {
        let mut enc = cbor::Encoder::new();
        enc.encode_map_header(1);
        enc.encode_int(258);
        enc.encode_bytes(&[1, 2, 3, 4, 5]); // 5 bytes: neither 3 nor 16

        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            oemid: Oemid,
        }
        assert!(Token::decode_cbor(&enc.finish()).is_err());
    }

    /// Tests that a non-bstr/uint CBOR type is rejected for OEMID.
    #[test]
    fn test_oemid_invalid_type() {
        let mut enc = cbor::Encoder::new();
        enc.encode_map_header(1);
        enc.encode_int(258);
        enc.encode_text("not-bytes");

        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            oemid: Oemid,
        }
        assert!(Token::decode_cbor(&enc.finish()).is_err());
    }

    /// Tests that an out-of-range debug state is rejected.
    #[test]
    fn test_debug_state_invalid() {
        let mut enc = cbor::Encoder::new();
        enc.encode_map_header(1);
        enc.encode_int(263);
        enc.encode_uint(99); // not in 0..4

        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            debug: DebugStatus,
        }
        assert!(Token::decode_cbor(&enc.finish()).is_err());
    }

    /// Tests that an out-of-range intended use is rejected.
    #[test]
    fn test_use_invalid() {
        let mut enc = cbor::Encoder::new();
        enc.encode_map_header(1);
        enc.encode_int(275);
        enc.encode_uint(0); // not in 1..5

        #[derive(Debug, Cbor)]
        struct Token {
            #[cbor(embed)]
            intended_use: IntendedUse,
        }
        assert!(Token::decode_cbor(&enc.finish()).is_err());
    }
}
