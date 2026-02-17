// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use super::{Error, Result};
use const_oid::ObjectIdentifier;
use der::Tag;
use der::asn1::{Any, SetOfVec};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};

/// OID for CommonName (2.5.4.3).
pub(super) const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// A DN attribute value encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameValue {
    /// UTF8String value.
    Utf8(String),
    /// PrintableString value (restricted ASCII subset from RFC 5280).
    Printable(String),
    /// IA5String value (7-bit ASCII).
    Ia5(String),
    /// Raw bytes for non-text or undecodable values.
    Bytes(Vec<u8>),
}

impl NameValue {
    fn as_any(&self) -> Result<Any> {
        match self {
            NameValue::Utf8(value) => Ok(Any::new(Tag::Utf8String, value.as_bytes())?),
            NameValue::Printable(value) => {
                if !is_printable_string(value) {
                    return Err(Error::InvalidPrintableString);
                }
                Ok(Any::new(Tag::PrintableString, value.as_bytes())?)
            }
            NameValue::Ia5(value) => {
                if !value.is_ascii() {
                    return Err(Error::InvalidIa5String);
                }
                Ok(Any::new(Tag::Ia5String, value.as_bytes())?)
            }
            NameValue::Bytes(_) => Err(Error::RawNameValueNotAllowedForIssuance),
        }
    }
}

fn is_printable_string(value: &str) -> bool {
    value.as_bytes().iter().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                *b,
                b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
            )
    })
}

/// A single DN attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameAttribute {
    /// Attribute OID (for example `2.5.4.3` for CN).
    pub oid: ObjectIdentifier,
    /// Encoded attribute value.
    pub value: NameValue,
}

/// Distinguished Name represented as ordered attributes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DistinguishedName {
    /// Ordered list of RDN attributes.
    pub attrs: Vec<NameAttribute>,
}

impl DistinguishedName {
    /// Creates an empty DN.
    pub fn new() -> Self {
        Self { attrs: Vec::new() }
    }

    /// Adds a UTF8String CN attribute.
    pub fn cn(mut self, value: impl Into<String>) -> Self {
        self.attrs.push(NameAttribute {
            oid: OID_CN,
            value: NameValue::Utf8(value.into()),
        });
        self
    }

    /// Adds an arbitrary attribute.
    pub fn push(mut self, oid: ObjectIdentifier, value: NameValue) -> Self {
        self.attrs.push(NameAttribute { oid, value });
        self
    }

    pub(super) fn to_x509_name(&self) -> Result<Name> {
        let mut rdns = Vec::with_capacity(self.attrs.len());
        for attr in &self.attrs {
            let mut set = SetOfVec::new();
            set.insert(AttributeTypeAndValue {
                oid: attr.oid,
                value: attr.value.as_any()?,
            })
            .expect("single ATAV per RDN must be unique");
            rdns.push(RelativeDistinguishedName::from(set));
        }
        Ok(RdnSequence(rdns))
    }
}
