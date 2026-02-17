// crypto-rs: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use super::Result;
use const_oid::ObjectIdentifier;
use der::Tag;
use der::asn1::{Any, SetOfVec};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};

/// OID for CommonName (2.5.4.3).
pub(super) const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// OID for Organization (2.5.4.10).
const OID_O: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
/// OID for Country (2.5.4.6).
const OID_C: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
/// OID for StateOrProvinceName (2.5.4.8).
const OID_ST: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");
/// OID for Locality (2.5.4.7).
const OID_L: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
/// OID for StreetAddress (2.5.4.9).
const OID_STREET: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.9");
/// OID for PostalCode (2.5.4.17).
const OID_POSTAL_CODE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.17");

/// A single DN attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameAttribute {
    /// Attribute OID (for example `2.5.4.3` for CN).
    pub oid: ObjectIdentifier,
    /// Attribute value (UTF-8).
    pub value: String,
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

    /// Adds a common name (CN) attribute.
    pub fn cn(mut self, value: impl Into<String>) -> Self {
        self.attrs.push(NameAttribute {
            oid: OID_CN,
            value: value.into(),
        });
        self
    }

    /// Adds an organization (O) attribute.
    pub fn org(mut self, value: impl Into<String>) -> Self {
        self.attrs.push(NameAttribute {
            oid: OID_O,
            value: value.into(),
        });
        self
    }

    /// Adds a country (C) attribute.
    pub fn country(mut self, value: impl Into<String>) -> Self {
        self.attrs.push(NameAttribute {
            oid: OID_C,
            value: value.into(),
        });
        self
    }

    /// Adds a state or province (ST) attribute.
    pub fn province(mut self, value: impl Into<String>) -> Self {
        self.attrs.push(NameAttribute {
            oid: OID_ST,
            value: value.into(),
        });
        self
    }

    /// Adds a locality (L) attribute.
    pub fn locality(mut self, value: impl Into<String>) -> Self {
        self.attrs.push(NameAttribute {
            oid: OID_L,
            value: value.into(),
        });
        self
    }

    /// Adds a street address attribute.
    pub fn street(mut self, value: impl Into<String>) -> Self {
        self.attrs.push(NameAttribute {
            oid: OID_STREET,
            value: value.into(),
        });
        self
    }

    /// Adds a postal code attribute.
    pub fn postal_code(mut self, value: impl Into<String>) -> Self {
        self.attrs.push(NameAttribute {
            oid: OID_POSTAL_CODE,
            value: value.into(),
        });
        self
    }

    /// Adds an arbitrary attribute.
    pub fn push(mut self, oid: ObjectIdentifier, value: impl Into<String>) -> Self {
        self.attrs.push(NameAttribute {
            oid,
            value: value.into(),
        });
        self
    }

    pub(super) fn to_x509_name(&self) -> Result<Name> {
        let mut rdns = Vec::with_capacity(self.attrs.len());
        for attr in &self.attrs {
            let mut set = SetOfVec::new();
            set.insert(AttributeTypeAndValue {
                oid: attr.oid,
                value: Any::new(Tag::Utf8String, attr.value.as_bytes())?,
            })
            .expect("single ATAV per RDN must be unique");
            rdns.push(RelativeDistinguishedName::from(set));
        }
        Ok(RdnSequence(rdns))
    }
}
