// crypto-rs: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Procedural macros for darkbio-crypto.
//!
//! Provides the `Cbor` derive macro for structs that generates both `Encode`
//! and `Decode` implementations.
//!
//! # Struct encoding modes
//!
//! By default, structs encode as CBOR maps with integer keys specified via
//! `#[cbor(key = N)]`. Use `#[cbor(array)]` to encode as a CBOR array instead.
//!
//! # Examples
//!
//! Map encoding (default):
//! ```ignore
//! #[derive(Cbor)]
//! struct Data {
//!     #[cbor(key = 1)]
//!     name: String,
//!     #[cbor(key = -1)]
//!     value: u64,
//! }
//! // Encodes as: {1: name, -1: value} (sorted by bytewise key encoding)
//! ```
//!
//! Array encoding:
//! ```ignore
//! #[derive(Cbor)]
//! #[cbor(array)]
//! struct Point {
//!     x: u64,
//!     y: u64,
//! }
//! // Encodes as: [x, y]
//! ```

mod cbor;

use cbor::cbor_key_bytes;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use std::collections::BTreeSet;
use syn::{Data, DeriveInput, Expr, Fields, Lit, parse_macro_input};

/// Derives the CBOR encoder and decoder for structs tagged with #[derive(Cbor)]
/// and internally fields tagged with #[cbor(...)].
#[proc_macro_derive(Cbor, attributes(cbor))]
pub fn derive_cbor(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let encode = derive_encode(&input);
    let decode = derive_decode(&input);
    match (encode, decode) {
        (Ok(enc), Ok(dec)) => quote! { #enc #dec }.into(),
        (Err(e), _) | (_, Err(e)) => e.to_compile_error().into(),
    }
}

/// Generates the `Encode` trait implementation for a struct.
fn derive_encode(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let fields = parse_fields(input)?;
    if want_array(input) {
        derive_encode_array(&input.ident, &fields)
    } else {
        derive_encode_map(&input.ident, &fields)
    }
}

/// Generates array-mode `Encode` impl: fields encoded in declaration order.
fn derive_encode_array(name: &syn::Ident, fields: &[FieldInfo]) -> syn::Result<TokenStream2> {
    let cbor_crate = quote! { darkbio_crypto::cbor };
    let len = fields.len();

    // Generate code to encode each field in declaration order
    let encode_fields: Vec<_> = fields
        .iter()
        .map(|f| {
            let ident = &f.ident;
            quote! { enc.extend(&self.#ident.encode_cbor()?); }
        })
        .collect();

    Ok(quote! {
        impl #cbor_crate::Encode for #name {
            fn encode_cbor(&self) -> Result<Vec<u8>, #cbor_crate::Error> {
                let mut enc = #cbor_crate::Encoder::new();
                enc.encode_array_header(#len);
                #(#encode_fields)*
                Ok(enc.finish())
            }
        }
    })
}

/// Generates map-mode `Encode` impl: fields encoded as key-value pairs, sorted by key bytes.
/// Option<T> fields are omitted when None (the key-value pair is not encoded).
/// Fields with #[cbor(embed)] are flattened: their CBOR map entries are merged into the parent.
fn derive_encode_map(name: &syn::Ident, fields: &[FieldInfo]) -> syn::Result<TokenStream2> {
    let cbor_crate = quote! { darkbio_crypto::cbor };

    // Validate field attributes: mutual exclusivity, duplicate direct keys,
    // and reject embed on optional/nullable types.
    let embed_count = fields.iter().filter(|f| f.embed).count();
    let mut direct_keys = BTreeSet::new();
    for field in fields {
        if field.embed && field.key.is_some() {
            return Err(syn::Error::new_spanned(
                &field.ident,
                "#[cbor(embed)] and #[cbor(key)] are mutually exclusive",
            ));
        }
        if field.embed
            && (extract_option_inner(&field.kind).is_some()
                || extract_nullable_inner(&field.kind).is_some())
        {
            return Err(syn::Error::new_spanned(
                &field.ident,
                "#[cbor(embed)] cannot be optional or nullable",
            ));
        }
        if !field.embed && field.key.is_none() {
            return Err(syn::Error::new_spanned(
                &field.ident,
                "map struct fields require #[cbor(key = N)], or use #[cbor(array)]",
            ));
        }
        if !field.embed && !direct_keys.insert(field.key.unwrap()) {
            return Err(syn::Error::new_spanned(
                &field.ident,
                format!("duplicate CBOR key {}", field.key.unwrap()),
            ));
        }
    }
    if embed_count > 0 {
        let direct: Vec<_> = fields.iter().filter(|f| !f.embed).collect();
        let embeds: Vec<_> = fields.iter().filter(|f| f.embed).collect();

        let direct_key_lits: Vec<i64> = direct.iter().map(|f| f.key.unwrap()).collect();

        let schema_checks: Vec<_> = embeds
            .iter()
            .map(|f| {
                let ty = &f.kind;
                quote! {
                    {
                        let ek: std::collections::BTreeSet<i64> =
                            <#ty as #cbor_crate::MapDecode>::cbor_map_keys().into_iter().collect();
                        for k in ek.iter() {
                            if dk.contains(k) {
                                return Err(#cbor_crate::Error::DuplicateMapKey(*k));
                            }
                            if !sek.insert(*k) {
                                return Err(#cbor_crate::Error::DuplicateMapKey(*k));
                            }
                        }
                    }
                }
            })
            .collect();

        let direct_entries: Vec<_> = direct
            .iter()
            .map(|f| {
                let ident = &f.ident;
                let key = f.key.unwrap();
                if extract_option_inner(&f.kind).is_some() {
                    quote! {
                        if let Some(ref v) = self.#ident {
                            entries.push((#key, #cbor_crate::Raw(#cbor_crate::Encode::encode_cbor(v)?)));
                        }
                    }
                } else {
                    quote! {
                        entries.push((#key, #cbor_crate::Raw(#cbor_crate::Encode::encode_cbor(&self.#ident)?)));
                    }
                }
            })
            .collect();

        let embed_entries: Vec<_> = embeds
            .iter()
            .map(|f| {
                let ident = &f.ident;
                let ty = &f.kind;
                quote! {
                    <#ty as #cbor_crate::MapEncode>::encode_map(&self.#ident, entries)?;
                }
            })
            .collect();

        return Ok(quote! {
            impl #cbor_crate::Encode for #name {
                fn encode_cbor(&self) -> Result<Vec<u8>, #cbor_crate::Error> {
                    let dk: std::collections::BTreeSet<i64> = [#(#direct_key_lits),*].into_iter().collect();
                    let mut sek: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
                    #(#schema_checks)*

                    let mut entries: Vec<(i64, #cbor_crate::Raw)> = Vec::new();
                    <Self as #cbor_crate::MapEncode>::encode_map(self, &mut entries)?;
                    entries.sort_by(|a, b| #cbor_crate::cbor_key_cmp(a.0, b.0));

                    let mut prev_key: Option<i64> = None;
                    for (key, _) in entries.iter() {
                        if let Some(prev) = prev_key {
                            if #cbor_crate::cbor_key_cmp(prev, *key) != std::cmp::Ordering::Less {
                                return Err(if prev == *key {
                                    #cbor_crate::Error::DuplicateMapKey(*key)
                                } else {
                                    #cbor_crate::Error::InvalidMapKeyOrder(*key, prev)
                                });
                            }
                        }
                        prev_key = Some(*key);
                    }
                    Ok(#cbor_crate::encode_map_entries(&entries))
                }
            }

            impl #cbor_crate::MapEncode for #name {
                fn encode_map(&self, entries: &mut Vec<(i64, #cbor_crate::Raw)>) -> Result<(), #cbor_crate::Error> {
                    #(#direct_entries)*
                    #(#embed_entries)*
                    Ok(())
                }
            }
        });
    }
    // No embed fields — use direct encode (existing path)

    // Sort fields by CBOR-encoded key bytes for deterministic encoding
    let mut sorted: Vec<_> = fields.iter().collect();
    sorted.sort_by(|a, b| {
        let ka = cbor_key_bytes(a.key.unwrap());
        let kb = cbor_key_bytes(b.key.unwrap());
        ka.cmp(&kb)
    });

    // Check if any field is optional (affects whether map size is static or dynamic)
    let has_optional = sorted
        .iter()
        .any(|f| extract_option_inner(&f.kind).is_some());

    // Generate code to count and encode fields. Optional fields are only included
    // when they are Some, so the map header count must be computed at runtime.
    let count_fields: Vec<_> = sorted
        .iter()
        .map(|f| {
            let ident = &f.ident;
            if extract_option_inner(&f.kind).is_some() {
                quote! { if self.#ident.is_some() { count += 1; } }
            } else {
                quote! { count += 1; }
            }
        })
        .collect();

    let encode_fields: Vec<_> = sorted
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let key = f.key.unwrap();
            if extract_option_inner(&f.kind).is_some() {
                quote! {
                    if let Some(ref v) = self.#ident {
                        enc.encode_int(#key);
                        enc.extend(&v.encode_cbor()?);
                    }
                }
            } else {
                quote! {
                    enc.encode_int(#key);
                    enc.extend(&self.#ident.encode_cbor()?);
                }
            }
        })
        .collect();

    let map_encode_fields: Vec<_> = sorted
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let key = f.key.unwrap();
            if extract_option_inner(&f.kind).is_some() {
                quote! {
                    if let Some(ref v) = self.#ident {
                        entries.push((#key, #cbor_crate::Raw(#cbor_crate::Encode::encode_cbor(v)?)));
                    }
                }
            } else {
                quote! {
                    entries.push((#key, #cbor_crate::Raw(#cbor_crate::Encode::encode_cbor(&self.#ident)?)));
                }
            }
        })
        .collect();

    // If there are no optional fields, use a static map header size to avoid
    // generating unnecessary runtime counting code.
    if has_optional {
        Ok(quote! {
            impl #cbor_crate::Encode for #name {
                fn encode_cbor(&self) -> Result<Vec<u8>, #cbor_crate::Error> {
                    let mut enc = #cbor_crate::Encoder::new();
                    let mut count: usize = 0;
                    #(#count_fields)*
                    enc.encode_map_header(count);
                    #(#encode_fields)*
                    Ok(enc.finish())
                }
            }

            impl #cbor_crate::MapEncode for #name {
                fn encode_map(&self, entries: &mut Vec<(i64, #cbor_crate::Raw)>) -> Result<(), #cbor_crate::Error> {
                    #(#map_encode_fields)*
                    Ok(())
                }
            }
        })
    } else {
        let len = sorted.len();
        Ok(quote! {
            impl #cbor_crate::Encode for #name {
                fn encode_cbor(&self) -> Result<Vec<u8>, #cbor_crate::Error> {
                    let mut enc = #cbor_crate::Encoder::new();
                    enc.encode_map_header(#len);
                    #(#encode_fields)*
                    Ok(enc.finish())
                }
            }

            impl #cbor_crate::MapEncode for #name {
                fn encode_map(&self, entries: &mut Vec<(i64, #cbor_crate::Raw)>) -> Result<(), #cbor_crate::Error> {
                    #(#map_encode_fields)*
                    Ok(())
                }
            }
        })
    }
}

/// Generates the `Decode` trait implementation for a struct.
fn derive_decode(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let fields = parse_fields(input)?;
    if want_array(input) {
        derive_decode_array(&input.ident, &fields)
    } else {
        derive_decode_map(&input.ident, &fields)
    }
}

/// Generates array-mode `Decode` impl: fields decoded in declaration order.
fn derive_decode_array(name: &syn::Ident, fields: &[FieldInfo]) -> syn::Result<TokenStream2> {
    let cbor_crate = quote! { darkbio_crypto::cbor };
    let len = fields.len();
    let field_idents: Vec<_> = fields.iter().map(|f| &f.ident).collect();

    // Generate a decode statement for each field
    let decode_fields: Vec<_> = fields
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let ty = &f.kind;
            quote! {
                let #ident = <#ty as #cbor_crate::Decode>::decode_cbor_notrail(dec)?;
            }
        })
        .collect();

    Ok(quote! {
        impl #cbor_crate::Decode for #name {
            fn decode_cbor(data: &[u8]) -> Result<Self, #cbor_crate::Error> {
                let mut dec = #cbor_crate::Decoder::new(data);
                let result = Self::decode_cbor_notrail(&mut dec)?;
                dec.finish()?; // Ensure no trailing data
                Ok(result)
            }

            fn decode_cbor_notrail(dec: &mut #cbor_crate::Decoder) -> Result<Self, #cbor_crate::Error> {
                let len = dec.decode_array_header()?;
                if len != #len as u64 {
                    return Err(#cbor_crate::Error::UnexpectedItemCount(len, #len));
                }
                #(#decode_fields)*
                Ok(Self { #(#field_idents),* })
            }
        }
    })
}

/// Generates map-mode `Decode` impl: fields decoded as key-value pairs, validating key order.
/// Option<T> fields tolerate missing keys by defaulting to None.
/// Fields with #[cbor(embed)] consume remaining map entries after direct fields are extracted.
fn derive_decode_map(name: &syn::Ident, fields: &[FieldInfo]) -> syn::Result<TokenStream2> {
    let cbor_crate = quote! { darkbio_crypto::cbor };

    let mut direct_keys = BTreeSet::new();
    for field in fields {
        if field.embed && field.key.is_some() {
            return Err(syn::Error::new_spanned(
                &field.ident,
                "#[cbor(embed)] and #[cbor(key)] are mutually exclusive",
            ));
        }
        if field.embed
            && (extract_option_inner(&field.kind).is_some()
                || extract_nullable_inner(&field.kind).is_some())
        {
            return Err(syn::Error::new_spanned(
                &field.ident,
                "#[cbor(embed)] cannot be optional or nullable",
            ));
        }
        if !field.embed && field.key.is_none() {
            return Err(syn::Error::new_spanned(
                &field.ident,
                "map struct fields require #[cbor(key = N)], or use #[cbor(array)]",
            ));
        }
        if !field.embed && !direct_keys.insert(field.key.unwrap()) {
            return Err(syn::Error::new_spanned(
                &field.ident,
                format!("duplicate CBOR key {}", field.key.unwrap()),
            ));
        }
    }

    let direct: Vec<_> = fields.iter().filter(|f| !f.embed).collect();
    let embeds: Vec<_> = fields.iter().filter(|f| f.embed).collect();
    let direct_key_lits: Vec<i64> = direct.iter().map(|f| f.key.unwrap()).collect();

    let map_key_pushes: Vec<_> = fields
        .iter()
        .map(|f| {
            if f.embed {
                let ty = &f.kind;
                quote! { keys.extend(<#ty as #cbor_crate::MapDecode>::cbor_map_keys()); }
            } else {
                let key = f.key.unwrap();
                quote! { keys.push(#key); }
            }
        })
        .collect();

    let extract_direct: Vec<_> = direct
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let ty = &f.kind;
            let key = f.key.unwrap();
            if let Some(inner_ty) = extract_option_inner(ty) {
                quote! {
                    let #ident: #ty = if let Some(raw) = entries.remove(&#key) {
                        Some(<#inner_ty as #cbor_crate::Decode>::decode_cbor(&raw.0)?)
                    } else {
                        None
                    };
                }
            } else if let Some(inner_ty) = extract_nullable_inner(ty) {
                quote! {
                    let raw = entries.remove(&#key).ok_or(#cbor_crate::Error::DecodeFailed(
                        format!("missing required key {}", #key)
                    ))?;
                    let #ident: #ty = Some(<#inner_ty as #cbor_crate::Decode>::decode_cbor(&raw.0)?);
                }
            } else {
                quote! {
                    let raw = entries.remove(&#key).ok_or(#cbor_crate::Error::DecodeFailed(
                        format!("missing required key {}", #key)
                    ))?;
                    let #ident: #ty = <#ty as #cbor_crate::Decode>::decode_cbor(&raw.0)?;
                }
            }
        })
        .collect();

    let extract_embeds: Vec<_> = embeds
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let ty = &f.kind;
            quote! {
                let embed_keys: std::collections::BTreeSet<i64> =
                    <#ty as #cbor_crate::MapDecode>::cbor_map_keys().into_iter().collect();
                if embed_keys.is_empty() {
                    return Err(#cbor_crate::Error::DecodeFailed(format!(
                        "embedded field `{}` has no CBOR map keys", stringify!(#ident)
                    )));
                }
                for k in embed_keys.iter() {
                    if direct_keys.contains(k) {
                        return Err(#cbor_crate::Error::DuplicateMapKey(*k));
                    }
                    if !seen_embed_keys.insert(*k) {
                        return Err(#cbor_crate::Error::DuplicateMapKey(*k));
                    }
                }

                let mut subset: std::collections::BTreeMap<i64, #cbor_crate::Raw> = std::collections::BTreeMap::new();
                for k in embed_keys {
                    if let Some(raw) = entries.remove(&k) {
                        subset.insert(k, raw);
                    }
                }
                let #ident = <#ty as #cbor_crate::MapDecode>::decode_map(&mut subset)?;
                if !subset.is_empty() {
                    let unknown: Vec<i64> = subset.keys().copied().collect();
                    return Err(#cbor_crate::Error::DecodeFailed(
                        format!("unknown CBOR map keys: {:?}", unknown)
                    ));
                }
            }
        })
        .collect();

    let embed_state_setup = if embeds.is_empty() {
        quote! {}
    } else {
        quote! {
            let direct_keys: std::collections::BTreeSet<i64> = [#(#direct_key_lits),*].into_iter().collect();
            let mut seen_embed_keys: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
        }
    };

    let construct_fields: Vec<_> = fields.iter().map(|f| &f.ident).collect();

    let map_decode_impl = quote! {
        impl #cbor_crate::MapDecode for #name {
            fn cbor_map_keys() -> Vec<i64> {
                let mut keys = Vec::new();
                #(#map_key_pushes)*
                keys.sort_by(|a, b| #cbor_crate::cbor_key_cmp(*a, *b));
                keys
            }

            fn decode_map(entries: &mut std::collections::BTreeMap<i64, #cbor_crate::Raw>) -> Result<Self, #cbor_crate::Error> {
                #embed_state_setup

                #(#extract_direct)*
                #(#extract_embeds)*
                Ok(Self { #(#construct_fields),* })
            }
        }
    };

    if embeds.is_empty() {
        let mut sorted: Vec<_> = fields.iter().collect();
        sorted.sort_by(|a, b| {
            let ka = cbor_key_bytes(a.key.unwrap());
            let kb = cbor_key_bytes(b.key.unwrap());
            ka.cmp(&kb)
        });

        let len = sorted.len();
        let has_optional = sorted
            .iter()
            .any(|f| extract_option_inner(&f.kind).is_some());

        if !has_optional {
            let decode_fields: Vec<_> = sorted
                .iter()
                .map(|f| {
                    let ident = &f.ident;
                    let ty = &f.kind;
                    let key = f.key.unwrap();
                    let decode_expr = if let Some(inner_ty) = extract_nullable_inner(ty) {
                        quote! { Some(<#inner_ty as #cbor_crate::Decode>::decode_cbor_notrail(dec)?) }
                    } else {
                        quote! { <#ty as #cbor_crate::Decode>::decode_cbor_notrail(dec)? }
                    };
                    quote! {
                        let key = dec.decode_int()?;
                        if key != #key {
                            return Err(#cbor_crate::Error::InvalidMapKeyOrder(key, #key));
                        }
                        let #ident = #decode_expr;
                    }
                })
                .collect();

            return Ok(quote! {
                impl #cbor_crate::Decode for #name {
                    fn decode_cbor(data: &[u8]) -> Result<Self, #cbor_crate::Error> {
                        let mut dec = #cbor_crate::Decoder::new(data);
                        let result = Self::decode_cbor_notrail(&mut dec)?;
                        dec.finish()?;
                        Ok(result)
                    }

                    fn decode_cbor_notrail(dec: &mut #cbor_crate::Decoder) -> Result<Self, #cbor_crate::Error> {
                        let len = dec.decode_map_header()?;
                        if len != #len as u64 {
                            return Err(#cbor_crate::Error::UnexpectedItemCount(len, #len));
                        }
                        #(#decode_fields)*
                        Ok(Self { #(#construct_fields),* })
                    }
                }

                #map_decode_impl
            });
        }

        let decode_fields: Vec<_> = sorted
            .iter()
            .map(|f| {
                let ident = &f.ident;
                let key = f.key.unwrap();
                if let Some(inner_ty) = extract_option_inner(&f.kind) {
                    quote! {
                        let #ident = if remaining > 0 && dec.peek_int()? == #key {
                            dec.decode_int()?;
                            remaining -= 1;
                            Some(<#inner_ty as #cbor_crate::Decode>::decode_cbor_notrail(dec)?)
                        } else {
                            None
                        };
                    }
                } else {
                    let ty = &f.kind;
                    let decode_expr = if let Some(inner_ty) = extract_nullable_inner(ty) {
                        quote! { Some(<#inner_ty as #cbor_crate::Decode>::decode_cbor_notrail(dec)?) }
                    } else {
                        quote! { <#ty as #cbor_crate::Decode>::decode_cbor_notrail(dec)? }
                    };
                    quote! {
                        if remaining == 0 {
                            return Err(#cbor_crate::Error::InvalidMapKeyOrder(0, #key));
                        }
                        let key = dec.decode_int()?;
                        if key != #key {
                            return Err(#cbor_crate::Error::InvalidMapKeyOrder(key, #key));
                        }
                        remaining -= 1;
                        let #ident = #decode_expr;
                    }
                }
            })
            .collect();

        return Ok(quote! {
            impl #cbor_crate::Decode for #name {
                fn decode_cbor(data: &[u8]) -> Result<Self, #cbor_crate::Error> {
                    let mut dec = #cbor_crate::Decoder::new(data);
                    let result = Self::decode_cbor_notrail(&mut dec)?;
                    dec.finish()?;
                    Ok(result)
                }

                fn decode_cbor_notrail(dec: &mut #cbor_crate::Decoder) -> Result<Self, #cbor_crate::Error> {
                    let map_len = dec.decode_map_header()?;
                    if map_len > #len as u64 {
                        return Err(#cbor_crate::Error::UnexpectedItemCount(map_len, #len));
                    }
                    let mut remaining = map_len;
                    #(#decode_fields)*
                    if remaining != 0 {
                        return Err(#cbor_crate::Error::UnexpectedItemCount(map_len, (map_len - remaining) as usize));
                    }
                    Ok(Self { #(#construct_fields),* })
                }
            }

            #map_decode_impl
        });
    }

    Ok(quote! {
        impl #cbor_crate::Decode for #name {
            fn decode_cbor(data: &[u8]) -> Result<Self, #cbor_crate::Error> {
                let mut dec = #cbor_crate::Decoder::new(data);
                let result = Self::decode_cbor_notrail(&mut dec)?;
                dec.finish()?;
                Ok(result)
            }

            fn decode_cbor_notrail(dec: &mut #cbor_crate::Decoder) -> Result<Self, #cbor_crate::Error> {
                let entries = #cbor_crate::decode_map_entries_notrail(dec)?;
                let mut remaining: std::collections::BTreeMap<i64, #cbor_crate::Raw> =
                    entries.into_iter().collect();

                let value = <Self as #cbor_crate::MapDecode>::decode_map(&mut remaining)?;

                if !remaining.is_empty() {
                    let unknown: Vec<i64> = remaining.keys().copied().collect();
                    return Err(#cbor_crate::Error::DecodeFailed(
                        format!("unknown CBOR map keys: {:?}", unknown)
                    ));
                }
                Ok(value)
            }
        }

        #map_decode_impl
    })
}

/// Returns true if the struct has #[cbor(array)] attribute.
fn want_array(input: &DeriveInput) -> bool {
    for attr in &input.attrs {
        if attr.path().is_ident("cbor") {
            let mut is_array = false;
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("array") {
                    is_array = true;
                }
                Ok(())
            });
            if is_array {
                return true;
            }
        }
    }
    false
}

/// Parsed information about a struct field.
struct FieldInfo {
    ident: syn::Ident,
    kind: syn::Type,
    key: Option<i64>, // CBOR map key from #[cbor(key = N)], None for array-mode
    embed: bool,      // #[cbor(embed)] — flatten this field's map into the parent
}

/// Extracts field metadata from a struct, including names, types, and CBOR keys.
fn parse_fields(input: &DeriveInput) -> syn::Result<Vec<FieldInfo>> {
    // Ensure we're only tagging structs with plain fields
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    input,
                    "only named fields supported",
                ));
            }
        },
        _ => return Err(syn::Error::new_spanned(input, "only structs supported")),
    };
    // Collect all the keys from all the fields
    let mut result = Vec::new();

    for field in fields {
        let ident = field.ident.clone().unwrap();
        let kind = field.ty.clone();
        let mut key = None;
        let mut embed = false;

        for attr in &field.attrs {
            if attr.path().is_ident("cbor") {
                attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("key") {
                        let value: Expr = meta.value()?.parse()?;
                        key = Some(parse_key(&value)?);
                    }
                    if meta.path.is_ident("embed") {
                        embed = true;
                    }
                    Ok(())
                })?;
            }
        }
        result.push(FieldInfo {
            ident,
            kind,
            key,
            embed,
        });
    }
    Ok(result)
}

/// Checks if a type is `Option<T>` (but not `Option<Option<T>>`) and returns
/// the inner type `T`. Used to identify omittable map fields.
///
/// Returns `None` for `Option<Option<T>>`: nested options represent a
/// non-omittable nullable field (always present, value is null or T).
fn extract_option_inner(ty: &syn::Type) -> Option<&syn::Type> {
    if let syn::Type::Path(type_path) = ty {
        let segment = type_path.path.segments.last()?;
        if segment.ident == "Option"
            && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
            && args.args.len() == 1
            && let syn::GenericArgument::Type(inner) = args.args.first()?
        {
            // Option<Option<T>> is NOT omittable — it's a non-omittable
            // nullable field. See extract_nullable_inner.
            if is_option_type(inner) {
                return None;
            }
            return Some(inner);
        }
    }
    None
}

/// Checks if a type is `Option<Option<T>>` and returns the inner `Option<T>`.
/// Used to identify non-omittable nullable map fields. During decoding, the
/// derive generates `Some(<Option<T>>::decode(...))` so that null on the wire
/// becomes `Some(None)` rather than `None`.
fn extract_nullable_inner(ty: &syn::Type) -> Option<&syn::Type> {
    if let syn::Type::Path(type_path) = ty {
        let segment = type_path.path.segments.last()?;
        if segment.ident == "Option"
            && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
            && args.args.len() == 1
            && let syn::GenericArgument::Type(inner) = args.args.first()?
            && is_option_type(inner)
        {
            return Some(inner);
        }
    }
    None
}

/// Returns true if the type's last path segment is `Option`.
fn is_option_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
    {
        return segment.ident == "Option";
    }
    false
}

/// Parses an integer expression, handling both positive literals and negation.
fn parse_key(expr: &Expr) -> syn::Result<i64> {
    match expr {
        // Parse positive integers
        Expr::Lit(lit) => match &lit.lit {
            Lit::Int(i) => i.base10_parse(),
            _ => Err(syn::Error::new_spanned(expr, "expected integer literal")),
        },
        // Parse negative integers
        Expr::Unary(unary) => {
            if let syn::UnOp::Neg(_) = unary.op
                && let Expr::Lit(lit) = &*unary.expr
                && let Lit::Int(i) = &lit.lit
            {
                let val: i64 = i.base10_parse()?;
                return Ok(-val);
            }
            Err(syn::Error::new_spanned(expr, "expected integer literal"))
        }
        _ => Err(syn::Error::new_spanned(expr, "expected integer literal")),
    }
}
