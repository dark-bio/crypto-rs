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
            quote! { enc.extend(&self.#ident.encode_cbor()); }
        })
        .collect();

    Ok(quote! {
        impl #cbor_crate::Encode for #name {
            fn encode_cbor(&self) -> Vec<u8> {
                let mut enc = #cbor_crate::Encoder::new();
                enc.encode_array_header(#len);
                #(#encode_fields)*
                enc.finish()
            }
        }
    })
}

/// Generates map-mode `Encode` impl: fields encoded as key-value pairs, sorted by key bytes.
fn derive_encode_map(name: &syn::Ident, fields: &[FieldInfo]) -> syn::Result<TokenStream2> {
    let cbor_crate = quote! { darkbio_crypto::cbor };

    // Validate all fields have keys
    for field in fields {
        if field.key.is_none() {
            return Err(syn::Error::new_spanned(
                &field.ident,
                "map struct fields require #[cbor(key = N)], or use #[cbor(array)]",
            ));
        }
    }
    // Sort fields by CBOR-encoded key bytes for deterministic encoding
    let mut sorted: Vec<_> = fields.iter().collect();
    sorted.sort_by(|a, b| {
        let ka = cbor_key_bytes(a.key.unwrap());
        let kb = cbor_key_bytes(b.key.unwrap());
        ka.cmp(&kb)
    });

    let has_optional = sorted.iter().any(|f| f.optional);

    // Generate code to encode each key-value pair in sorted order
    let encode_fields: Vec<_> = sorted
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let key = f.key.unwrap();
            if f.optional {
                quote! {
                    if let Some(ref val) = self.#ident {
                        enc.encode_int(#key);
                        enc.extend(&val.encode_cbor());
                    }
                }
            } else {
                quote! {
                    enc.encode_int(#key);
                    enc.extend(&self.#ident.encode_cbor());
                }
            }
        })
        .collect();

    if has_optional {
        // Count optional fields to compute length at runtime
        let count_fields: Vec<_> = sorted
            .iter()
            .map(|f| {
                let ident = &f.ident;
                if f.optional {
                    quote! { if self.#ident.is_some() { len += 1; } }
                } else {
                    quote! { len += 1; }
                }
            })
            .collect();

        Ok(quote! {
            impl #cbor_crate::Encode for #name {
                fn encode_cbor(&self) -> Vec<u8> {
                    let mut len: usize = 0;
                    #(#count_fields)*

                    let mut enc = #cbor_crate::Encoder::new();
                    enc.encode_map_header(len);
                    #(#encode_fields)*
                    enc.finish()
                }
            }
        })
    } else {
        let len = sorted.len();
        Ok(quote! {
            impl #cbor_crate::Encode for #name {
                fn encode_cbor(&self) -> Vec<u8> {
                    let mut enc = #cbor_crate::Encoder::new();
                    enc.encode_map_header(#len);
                    #(#encode_fields)*
                    enc.finish()
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
fn derive_decode_map(name: &syn::Ident, fields: &[FieldInfo]) -> syn::Result<TokenStream2> {
    // Validate all fields have keys
    for field in fields {
        if field.key.is_none() {
            return Err(syn::Error::new_spanned(
                &field.ident,
                "map struct fields require #[cbor(key = N)], or use #[cbor(array)]",
            ));
        }
    }
    // Sort fields by CBOR-encoded key bytes (must match encoder order)
    let mut sorted: Vec<_> = fields.iter().collect();
    sorted.sort_by(|a, b| {
        let ka = cbor_key_bytes(a.key.unwrap());
        let kb = cbor_key_bytes(b.key.unwrap());
        ka.cmp(&kb)
    });

    let has_optional = sorted.iter().any(|f| f.optional);

    // Use original field order for struct construction (not sorted order)
    let construct_fields: Vec<_> = fields.iter().map(|f| &f.ident).collect();

    if has_optional {
        derive_decode_map_with_optionals(name, &sorted, &construct_fields)
    } else {
        derive_decode_map_required_only(name, &sorted, &construct_fields)
    }
}

/// Generates map-mode `Decode` impl when all fields are required (no Option fields).
fn derive_decode_map_required_only(
    name: &syn::Ident,
    sorted: &[&FieldInfo],
    construct_fields: &[&syn::Ident],
) -> syn::Result<TokenStream2> {
    let cbor_crate = quote! { darkbio_crypto::cbor };
    let len = sorted.len();

    let decode_fields: Vec<_> = sorted
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let ty = &f.kind;
            let key = f.key.unwrap();
            quote! {
                let key = dec.decode_int()?;
                if key != #key {
                    return Err(#cbor_crate::Error::InvalidMapKeyOrder(key, #key));
                }
                let #ident = <#ty as #cbor_crate::Decode>::decode_cbor_notrail(dec)?;
            }
        })
        .collect();

    Ok(quote! {
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
    })
}

/// Generates map-mode `Decode` impl when some fields are Option (may be omitted).
fn derive_decode_map_with_optionals(
    name: &syn::Ident,
    sorted: &[&FieldInfo],
    construct_fields: &[&syn::Ident],
) -> syn::Result<TokenStream2> {
    let cbor_crate = quote! { darkbio_crypto::cbor };

    let num_required = sorted.iter().filter(|f| !f.optional).count();
    let num_total = sorted.len();

    // Initialize all field variables (Option fields default to None)
    let init_fields: Vec<_> = sorted
        .iter()
        .map(|f| {
            let ident = &f.ident;
            if f.optional {
                quote! { let mut #ident = None; }
            } else {
                let ty = &f.kind;
                quote! { let mut #ident: Option<#ty> = None; }
            }
        })
        .collect();

    // Build match arms: for each key, decode the corresponding field
    let match_arms: Vec<_> = sorted
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let key = f.key.unwrap();
            let inner_ty = &f.inner_ty;
            quote! {
                #key => {
                    #ident = Some(<#inner_ty as #cbor_crate::Decode>::decode_cbor_notrail(dec)?);
                }
            }
        })
        .collect();

    // Build the sorted key list for order validation
    let sorted_keys: Vec<_> = sorted.iter().map(|f| f.key.unwrap()).collect();

    // Unwrap required fields (non-Option), checking they were present
    let unwrap_fields: Vec<_> = sorted
        .iter()
        .map(|f| {
            let ident = &f.ident;
            if f.optional {
                // Already the right type (Option<T>), no unwrap needed
                quote! {}
            } else {
                let key = f.key.unwrap();
                quote! {
                    let #ident = #ident.ok_or(#cbor_crate::Error::MissingMapKey(#key))?;
                }
            }
        })
        .collect();

    Ok(quote! {
        impl #cbor_crate::Decode for #name {
            fn decode_cbor(data: &[u8]) -> Result<Self, #cbor_crate::Error> {
                let mut dec = #cbor_crate::Decoder::new(data);
                let result = Self::decode_cbor_notrail(&mut dec)?;
                dec.finish()?;
                Ok(result)
            }

            fn decode_cbor_notrail(dec: &mut #cbor_crate::Decoder) -> Result<Self, #cbor_crate::Error> {
                let map_len = dec.decode_map_header()? as usize;
                if map_len < #num_required || map_len > #num_total {
                    return Err(#cbor_crate::Error::UnexpectedItemCount(map_len as u64, #num_required));
                }
                #(#init_fields)*

                // Track key ordering using the expected key sequence
                const SORTED_KEYS: &[i64] = &[#(#sorted_keys),*];
                let mut key_idx = 0usize;

                for _ in 0..map_len {
                    let key = dec.decode_int()?;

                    // Advance past optional keys that were skipped
                    while key_idx < SORTED_KEYS.len() && SORTED_KEYS[key_idx] != key {
                        key_idx += 1;
                    }
                    if key_idx >= SORTED_KEYS.len() {
                        return Err(#cbor_crate::Error::InvalidMapKeyOrder(key, *SORTED_KEYS.last().unwrap()));
                    }
                    match key {
                        #(#match_arms)*
                        _ => return Err(#cbor_crate::Error::InvalidMapKeyOrder(key, SORTED_KEYS[key_idx])),
                    }
                    key_idx += 1;
                }
                #(#unwrap_fields)*
                Ok(Self { #(#construct_fields),* })
            }
        }
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
    key: Option<i64>,    // CBOR map key from #[cbor(key = N)], None for array-mode
    optional: bool,      // Whether the field type is Option<T>
    inner_ty: syn::Type, // Inner type (T for Option<T>, same as kind otherwise)
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

        for attr in &field.attrs {
            if attr.path().is_ident("cbor") {
                attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("key") {
                        let value: Expr = meta.value()?.parse()?;
                        key = Some(parse_key(&value)?);
                    }
                    Ok(())
                })?;
            }
        }
        let (optional, inner_ty) = extract_option_inner(&kind);
        result.push(FieldInfo {
            ident,
            kind,
            key,
            optional,
            inner_ty,
        });
    }
    Ok(result)
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

/// Returns (true, inner_type) if `ty` is `Option<T>`, otherwise (false, ty.clone()).
fn extract_option_inner(ty: &syn::Type) -> (bool, syn::Type) {
    if let syn::Type::Path(type_path) = ty {
        if let Some(seg) = type_path.path.segments.last() {
            if seg.ident == "Option" {
                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                        return (true, inner.clone());
                    }
                }
            }
        }
    }
    (false, ty.clone())
}
