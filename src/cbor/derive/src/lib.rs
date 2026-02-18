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
use syn::{
    Data, DeriveInput, Expr, Fields, GenericArgument, Lit, PathArguments, Type, TypePath,
    parse_macro_input,
};

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

    let count_fields: Vec<_> = sorted
        .iter()
        .map(|f| {
            let ident = &f.ident;
            if f.option_inner.is_some() {
                quote! {
                    if self.#ident.is_some() {
                        len += 1;
                    }
                }
            } else {
                quote! {
                    len += 1;
                }
            }
        })
        .collect();

    // Generate code to encode each key-value pair in sorted order
    let encode_fields: Vec<_> = sorted
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let key = f.key.unwrap();
            if f.option_inner.is_some() {
                quote! {
                    if let Some(value) = &self.#ident {
                        enc.encode_int(#key);
                        enc.extend(&value.encode_cbor());
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

    Ok(quote! {
        impl #cbor_crate::Encode for #name {
            fn encode_cbor(&self) -> Vec<u8> {
                let mut enc = #cbor_crate::Encoder::new();
                let mut len: usize = 0;
                #(#count_fields)*
                enc.encode_map_header(len);
                #(#encode_fields)*
                enc.finish()
            }
        }
    })
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
    // Sort fields by CBOR-encoded key bytes (must match encoder order)
    let mut sorted: Vec<_> = fields.iter().collect();
    sorted.sort_by(|a, b| {
        let ka = cbor_key_bytes(a.key.unwrap());
        let kb = cbor_key_bytes(b.key.unwrap());
        ka.cmp(&kb)
    });

    let len = sorted.len();
    let min_len = sorted.iter().filter(|f| f.option_inner.is_none()).count();

    let init_fields: Vec<_> = fields
        .iter()
        .map(|f| {
            let ident = &f.ident;
            if f.option_inner.is_some() {
                let inner = f.option_inner.as_ref().unwrap();
                quote! { let mut #ident: Option<#inner> = None; }
            } else {
                let ty = &f.kind;
                quote! { let mut #ident: Option<#ty> = None; }
            }
        })
        .collect();

    let key_arms: Vec<_> = sorted
        .iter()
        .enumerate()
        .map(|(idx, f)| {
            let key = f.key.unwrap();
            let ident = &f.ident;
            let next_idx = idx + 1;
            if let Some(inner) = &f.option_inner {
                quote! {
                    #key => {
                        if expected > #idx {
                            return Err(#cbor_crate::Error::InvalidMapKeyOrder(key, #key));
                        }
                        while expected < #idx {
                            if !optional_flags[expected] {
                                return Err(#cbor_crate::Error::InvalidMapKeyOrder(key, expected_keys[expected]));
                            }
                            expected += 1;
                        }
                        let value = <#inner as #cbor_crate::Decode>::decode_cbor_notrail(dec)?;
                        #ident = Some(value);
                        expected = #next_idx;
                    }
                }
            } else {
                let ty = &f.kind;
                quote! {
                    #key => {
                        if expected > #idx {
                            return Err(#cbor_crate::Error::InvalidMapKeyOrder(key, #key));
                        }
                        while expected < #idx {
                            if !optional_flags[expected] {
                                return Err(#cbor_crate::Error::InvalidMapKeyOrder(key, expected_keys[expected]));
                            }
                            expected += 1;
                        }
                        let value = <#ty as #cbor_crate::Decode>::decode_cbor_notrail(dec)?;
                        #ident = Some(value);
                        expected = #next_idx;
                    }
                }
            }
        })
        .collect();

    let missing_required_checks: Vec<_> = fields
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let key = f.key.unwrap();
            if f.option_inner.is_some() {
                quote! {}
            } else {
                quote! {
                    if #ident.is_none() {
                        return Err(#cbor_crate::Error::DecodeFailed(
                            format!("missing required map key: {}", #key)
                        ));
                    }
                }
            }
        })
        .collect();

    let construct_fields: Vec<_> = fields
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let key = f.key.unwrap();
            if f.option_inner.is_some() {
                quote! { #ident: #ident }
            } else {
                quote! {
                    #ident: #ident.ok_or_else(|| {
                        #cbor_crate::Error::DecodeFailed(format!("missing required map key: {}", #key))
                    })?
                }
            }
        })
        .collect();

    let expected_keys: Vec<_> = sorted.iter().map(|f| f.key.unwrap()).collect();
    let optional_flags: Vec<_> = sorted.iter().map(|f| f.option_inner.is_some()).collect();

    Ok(quote! {
        impl #cbor_crate::Decode for #name {
            fn decode_cbor(data: &[u8]) -> Result<Self, #cbor_crate::Error> {
                let mut dec = #cbor_crate::Decoder::new(data);
                let result = Self::decode_cbor_notrail(&mut dec)?;
                dec.finish()?; // Ensure no trailing data
                Ok(result)
            }

            fn decode_cbor_notrail(dec: &mut #cbor_crate::Decoder) -> Result<Self, #cbor_crate::Error> {
                let len = dec.decode_map_header()?;
                if len < #min_len as u64 || len > #len as u64 {
                    return Err(#cbor_crate::Error::UnexpectedItemCount(len, #len));
                }
                #(#init_fields)*
                let expected_keys: &[i64] = &[#(#expected_keys),*];
                let optional_flags: &[bool] = &[#(#optional_flags),*];
                let mut expected: usize = 0;

                for _ in 0..len {
                    let key = dec.decode_int()?;
                    match key {
                        #(#key_arms)*
                        _ => {
                            let want = if expected < expected_keys.len() {
                                expected_keys[expected]
                            } else {
                                expected_keys[expected_keys.len() - 1]
                            };
                            return Err(#cbor_crate::Error::InvalidMapKeyOrder(key, want));
                        }
                    }
                }

                #(#missing_required_checks)*
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
    kind: Type,
    option_inner: Option<Type>,
    key: Option<i64>, // CBOR map key from #[cbor(key = N)], None for array-mode
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
        let option_inner = option_inner_type(&kind);
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
        result.push(FieldInfo {
            ident,
            kind,
            option_inner,
            key,
        });
    }
    Ok(result)
}

/// If a type is Option<T>, returns T.
fn option_inner_type(ty: &Type) -> Option<Type> {
    let Type::Path(TypePath { qself: None, path }) = ty else {
        return None;
    };
    let segment = path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    if args.args.len() != 1 {
        return None;
    }
    match args.args.first()? {
        GenericArgument::Type(inner) => Some(inner.clone()),
        _ => None,
    }
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
