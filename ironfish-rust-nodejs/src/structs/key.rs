/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use ironfish_rust::keys::{MNEMONIC_SIZE, SPEND_KEY_SIZE};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::to_napi_err;

#[napi]
pub const SPEND_KEY_LENGTH: u32 = SPEND_KEY_SIZE as u32;

#[napi]
pub const MNEMONIC_LENGTH: u32 = MNEMONIC_SIZE as u32;

#[napi(js_name = "SaplingKey")]
pub struct SaplingKey {}

#[napi]
impl SaplingKey {
    // returns buffer of MNEMONIC_SIZE length
    #[napi]
    pub fn words_spending_key(spending_key: String, language_code: String) -> Result<Buffer> {
        let spending_key_bytes: [u8; SPEND_KEY_SIZE] =
            spending_key.as_bytes().try_into().map_err(to_napi_err)?;
        let words  =
            ironfish_rust::SaplingKey::words_spending_key(spending_key_bytes, &language_code)
                .map_err(to_napi_err)?;
        Ok(Buffer::from(&words[..]))
    }
}
