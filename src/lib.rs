// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg_attr(not(test), no_std)]

//! Gimlet Inspector protocol definition.
//!
//! The types in this file are intended to be encoded with `hubpack` and stuffed
//! into a UDP packet. Messages to Gimlet use the `Request` type. Responses from
//! Gimlet use the `*Response` types -- a response structure may be specific to
//! the request. In both cases, certain requests/responses may append binary
//! data _after_ the `hubpack`-encoded data. This is documented below on the
//! specific items.

use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

/// Request format to the inspector agent.
///
/// This is an enum so that we implicitly get a protocol version field at the
/// start of all encoded packets. In the event that multiple versions coexist at
/// one time, we can add multiple variants. As versions are obsoleted, we can
/// replace them with stub variants to ensure their indexes don't get reused.
///
/// The downside of this approach is that it will fail at 256 versions.
#[derive(
    Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, SerializedSize,
)]
pub enum Request {
    /// A request in v0 consists only of the name of the query to be issued.
    V0(QueryV0),
}

/// Maximum trailer size for any defined `Request`. In the event that we start
/// using request trailers, we'll want to compute this somehow.
pub const REQUEST_TRAILER: usize = QUERY_V0_TRAILER;

/// Queries that can be sent in V0. Don't send this raw, use `Request`.
///
/// The order and presence of variants in this enum _is_ the protocol
/// definition; do not reorder or remove variants. You can add new variants at
/// the end, but they will not be compatible with any earlier firmware.
#[derive(
    Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, SerializedSize,
)]
pub enum QueryV0 {
    /// Asks the agent to interrogate the sequencer FPGA and send the register
    /// contents back. The response is always a `SequencerRegistersResponseV0`.
    SequencerRegisters,
}

/// Maximum trailer size for any `QueryV0`.
pub const QUERY_V0_TRAILER: usize = 0;

/// Maximum size of any possible response in protocol V0. Clients should know
/// what response to expect, and don't need to use this constant -- it's
/// intended for servers.
pub const ANY_RESPONSE_V0_MAX_SIZE: usize =
    SequencerRegistersResponseV0::MAX_SIZE + SEQ_REG_RESP_V0_TRAILER;

/// Response sent in response to `QueryV0::SequencerRegisters`. The variants in
/// this enum _are_ the protocol definition. Add variants only at the end, and
/// note that adding a variant will cause that response to be incompatible with
/// existing clients. (Other responses will still work.)
#[derive(
    Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, SerializedSize,
)]
pub enum SequencerRegistersResponseV0 {
    /// The agent successfully contacted the sequencer and collected its
    /// registers. They are appended in the binary payload section of the
    /// message. The number of bytes appended may depend on the sequencer
    /// revision, but the sequencer revision is always in the first bytes of the
    /// registers. At the time of this writing, 64 bytes will be appended.
    Success,

    /// The agent was unable to contact the sequencer task because it crashed
    /// during the attempt. No data is attached.
    SequencerTaskDead,

    /// The agent contacted the sequencer task, but _it_ was unable to contact
    /// the FPGA. The only way this can fail in the current sequencer is the
    /// `ReadRegsFailure` variant, which is implied here. No data is attached.
    SequencerReadRegsFailed,
}

/// Current limit on "trailer" bytes following a SequencerRegistersResponseV0.
/// Allocate this much space beyond the hubpack suggested size.
pub const SEQ_REG_RESP_V0_TRAILER: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v0_seq_regs_encoding_check() {
        let message = Request::V0(QueryV0::SequencerRegisters);
        let mut encoded = [0; Request::MAX_SIZE];
        let len = hubpack::serialize(&mut encoded, &message).unwrap();

        assert_eq!(len, 2);
        assert_eq!(
            &encoded[..2],
            &[
                0, // encoded version
                0, // sequencer registers query
            ]
        );
    }

    #[test]
    fn v0_seq_regs_response_encoding_check() {
        // This test checks that these three variants serialize to dense small
        // integers starting at 0, in this exact order:
        let variants = [
            SequencerRegistersResponseV0::Success,
            SequencerRegistersResponseV0::SequencerTaskDead,
            SequencerRegistersResponseV0::SequencerReadRegsFailed,
        ];
        for (i, v) in variants.into_iter().enumerate() {
            let mut encoded = [0; SequencerRegistersResponseV0::MAX_SIZE];
            let len = hubpack::serialize(&mut encoded, &v).unwrap();
            assert_eq!(len, 1);
            assert_eq!(encoded[0], i as u8);
        }
    }
}
