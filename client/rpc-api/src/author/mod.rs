// This file is part of Substrate.

// Copyright (C) 2017-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Substrate block-author/full-node API.

pub mod error;
pub mod hash;

use jsonrpsee::{proc_macros::rpc, types::JsonRpcResult};
use sc_transaction_pool_api::TransactionStatus;
use sp_core::Bytes;

/// Dummy type because generics doesn't work
pub type Hash = sp_core::H256;
/// Dummy type because generics doesn't work
pub type BlockHash = Vec<u8>;

// TODO(niklasad1): the generic type params are ignored by jsonrpsee
// https://github.com/paritytech/jsonrpsee/issues/426
#[rpc(server)]
pub trait AuthorApi<Hash, BlockHash> {
	/// Submit hex-encoded extrinsic for inclusion in block.
	#[method(name = "author_submitExtrinsic")]
	async fn submit_extrinsic(&self, extrinsic: Bytes) -> JsonRpcResult<Hash>;

	/// Insert a key into the keystore.
	#[method(name = "author_insertKey")]
	fn insert_key(&self, key_type: String, suri: String, public: Bytes) -> JsonRpcResult<()>;

	/// Generate new session keys and returns the corresponding public keys.
	#[method(name = "author_rotateKeys")]
	fn rotate_keys(&self) -> JsonRpcResult<Bytes>;

	/// Checks if the keystore has private keys for the given session public keys.
	///
	/// `session_keys` is the SCALE encoded session keys object from the runtime.
	///
	/// Returns `true` iff all private keys could be found.
	#[method(name = "author_hasSessionKeys")]
	fn has_session_keys(&self, session_keys: Bytes) -> JsonRpcResult<bool>;

	/// Checks if the keystore has private keys for the given public key and key type.
	///
	/// Returns `true` if a private key could be found.
	#[method(name = "author_hasKey")]
	fn has_key(&self, public_key: Bytes, key_type: String) -> JsonRpcResult<bool>;

	/// Returns all pending extrinsics, potentially grouped by sender.
	#[method(name = "author_pendingExtrinsics")]
	fn pending_extrinsics(&self) -> JsonRpcResult<Vec<Bytes>>;

	/// Remove given extrinsic from the pool and temporarily ban it to prevent reimporting.
	#[method(name = "author_removeExtrinsic")]
	fn remove_extrinsic(
		&self,
		bytes_or_hash: Vec<hash::ExtrinsicOrHash<Hash>>,
	) -> JsonRpcResult<Vec<Hash>>;

	/// Submit an extrinsic to watch.
	///
	/// See [`TransactionStatus`](sc_transaction_pool_api::TransactionStatus) for details on
	/// transaction life cycle.
	#[subscription(
		name = "author_submitAndWatchExtrinsic"
		unsub = "author_unwatchExtrinsic",
		item = TransactionStatus<Hash, BlockHash>,
	)]
	fn watch_extrinsic(&self, extrinsic: Bytes);
}
