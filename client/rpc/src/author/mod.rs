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

#[cfg(test)]
mod tests;

use std::{convert::TryInto, sync::Arc};

use crate::SubscriptionTaskExecutor;

use codec::{Decode, Encode};
use futures::{FutureExt, StreamExt};
use jsonrpsee::{
	types::{
		async_trait,
		error::{CallError as RpseeCallError, Error as JsonRpseeError},
		JsonRpcResult,
	},
	RpcModule, SubscriptionSink,
};
use sc_rpc_api::{author::AuthorApiServer, DenyUnsafe};
use sc_transaction_pool_api::{
	error::IntoPoolError, InPoolTransaction, TransactionFor, TransactionPool, TransactionSource,
	TxHash,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::Bytes;
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use sp_runtime::generic;
use sp_session::SessionKeys;

use self::error::{Error, Result};
/// Re-export the API for backward compatibility.
pub use sc_rpc_api::author::*;

/// Authoring API
pub struct Author<P, Client> {
	/// Substrate client
	client: Arc<Client>,
	/// Transactions pool
	pool: Arc<P>,
	/// The key store.
	keystore: SyncCryptoStorePtr,
	/// Whether to deny unsafe calls
	deny_unsafe: DenyUnsafe,
	/// Executor to spawn subscriptions.
	executor: Arc<SubscriptionTaskExecutor>,
}

impl<P, Client> Author<P, Client> {
	/// Create new instance of Authoring API.
	pub fn new(
		client: Arc<Client>,
		pool: Arc<P>,
		keystore: SyncCryptoStorePtr,
		deny_unsafe: DenyUnsafe,
		executor: Arc<SubscriptionTaskExecutor>,
	) -> Self {
		Author { client, pool, keystore, deny_unsafe, executor }
	}
}

impl<P, Client> Author<P, Client>
where
	P: TransactionPool + Sync + Send + 'static,
	Client: HeaderBackend<P::Block> + ProvideRuntimeApi<P::Block> + Send + Sync + 'static,
	Client::Api: SessionKeys<P::Block>,
{
	/// Convert a [`Author`] to an [`RpcModule`]. Registers all the RPC methods available with the RPC server.
	pub fn into_rpc_module(self) -> std::result::Result<RpcModule<Self>, JsonRpseeError> {
		let mut module = RpcModule::new(self);

		module.register_method::<_, _, RpseeCallError>("author_insertKey", |params, author| {
			author.deny_unsafe.check_if_safe()?;
			let (key_type, suri, public): (String, String, Bytes) = params.parse()?;
			let key_type = key_type.as_str().try_into().map_err(|_| Error::BadKeyType)?;
			SyncCryptoStore::insert_unknown(&*author.keystore, key_type, &suri, &public[..])
				.map_err(|_| Error::KeyStoreUnavailable)?;
			Ok(())
		})?;

		module.register_method::<Bytes, _, RpseeCallError>(
			"author_rotateKeys",
			|_params, author| {
				author.deny_unsafe.check_if_safe()?;

				let best_block_hash = author.client.info().best_hash;
				author
					.client
					.runtime_api()
					.generate_session_keys(&generic::BlockId::Hash(best_block_hash), None)
					.map(Into::into)
					.map_err(|api_err| Error::Client(Box::new(api_err)).into())
			},
		)?;

		module.register_method::<_, _, RpseeCallError>(
			"author_hasSessionKeys",
			|params, author| {
				author.deny_unsafe.check_if_safe()?;

				let session_keys: Bytes = params.one()?;
				let best_block_hash = author.client.info().best_hash;
				let keys = author
					.client
					.runtime_api()
					.decode_session_keys(
						&generic::BlockId::Hash(best_block_hash),
						session_keys.to_vec(),
					)
					.map_err(|e| RpseeCallError::Failed(Box::new(e)))?
					.ok_or_else(|| Error::InvalidSessionKeys)?;

				Ok(SyncCryptoStore::has_keys(&*author.keystore, &keys))
			},
		)?;

		module.register_method::<_, _, RpseeCallError>("author_hasKey", |params, author| {
			author.deny_unsafe.check_if_safe()?;

			let (public_key, key_type) = params.parse::<(Vec<u8>, String)>()?;
			let key_type = key_type.as_str().try_into().map_err(|_| Error::BadKeyType)?;
			Ok(SyncCryptoStore::has_keys(&*author.keystore, &[(public_key, key_type)]))
		})?;

		module.register_async_method::<TxHash<P>, _, _>(
			"author_submitExtrinsic",
			|params, author| {
				let ext: Bytes = match params.one() {
					Ok(ext) => ext,
					Err(e) => return Box::pin(futures::future::err(e)),
				};
				async move {
					let xt = match Decode::decode(&mut &ext[..]) {
						Ok(xt) => xt,
						Err(err) => return Err(RpseeCallError::Failed(err.into())),
					};
					let best_block_hash = author.client.info().best_hash;
					author
						.pool
						.submit_one(&generic::BlockId::hash(best_block_hash), TX_SOURCE, xt)
						.await
						.map_err(|e| {
							e.into_pool_error()
								.map(|e| RpseeCallError::Failed(Box::new(e)))
								.unwrap_or_else(|e| RpseeCallError::Failed(Box::new(e)))
						})
				}
				.boxed()
			},
		)?;

		module.register_method::<Vec<Bytes>, _, RpseeCallError>(
			"author_pendingExtrinsics",
			|_, author| Ok(author.pool.ready().map(|tx| tx.data().encode().into()).collect()),
		)?;

		module.register_method::<Vec<TxHash<P>>, _, RpseeCallError>(
			"author_removeExtrinsic",
			|params, author| {
				author.deny_unsafe.check_if_safe()?;

				let bytes_or_hash: Vec<hash::ExtrinsicOrHash<TxHash<P>>> = params.parse()?;
				let hashes = bytes_or_hash
					.into_iter()
					.map(|x| match x {
						hash::ExtrinsicOrHash::Hash(h) => Ok(h),
						hash::ExtrinsicOrHash::Extrinsic(bytes) => {
							let xt = Decode::decode(&mut &bytes[..])?;
							Ok(author.pool.hash_of(&xt))
						},
					})
					.collect::<Result<Vec<_>>>()?;

				Ok(author
					.pool
					.remove_invalid(&hashes)
					.into_iter()
					.map(|tx| tx.hash().clone())
					.collect())
			},
		)?;

		module.register_subscription(
			"author_submitAndWatchExtrinsic",
			"author_unwatchExtrinsic",
			|params, mut sink, ctx| {
				let xt: Bytes = params.one()?;
				let best_block_hash = ctx.client.info().best_hash;
				let dxt = TransactionFor::<P>::decode(&mut &xt[..])
					.map_err(|e| JsonRpseeError::Custom(e.to_string()))?;

				let executor = ctx.executor.clone();
				let fut = async move {
					let stream = match ctx
						.pool
						.submit_and_watch(&generic::BlockId::hash(best_block_hash), TX_SOURCE, dxt)
						.await
					{
						Ok(stream) => stream,
						Err(e) => {
							let _ = sink.send(&format!(
								"txpool subscription failed: {:?}; subscription useless",
								e
							));
							return
						},
					};

					stream
						.for_each(|item| {
							let _ = sink.send(&item);
							futures::future::ready(())
						})
						.await;
				};

				executor.execute(Box::pin(fut));
				Ok(())
			},
		)?;

		Ok(module)
	}
}

#[async_trait]
impl<P, Client> AuthorApiServer for Author<P, Client>
where
	P: TransactionPool + Sync + Send + 'static,
	Client: HeaderBackend<P::Block> + ProvideRuntimeApi<P::Block> + Send + Sync + 'static,
	Client::Api: SessionKeys<P::Block>,
{
	async fn submit_extrinsic(&self, _extrinsic: Bytes) -> JsonRpcResult<Hash> {
		todo!();
	}

	fn insert_key(&self, key_type: String, suri: String, public: Bytes) -> JsonRpcResult<()> {
		self.deny_unsafe.check_if_safe().map_err(RpseeCallError::from)?;
		let key_type = key_type
			.as_str()
			.try_into()
			.map_err(|_| Error::BadKeyType)
			.map_err(RpseeCallError::from)?;
		SyncCryptoStore::insert_unknown(&*self.keystore, key_type, &suri, &public[..])
			.map_err(|_| Error::KeyStoreUnavailable)
			.map_err(RpseeCallError::from)?;
		Ok(())
	}

	fn rotate_keys(&self) -> JsonRpcResult<Bytes> {
		todo!();
	}

	fn has_session_keys(&self, _session_keys: Bytes) -> JsonRpcResult<bool> {
		todo!();
	}

	fn has_key(&self, _public_key: Bytes, _key_type: String) -> JsonRpcResult<bool> {
		todo!();
	}

	fn pending_extrinsics(&self) -> JsonRpcResult<Vec<Bytes>> {
		todo!();
	}

	fn remove_extrinsic(
		&self,
		_bytes_or_hash: Vec<hash::ExtrinsicOrHash<Hash>>,
	) -> JsonRpcResult<Vec<Hash>> {
		todo!();
	}

	fn watch_extrinsic(&self, _sink: SubscriptionSink, _xt: Bytes) {
		todo!();
	}
}

/// Currently we treat all RPC transactions as externals.
///
/// Possibly in the future we could allow opt-in for special treatment
/// of such transactions, so that the block authors can inject
/// some unique transactions via RPC and have them included in the pool.
const TX_SOURCE: TransactionSource = TransactionSource::External;
