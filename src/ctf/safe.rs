//! Gnosis Safe client for executing transactions through a Safe wallet.
//!
//! This module provides `SafeClient` which wraps arbitrary contract calls
//! in Safe's `execTransaction`, allowing the Safe to be the `msg.sender`.

use alloy::primitives::{Address, B256, Bytes, U256, address};
use alloy::providers::Provider;
use alloy::signers::Signer;
use alloy::sol;
use alloy::sol_types::SolCall;
use thiserror::Error;

/// CTF contract address on Polygon
pub const CTF_ADDRESS: Address = address!("4D97DCd97eC945f40cF65F87097ACe5EA0476045");

// Gnosis Safe interface - only the methods we need
// Note: execTransaction has 11 parameters which exceeds clippy's default limit
#[allow(clippy::too_many_arguments)]
mod gnosis_safe {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IGnosisSafe {
            function nonce() external view returns (uint256);
            function execTransaction(
                address to,
                uint256 value,
                bytes calldata data,
                uint8 operation,
                uint256 safeTxGas,
                uint256 baseGas,
                uint256 gasPrice,
                address gasToken,
                address payable refundReceiver,
                bytes calldata signatures
            ) external payable returns (bool success);
        }
    }
}
pub use gnosis_safe::IGnosisSafe;

// CTF interface for building redemption calldata
sol! {
    interface IConditionalTokens {
        function redeemPositions(
            address collateralToken,
            bytes32 parentCollectionId,
            bytes32 conditionId,
            uint256[] calldata indexSets
        ) external;
    }
}

/// SafeTx struct matching Gnosis Safe's EIP-712 typed data
/// Note: This is for computing the transaction hash to sign
#[derive(Debug, Clone)]
pub struct SafeTx {
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub operation: u8,
    pub safe_tx_gas: U256,
    pub base_gas: U256,
    pub gas_price: U256,
    pub gas_token: Address,
    pub refund_receiver: Address,
    pub nonce: U256,
}

impl SafeTx {
    /// Compute the EIP-712 struct hash for this SafeTx
    pub fn struct_hash(&self) -> B256 {
        use alloy::primitives::keccak256;

        // SafeTx type hash: keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")
        let type_hash: B256 = "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8"
            .parse()
            .unwrap();

        // Encode the struct data
        let data_hash = keccak256(&self.data);

        let encoded = [
            type_hash.as_slice(),
            &self.to.into_word()[..],
            &B256::from(self.value)[..],
            data_hash.as_slice(),
            &B256::from(U256::from(self.operation))[..],
            &B256::from(self.safe_tx_gas)[..],
            &B256::from(self.base_gas)[..],
            &B256::from(self.gas_price)[..],
            &self.gas_token.into_word()[..],
            &self.refund_receiver.into_word()[..],
            &B256::from(self.nonce)[..],
        ]
        .concat();

        keccak256(&encoded)
    }
}

/// Errors that can occur during Safe operations
#[derive(Error, Debug)]
pub enum SafeError {
    #[error("Failed to get Safe nonce: {0}")]
    NonceError(String),

    #[error("Failed to sign transaction: {0}")]
    SigningError(String),

    #[error("Failed to execute transaction: {0}")]
    ExecutionError(String),

    #[error("Transaction reverted")]
    Reverted,

    #[error("Provider error: {0}")]
    ProviderError(String),
}

/// Response from a Safe transaction execution
#[derive(Debug, Clone)]
pub struct SafeExecResponse {
    /// Transaction hash
    pub transaction_hash: B256,
    /// Block number where the transaction was mined
    pub block_number: u64,
}

/// Client for executing transactions through a Gnosis Safe
pub struct SafeClient<P> {
    provider: P,
    safe_address: Address,
    chain_id: u64,
}

impl<P: Provider + Clone> SafeClient<P> {
    /// Create a new SafeClient
    pub fn new(provider: P, safe_address: Address, chain_id: u64) -> Self {
        Self {
            provider,
            safe_address,
            chain_id,
        }
    }

    /// Get the current nonce of the Safe
    pub async fn get_nonce(&self) -> Result<U256, SafeError> {
        let safe = IGnosisSafe::new(self.safe_address, &self.provider);
        safe.nonce()
            .call()
            .await
            .map_err(|e| SafeError::NonceError(e.to_string()))
    }

    /// Compute the EIP-712 domain separator for this Safe
    fn domain_separator(&self) -> B256 {
        use alloy::primitives::keccak256;

        // Safe domain: keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
        // Note: Safe does NOT use name or version in its domain
        let domain_type_hash: B256 =
            "0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218"
                .parse()
                .unwrap();

        let encoded = [
            domain_type_hash.as_slice(),
            &B256::from(U256::from(self.chain_id))[..],
            &self.safe_address.into_word()[..],
        ]
        .concat();

        keccak256(&encoded)
    }

    /// Compute the full EIP-712 hash to sign
    fn safe_tx_hash(&self, safe_tx: &SafeTx) -> B256 {
        use alloy::primitives::keccak256;

        let domain_separator = self.domain_separator();
        let struct_hash = safe_tx.struct_hash();

        // EIP-712: keccak256("\x19\x01" || domainSeparator || structHash)
        let encoded = [
            &[0x19, 0x01][..],
            domain_separator.as_slice(),
            struct_hash.as_slice(),
        ]
        .concat();

        keccak256(&encoded)
    }

    /// Execute a transaction through the Safe
    ///
    /// # Arguments
    /// * `to` - Target contract address
    /// * `data` - Calldata for the target contract
    /// * `signer` - The EOA signer that controls the Safe
    pub async fn exec_transaction<S: Signer + Sync>(
        &self,
        to: Address,
        data: Bytes,
        signer: &S,
    ) -> Result<SafeExecResponse, SafeError> {
        // Get current nonce
        let nonce = self.get_nonce().await?;

        // Build SafeTx with zero gas params (Safe will estimate)
        let safe_tx = SafeTx {
            to,
            value: U256::ZERO,
            data: data.clone(),
            operation: 0, // Call (not DelegateCall)
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce,
        };

        // Compute the hash to sign
        let tx_hash = self.safe_tx_hash(&safe_tx);

        // Sign the hash
        let signature = signer
            .sign_hash(&tx_hash)
            .await
            .map_err(|e| SafeError::SigningError(e.to_string()))?;

        // Convert signature to Safe format
        // Safe expects r || s || v
        // Since we use sign_hash (direct ECDSA over the Safe tx hash), we use v = 27/28
        // DO NOT convert to v=31/32 (eth_sign type) - that's for pre-hashed messages with prefix
        let sig_bytes = signature.as_bytes().to_vec();

        // Create Safe instance and execute the transaction
        let safe = IGnosisSafe::new(self.safe_address, &self.provider);
        let pending_tx = safe
            .execTransaction(
                safe_tx.to,
                safe_tx.value,
                safe_tx.data,
                safe_tx.operation,
                safe_tx.safe_tx_gas,
                safe_tx.base_gas,
                safe_tx.gas_price,
                safe_tx.gas_token,
                safe_tx.refund_receiver,
                Bytes::from(sig_bytes),
            )
            .send()
            .await
            .map_err(|e| SafeError::ExecutionError(e.to_string()))?;

        let transaction_hash = *pending_tx.tx_hash();

        let receipt = pending_tx
            .get_receipt()
            .await
            .map_err(|e| SafeError::ExecutionError(e.to_string()))?;

        let block_number = receipt.block_number.ok_or_else(|| {
            SafeError::ExecutionError("Block number not available in receipt".to_owned())
        })?;

        Ok(SafeExecResponse {
            transaction_hash,
            block_number,
        })
    }

    /// Convenience method to redeem CTF positions through the Safe
    ///
    /// # Arguments
    /// * `collateral_token` - The collateral token address (e.g., USDC)
    /// * `condition_id` - The condition ID to redeem
    /// * `signer` - The EOA signer that controls the Safe
    pub async fn redeem_ctf_positions<S: Signer + Sync>(
        &self,
        collateral_token: Address,
        condition_id: B256,
        signer: &S,
    ) -> Result<SafeExecResponse, SafeError> {
        // Build the CTF redeemPositions calldata
        let call = IConditionalTokens::redeemPositionsCall {
            collateralToken: collateral_token,
            parentCollectionId: B256::ZERO,
            conditionId: condition_id,
            indexSets: vec![U256::from(1), U256::from(2)], // Binary market: YES=1, NO=2
        };

        let calldata = Bytes::from(call.abi_encode());

        // Execute through Safe
        self.exec_transaction(CTF_ADDRESS, calldata, signer).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_tx_type_hash() {
        // Verify the SafeTx type hash is correct
        use alloy::primitives::keccak256;

        let type_string = "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";
        let computed_hash = keccak256(type_string.as_bytes());

        let expected: B256 = "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8"
            .parse()
            .unwrap();

        assert_eq!(computed_hash, expected);
    }

    #[test]
    fn test_domain_type_hash() {
        // Verify the domain type hash is correct
        use alloy::primitives::keccak256;

        let type_string = "EIP712Domain(uint256 chainId,address verifyingContract)";
        let computed_hash = keccak256(type_string.as_bytes());

        let expected: B256 = "0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218"
            .parse()
            .unwrap();

        assert_eq!(computed_hash, expected);
    }
}
