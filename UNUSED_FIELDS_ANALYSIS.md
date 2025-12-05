# Unused Event Fields Analysis

This document lists all fields from event structs that are NOT being used in the parsers.
AI Generated.

## 1. LinkTokenStarted (`parser_its_link_token_started.rs`)

**Struct Definition (all fields):**
- `token_id: [u8; 32]`
- `destination_chain: String`
- `source_token_address: Pubkey`
- `destination_token_address: Vec<u8>`
- `token_manager_type: u8`
- `params: Vec<u8>`

**Fields USED:**
- `destination_chain`
- `token_id`
- `source_token_address`
- `destination_token_address`
- `token_manager_type`

**Fields NOT USED:**
- ❌ **`params`** - Explicitly commented out on line 107: `//params: parsed.params, // TBD if we need this`

---

## 2. TokenMetadataRegistered (`parser_its_token_metadata_registered.rs`)

**Struct Definition (all fields):**
- `token_address: Pubkey`
- `decimals: u8`

**Fields USED:**
- `token_address`
- `decimals`

**Fields NOT USED:**
- ✅ **None** - All fields are used

---

## 3. InterchainTokenDeploymentStarted (`parser_its_interchain_token_deployment_started.rs`)

**Struct Definition (all fields):**
- `token_id: [u8; 32]`
- `token_name: String`
- `token_symbol: String`
- `token_decimals: u8`
- `minter: Vec<u8>`
- `destination_chain: String`

**Fields USED:**
- `minter`
- `token_id`
- `destination_chain`
- `token_name`
- `token_symbol`
- `token_decimals`

**Fields NOT USED:**
- **None** - All fields are used

---

## 4. InterchainTransfer (`parser_its_interchain_transfer.rs`)

**Struct Definition (all fields):**
- `token_id: [u8; 32]`
- `source_address: Pubkey`
- `source_token_account: Pubkey`
- `destination_chain: String`
- `destination_address: Vec<u8>`
- `amount: u64`
- `data_hash: [u8; 32]`

**Fields USED:**
- `source_token_account`
- `source_address`
- `destination_chain`
- `destination_address`
- `data_hash`
- `token_id`
- `amount`

**Fields NOT USED:**
- **None** - All fields are used

---

## 5. MessageApprovedEvent (`parser_message_approved.rs`)

**Struct Definition (all fields):**
- `command_id: [u8; 32]`
- `destination_address: Pubkey`
- `payload_hash: [u8; 32]`
- `source_chain: String`
- `cc_id: String`
- `source_address: String`
- `destination_chain: String`

**Fields USED:**
- `destination_chain`
- `destination_address`
- `payload_hash`
- `command_id`
- `cc_id`
- `source_chain`
- `source_address`

**Fields NOT USED:**
- **None** - All fields are used

---

## 6. MessageExecutedEvent (`parser_message_executed.rs`)

**Struct Definition (all fields):**
- `command_id: [u8; 32]`
- `destination_address: Pubkey`
- `payload_hash: [u8; 32]`
- `source_chain: String`
- `cc_id: String`
- `source_address: String`
- `destination_chain: String`

**Fields USED:**
- `command_id`
- `cc_id`
- `source_chain`

**Fields NOT USED:**
- **`destination_address`** - Not used in `event()` method
- **`payload_hash`** - Not used in `event()` method
- **`source_address`** - Not used in `event()` method
- **`destination_chain`** - Not used in `event()` method

---

## 7. VerifierSetRotatedEvent (`parser_signers_rotated.rs`)

**Struct Definition (all fields):**
- `epoch: U256`
- `verifier_set_hash: [u8; 32]`

**Fields USED:**
- `epoch`
- `verifier_set_hash`

**Fields NOT USED:**
- **None** - All fields are used

---

## 8. GasAddedEvent (`parser_native_gas_added.rs`)

**Struct Definition (all fields):**
- `sender: Pubkey`
- `message_id: String`
- `amount: u64`
- `refund_address: Pubkey`
- `spl_token_account: Option<Pubkey>`

**Fields USED:**
- `refund_address`
- `amount`
- `message_id`

**Fields NOT USED:**
- **`sender`** - Not used in `event()` method
- **`spl_token_account`** - Not used in `event()` method

---

## 9. GasPaidEvent (`parser_native_gas_paid.rs`)

**Struct Definition (all fields):**
- `sender: Pubkey`
- `destination_chain: String`
- `destination_address: String`
- `payload_hash: [u8; 32]`
- `amount: u64`
- `refund_address: Pubkey`
- `spl_token_account: Option<Pubkey>`

**Fields USED:**
- `destination_chain`
- `destination_address`
- `payload_hash`
- `refund_address`
- `amount`

**Fields NOT USED:**
- **`sender`** - Not used in `event()` method
- **`spl_token_account`** - Not used in `event()` method

---

## 10. GasRefundedEvent (`parser_native_gas_refunded.rs`)

**Struct Definition (all fields):**
- `receiver: Pubkey`
- `message_id: String`
- `amount: u64`
- `spl_token_account: Option<Pubkey>`

**Fields USED:**
- `receiver`
- `amount`
- `message_id`

**Fields NOT USED:**
- **`spl_token_account`** - Not used in `event()` method

---

## 11. CallContractEvent (`parser_call_contract.rs`)

**Struct Definition (all fields):**
- `sender: Pubkey`
- `payload_hash: [u8; 32]`
- `destination_chain: String`
- `destination_contract_address: String`
- `payload: Vec<u8>`

**Fields USED:**
- `destination_chain`
- `destination_contract_address`
- `payload_hash`
- `sender`
- `payload`

**Fields NOT USED:**
- **None** - All fields are used

---

## Summary

**Total unused fields across all parsers:**
1. `LinkTokenStarted.params` - Commented out, marked as TBD
2. `MessageExecutedEvent.destination_address` - Not used
3. `MessageExecutedEvent.payload_hash` - Not used
4. `MessageExecutedEvent.source_address` - Not used
5. `MessageExecutedEvent.destination_chain` - Not used
6. `GasAddedEvent.sender` - Not used
7. `GasAddedEvent.spl_token_account` - Not used
8. `GasPaidEvent.sender` - Not used
9. `GasPaidEvent.spl_token_account` - Not used
10. `GasRefundedEvent.spl_token_account` - Not used

**Total: 10 unused fields across 4 different event types**

