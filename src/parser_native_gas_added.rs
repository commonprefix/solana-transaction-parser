use crate::common::check_discriminators_and_address;
use crate::discriminators::{CPI_EVENT_DISC, NATIVE_GAS_ADDED_EVENT_DISC};
use crate::error::TransactionParsingError;
use crate::instruction_index::InstructionIndex;
use crate::message_matching_key::MessageMatchingKey;
use crate::parser::{Parser, ParserConfig};
use async_trait::async_trait;
use borsh::BorshDeserialize;
use relayer_core::gmp_api::gmp_types::{Amount, CommonEventFields, Event, EventMetadata};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::UiCompiledInstruction;
use tracing::debug;

// TODO: Get them from a library?
#[derive(BorshDeserialize, Clone, Debug)]
pub struct NativeGasAddedEvent {
    /// The Gas service config PDA
    pub _config_pda: Pubkey,
    /// Solana transaction signature
    pub tx_hash: [u8; 64],
    /// index of the log
    pub log_index: String,
    /// The refund address
    pub refund_address: Pubkey,
    /// amount of SOL
    pub gas_fee_amount: u64,
}

pub struct ParserNativeGasAdded {
    signature: String,
    parsed: Option<NativeGasAddedEvent>,
    instruction: UiCompiledInstruction,
    config: ParserConfig,
    accounts: Vec<String>,
}

impl ParserNativeGasAdded {
    pub(crate) async fn new(
        signature: String,
        instruction: UiCompiledInstruction,
        expected_contract_address: Pubkey,
        accounts: Vec<String>,
    ) -> Result<Self, TransactionParsingError> {
        Ok(Self {
            signature,
            parsed: None,
            instruction,
            config: ParserConfig {
                event_cpi_discriminator: CPI_EVENT_DISC,
                event_type_discriminator: NATIVE_GAS_ADDED_EVENT_DISC,
                expected_contract_address,
            },
            accounts,
        })
    }

    fn try_extract_with_config(
        instruction: &UiCompiledInstruction,
        config: ParserConfig,
        accounts: &[String],
    ) -> Result<NativeGasAddedEvent, TransactionParsingError> {
        let payload = check_discriminators_and_address(instruction, config, accounts)?;
        match NativeGasAddedEvent::try_from_slice(payload.into_iter().as_slice()) {
            Ok(event) => {
                debug!("Native Gas Added event={:?}", event);
                Ok(event)
            }
            Err(_) => Err(TransactionParsingError::InvalidInstructionData(
                "invalid native gas added event".to_string(),
            )),
        }
    }
}

#[async_trait]
impl Parser for ParserNativeGasAdded {
    async fn parse(&mut self) -> Result<bool, TransactionParsingError> {
        if self.parsed.is_none() {
            self.parsed = Some(Self::try_extract_with_config(
                &self.instruction,
                self.config,
                &self.accounts,
            )?);
        }
        Ok(self.parsed.is_some())
    }

    async fn is_match(&mut self) -> Result<bool, TransactionParsingError> {
        match Self::try_extract_with_config(&self.instruction, self.config, &self.accounts) {
            Ok(parsed) => {
                self.parsed = Some(parsed);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    async fn key(&self) -> Result<MessageMatchingKey, TransactionParsingError> {
        Err(TransactionParsingError::Message(
            "MessageMatchingKey is not available for NativeGasAddedEvent".to_string(),
        ))
    }

    async fn event(&self, _message_id: Option<String>) -> Result<Event, TransactionParsingError> {
        let parsed = self
            .parsed
            .clone()
            .ok_or_else(|| TransactionParsingError::Message("Missing parsed".to_string()))?;

        let message_id = self
            .message_id()
            .await?
            .ok_or_else(|| TransactionParsingError::Message("Missing message_id".to_string()))?;

        Ok(Event::GasCredit {
            common: CommonEventFields {
                r#type: "GAS_CREDIT".to_owned(),
                event_id: format!("{}-gas", self.signature),
                meta: Some(EventMetadata {
                    tx_id: Some(self.signature.to_string()),
                    from_address: None,
                    finalized: None,
                    source_context: None,
                    timestamp: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                }),
            },
            message_id,
            refund_address: parsed.refund_address.to_string(),
            payment: Amount {
                token_id: None,
                amount: parsed.gas_fee_amount.to_string(),
            },
        })
    }

    async fn message_id(&self) -> Result<Option<String>, TransactionParsingError> {
        if let Some(parsed) = self.parsed.clone() {
            // Deserialize and then reserialize to ensure that formatting is correct
            let index = InstructionIndex::deserialize(parsed.log_index)?;
            Ok(Some(format!(
                "{}-{}",
                Signature::from(parsed.tx_hash),
                index.serialize()
            )))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use solana_sdk::signature::Signature;
    use solana_transaction_status::UiInstruction;

    use super::*;
    use crate::parser_native_gas_added::ParserNativeGasAdded;
    use crate::test_utils::fixtures::transaction_fixtures;
    #[tokio::test]
    async fn test_parser() {
        let txs = transaction_fixtures();

        let tx = txs[4].clone();
        let compiled_ix: UiCompiledInstruction = match tx.ixs[0].instructions[0].clone() {
            UiInstruction::Compiled(ix) => ix,
            _ => panic!("expected a compiled instruction"),
        };

        let mut parser = ParserNativeGasAdded::new(
            tx.signature.to_string(),
            compiled_ix,
            Pubkey::from_str("7RdSDLUUy37Wqc6s9ebgo52AwhGiw4XbJWZJgidQ1fJc").unwrap(),
            tx.account_keys,
        )
        .await
        .unwrap();
        assert!(parser.is_match().await.unwrap());
        let sig = tx.signature.clone().to_string();
        parser.parse().await.unwrap();
        let event = parser.event(None).await.unwrap();
        match event {
            Event::GasCredit { .. } => {
                let expected_event = Event::GasCredit {
                    common: CommonEventFields {
                        r#type: "GAS_CREDIT".to_owned(),
                        event_id: format!("{}-gas", sig),
                        meta: Some(EventMetadata {
                            tx_id: Some(sig.to_string()),
                            from_address: None,
                            finalized: None,
                            source_context: None,
                            timestamp: chrono::Utc::now()
                                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        }),
                    },
                    message_id: format!(
                        "{}-{}",
                        Signature::from(parser.parsed.as_ref().unwrap().tx_hash),
                        parser.parsed.as_ref().unwrap().log_index
                    ),
                    refund_address: parser.parsed.as_ref().unwrap().refund_address.to_string(),
                    payment: Amount {
                        token_id: None,
                        amount: parser.parsed.as_ref().unwrap().gas_fee_amount.to_string(),
                    },
                };
                assert_eq!(event, expected_event);
            }
            _ => panic!("Expected GasCredit event"),
        }
    }

    #[tokio::test]
    async fn test_no_match() {
        let txs = transaction_fixtures();

        let tx = txs[0].clone();
        let compiled_ix: UiCompiledInstruction = match tx.ixs[0].instructions[0].clone() {
            UiInstruction::Compiled(ix) => ix,
            _ => panic!("expected a compiled instruction"),
        };
        let mut parser = ParserNativeGasAdded::new(
            tx.signature.to_string(),
            compiled_ix,
            Pubkey::from_str("7RdSDLUUy37Wqc6s9ebgo52AwhGiw4XbJWZJgidQ1fJc").unwrap(),
            tx.account_keys,
        )
        .await
        .unwrap();

        assert!(!parser.is_match().await.unwrap());
    }
}
