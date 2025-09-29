use crate::common::check_discriminators_and_address;
use crate::discriminators::CPI_EVENT_DISC;
use crate::error::TransactionParsingError;
use crate::instruction_index::InstructionIndex;
use crate::message_matching_key::MessageMatchingKey;
use crate::parser::{Parser, ParserConfig};
use async_trait::async_trait;
use borsh::BorshDeserialize;
use event_cpi::Discriminator;
use relayer_core::gmp_api::gmp_types::{
    CommonEventFields, Event, EventMetadata, SignersRotatedEventMetadata,
};
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::UiCompiledInstruction;
use tracing::debug;

use axelar_solana_gateway::events::VerifierSetRotatedEvent;

pub struct ParserSignersRotated {
    signature: String,
    parsed: Option<VerifierSetRotatedEvent>,
    instruction: UiCompiledInstruction,
    config: ParserConfig,
    index: InstructionIndex,
    accounts: Vec<String>,
}

impl ParserSignersRotated {
    pub(crate) async fn new(
        signature: String,
        instruction: UiCompiledInstruction,
        index: InstructionIndex,
        expected_contract_address: Pubkey,
        accounts: Vec<String>,
    ) -> Result<Self, TransactionParsingError> {
        Ok(Self {
            signature,
            parsed: None,
            instruction,
            config: ParserConfig {
                event_cpi_discriminator: CPI_EVENT_DISC,
                event_type_discriminator: VerifierSetRotatedEvent::DISCRIMINATOR
                    .get(0..8)
                    .ok_or_else(|| {
                        TransactionParsingError::Message("Invalid discriminator".to_string())
                    })?
                    .try_into()
                    .expect("8-byte discriminator"),
                expected_contract_address,
            },
            index,
            accounts,
        })
    }

    fn try_extract_with_config(
        instruction: &UiCompiledInstruction,
        config: ParserConfig,
        accounts: &[String],
    ) -> Result<VerifierSetRotatedEvent, TransactionParsingError> {
        let payload = check_discriminators_and_address(instruction, config, accounts)?;
        match VerifierSetRotatedEvent::try_from_slice(payload.into_iter().as_slice()) {
            Ok(event) => {
                debug!("Verifier Set Rotated event={:?}", event);
                Ok(event)
            }
            Err(_) => Err(TransactionParsingError::InvalidInstructionData(
                "invalid verifier set rotated event".to_string(),
            )),
        }
    }
}

#[async_trait]
impl Parser for ParserSignersRotated {
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
            "MessageMatchingKey is not available for VerifierSetRotatedEvent".to_string(),
        ))
    }

    async fn event(&self, _: Option<String>) -> Result<Event, TransactionParsingError> {
        let parsed = self
            .parsed
            .clone()
            .ok_or_else(|| TransactionParsingError::Message("Missing parsed".to_string()))?;

        let epoch = {
            let le = parsed.epoch.to_le_bytes();
            let first8 = le.get(..8).ok_or_else(|| {
                TransactionParsingError::InvalidInstructionData("epoch too short".to_string())
            })?;
            let arr: [u8; 8] = first8.try_into().map_err(|_| {
                TransactionParsingError::InvalidInstructionData("epoch cast failed".to_string())
            })?;
            u64::from_le_bytes(arr)
        };

        Ok(Event::SignersRotated {
            common: CommonEventFields {
                r#type: "SIGNERS_ROTATED".to_owned(),
                event_id: format!("{}-signers-rotated", self.signature.clone()),
                meta: Some(SignersRotatedEventMetadata {
                    common_meta: EventMetadata {
                        tx_id: Some(self.signature.clone()),
                        from_address: None,
                        finalized: None,
                        source_context: None,
                        timestamp: chrono::Utc::now()
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    },
                    signers_hash: Some(hex::encode(parsed.verifier_set_hash)),
                    epoch: Some(epoch),
                }),
            },
            message_id: format!("{}-{}", self.signature, self.index.serialize()),
        })
    }

    async fn message_id(&self) -> Result<Option<String>, TransactionParsingError> {
        Ok(Some(format!(
            "{}-{}",
            self.signature,
            self.index.serialize()
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use solana_transaction_status::UiInstruction;

    use super::*;
    use crate::parser_signers_rotated::ParserSignersRotated;
    use crate::test_utils::fixtures::transaction_fixtures;
    #[tokio::test]
    async fn test_parser() {
        let txs = transaction_fixtures();

        let tx = txs[11].clone();
        let compiled_ix: UiCompiledInstruction = match tx.ixs[0].instructions[0].clone() {
            UiInstruction::Compiled(ix) => ix,
            _ => panic!("expected a compiled instruction"),
        };

        let mut parser = ParserSignersRotated::new(
            tx.signature.to_string(),
            compiled_ix,
            InstructionIndex::new(1, 2),
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
            Event::SignersRotated { .. } => {
                let expected_event = Event::SignersRotated {
                    common: CommonEventFields {
                        r#type: "SIGNERS_ROTATED".to_owned(),
                        event_id: format!("{}-signers-rotated", sig),
                        meta: Some(SignersRotatedEventMetadata {
                            common_meta: EventMetadata {
                                tx_id: Some(sig.to_string()),
                                from_address: None,
                                finalized: None,
                                source_context: None,
                                timestamp: chrono::Utc::now()
                                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                            },
                            signers_hash: Some(hex::encode(
                                parser.parsed.as_ref().unwrap().verifier_set_hash,
                            )),
                            epoch: Some(u64::from_le_bytes(
                                parser.parsed.as_ref().unwrap().epoch.to_le_bytes()[..8]
                                    .try_into()
                                    .unwrap(),
                            )),
                        }),
                    },
                    message_id: format!(
                        "{}-{}.{}",
                        sig, parser.index.outer_index, parser.index.inner_index
                    ),
                };
                assert_eq!(event, expected_event);
            }
            _ => panic!("Expected GasRefunded event"),
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
        let mut parser = ParserSignersRotated::new(
            tx.signature.to_string(),
            compiled_ix,
            InstructionIndex::new(1, 2),
            Pubkey::from_str("7RdSDLUUy37Wqc6s9ebgo52AwhGiw4XbJWZJgidQ1fJc").unwrap(),
            tx.account_keys,
        )
        .await
        .unwrap();

        assert!(!parser.is_match().await.unwrap());
    }
}
