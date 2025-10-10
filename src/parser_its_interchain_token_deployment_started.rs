use std::collections::HashMap;

use crate::common::check_discriminators_and_address;
use crate::error::TransactionParsingError;
use crate::message_matching_key::MessageMatchingKey;
use crate::parser::Parser;
use async_trait::async_trait;
use borsh::BorshDeserialize;
use relayer_core::gmp_api::gmp_types::{
    CommonEventFields, Event, EventMetadata, InterchainTokenDefinition,
};
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::UiCompiledInstruction;
use tracing::debug;
use uuid::Uuid;

#[derive(BorshDeserialize, Clone, Debug)]
pub struct InterchainTokenDeploymentStarted {
    pub token_id: [u8; 32],
    pub token_name: String,
    pub token_symbol: String,
    pub token_decimals: u8,
    pub minter: Vec<u8>,
    pub destination_chain: String,
}

pub struct ParserInterchainTokenDeploymentStarted {
    signature: String,
    parsed: Option<InterchainTokenDeploymentStarted>,
    instruction: UiCompiledInstruction,
    expected_contract_address: Pubkey,
    accounts: Vec<String>,
    timestamp: String,
}

impl ParserInterchainTokenDeploymentStarted {
    pub(crate) async fn new(
        signature: String,
        instruction: UiCompiledInstruction,
        expected_contract_address: Pubkey,
        accounts: Vec<String>,
        timestamp: String,
    ) -> Result<Self, TransactionParsingError> {
        Ok(Self {
            signature,
            parsed: None,
            instruction,
            expected_contract_address,
            accounts,
            timestamp,
        })
    }

    fn try_extract_with_config(
        instruction: &UiCompiledInstruction,
        expected_contract_address: Pubkey,
        accounts: &[String],
    ) -> Result<InterchainTokenDeploymentStarted, TransactionParsingError> {
        let payload =
            check_discriminators_and_address(instruction, expected_contract_address, accounts)?;
        match InterchainTokenDeploymentStarted::try_from_slice(payload.into_iter().as_slice()) {
            Ok(event) => {
                debug!(
                    "Execute interchain token deployment started event={:?}",
                    event
                );
                Ok(event)
            }
            Err(_) => Err(TransactionParsingError::InvalidInstructionData(
                "invalid execute interchain token deployment started event".to_string(),
            )),
        }
    }
}

#[async_trait]
impl Parser for ParserInterchainTokenDeploymentStarted {
    async fn parse(&mut self) -> Result<bool, TransactionParsingError> {
        if self.parsed.is_none() {
            self.parsed = Some(Self::try_extract_with_config(
                &self.instruction,
                self.expected_contract_address,
                &self.accounts,
            )?);
        }
        Ok(self.parsed.is_some())
    }

    async fn is_match(&mut self) -> Result<bool, TransactionParsingError> {
        match Self::try_extract_with_config(
            &self.instruction,
            self.expected_contract_address,
            &self.accounts,
        ) {
            Ok(parsed) => {
                self.parsed = Some(parsed);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    async fn key(&self) -> Result<MessageMatchingKey, TransactionParsingError> {
        Err(TransactionParsingError::Message(
            "MessageMatchingKey is not available for InterchainTokenDeploymentStarted".to_string(),
        ))
    }

    async fn event(&self, message_id: Option<String>) -> Result<Event, TransactionParsingError> {
        let parsed = self
            .parsed
            .clone()
            .ok_or_else(|| TransactionParsingError::Message("Missing parsed".to_string()))?;

        Ok(Event::ITSInterchainTokenDeploymentStarted {
            common: CommonEventFields {
                r#type: "ITS/INTERCHAIN_TOKEN_DEPLOYMENT_STARTED".to_owned(),
                event_id: format!("{}-its-interchain-token-deployment-started", Uuid::new_v4()),
                meta: Some(EventMetadata {
                    tx_id: Some(self.signature.clone()),
                    from_address: Some(hex::encode(parsed.minter)),
                    finalized: None,
                    source_context: Some(HashMap::from([(
                        "token_id".to_owned(),
                        hex::encode(parsed.token_id),
                    )])),
                    timestamp: self.timestamp.clone(),
                }),
            },
            destination_chain: parsed.destination_chain.clone(),
            message_id: message_id.ok_or_else(|| {
                TransactionParsingError::Message("Missing message_id".to_string())
            })?,
            token: InterchainTokenDefinition {
                id: hex::encode(parsed.token_id),
                name: parsed.token_name.clone(),
                symbol: parsed.token_symbol.clone(),
                decimals: parsed.token_decimals,
            },
        })
    }

    async fn message_id(&self) -> Result<Option<String>, TransactionParsingError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use solana_transaction_status::UiInstruction;

    use super::*;
    use crate::parser_its_interchain_token_deployment_started::ParserInterchainTokenDeploymentStarted;
    use crate::test_utils::fixtures::transaction_fixtures;
    #[tokio::test]
    async fn test_parser() {
        let txs = transaction_fixtures();

        let tx = txs[9].clone();
        let compiled_ix: UiCompiledInstruction = match tx.ixs[1].instructions[0].clone() {
            UiInstruction::Compiled(ix) => ix,
            _ => panic!("expected a compiled instruction"),
        };

        let mut parser = ParserInterchainTokenDeploymentStarted::new(
            tx.signature.to_string(),
            compiled_ix,
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            tx.account_keys,
            tx.timestamp.unwrap_or_default().to_string(),
        )
        .await
        .unwrap();
        assert!(parser.is_match().await.unwrap());
        let sig = tx.signature.clone().to_string();
        parser.parse().await.unwrap();
        let event = parser.event(Some(format!("{}-1", sig))).await.unwrap();
        match event {
            Event::ITSInterchainTokenDeploymentStarted { ref common, .. } => {
                let expected_event = Event::ITSInterchainTokenDeploymentStarted {
                    common: CommonEventFields {
                        r#type: "ITS/INTERCHAIN_TOKEN_DEPLOYMENT_STARTED".to_owned(),
                        event_id: common.event_id.clone(),
                        meta: Some(EventMetadata {
                            tx_id: Some(sig.to_string()),
                            from_address: Some(hex::encode(parser.parsed.clone().unwrap().minter)),
                            finalized: None,
                            source_context: Some(HashMap::from([(
                                "token_id".to_owned(),
                                hex::encode(parser.parsed.as_ref().unwrap().token_id),
                            )])),
                            timestamp: parser.timestamp.clone(),
                        }),
                    },
                    message_id: format!("{}-1", sig),
                    destination_chain: parser.parsed.as_ref().unwrap().destination_chain.clone(),
                    token: InterchainTokenDefinition {
                        id: hex::encode(parser.parsed.as_ref().unwrap().token_id),
                        name: parser.parsed.as_ref().unwrap().token_name.clone(),
                        symbol: parser.parsed.as_ref().unwrap().token_symbol.clone(),
                        decimals: parser.parsed.as_ref().unwrap().token_decimals,
                    },
                };
                assert_eq!(event, expected_event);
            }
            _ => panic!("Expected ITSInterchainTokenDeploymentStarted event"),
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

        let mut parser = ParserInterchainTokenDeploymentStarted::new(
            tx.signature.to_string(),
            compiled_ix,
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            tx.account_keys,
            tx.timestamp.unwrap_or_default().to_string(),
        )
        .await
        .unwrap();
        assert!(!parser.is_match().await.unwrap());
    }
}
