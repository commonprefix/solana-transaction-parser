use crate::common::check_discriminators_and_address;
use crate::discriminators::{CANNOT_EXECUTE_MESSAGE_EVENT_DISC, CPI_EVENT_DISC};
use crate::error::TransactionParsingError;
use crate::message_matching_key::MessageMatchingKey;
use crate::parser::{Parser, ParserConfig};
use async_trait::async_trait;
use borsh::BorshDeserialize;
use relayer_core::gmp_api::gmp_types::{CannotExecuteMessageReason, CommonEventFields, Event};
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::UiCompiledInstruction;
use tracing::debug;

#[derive(BorshDeserialize, Clone, Debug)]
pub struct ExecuteInsufficientGasEvent {
    pub message_id: String,
    pub source_chain: String,
}

pub struct ParserExecuteInsufficientGas {
    signature: String,
    parsed: Option<ExecuteInsufficientGasEvent>,
    instruction: UiCompiledInstruction,
    config: ParserConfig,
    accounts: Vec<String>,
}

impl ParserExecuteInsufficientGas {
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
                event_type_discriminator: CANNOT_EXECUTE_MESSAGE_EVENT_DISC,
                expected_contract_address,
            },
            accounts,
        })
    }

    fn try_extract_with_config(
        instruction: &UiCompiledInstruction,
        config: ParserConfig,
        accounts: &[String],
    ) -> Result<ExecuteInsufficientGasEvent, TransactionParsingError> {
        let payload = check_discriminators_and_address(instruction, config, accounts)?;
        match ExecuteInsufficientGasEvent::try_from_slice(payload.into_iter().as_slice()) {
            Ok(event) => {
                debug!("Execute Insufficient Gas event={:?}", event);
                Ok(event)
            }
            Err(_) => Err(TransactionParsingError::InvalidInstructionData(
                "invalid execute insufficient gas event".to_string(),
            )),
        }
    }
}

#[async_trait]
impl Parser for ParserExecuteInsufficientGas {
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
            "MessageMatchingKey is not available for ExecuteInsufficientGasEvent".to_string(),
        ))
    }

    async fn event(&self, _: Option<String>) -> Result<Event, TransactionParsingError> {
        let parsed = self
            .parsed
            .clone()
            .ok_or_else(|| TransactionParsingError::Message("Missing parsed".to_string()))?;

        Ok(Event::CannotExecuteMessageV2 {
            common: CommonEventFields {
                r#type: "CANNOT_EXECUTE_MESSAGE/V2".to_owned(),
                event_id: format!("cannot-execute-task-v2-{}", self.signature),
                meta: None,
            },
            message_id: parsed.message_id,
            source_chain: parsed.source_chain,
            reason: CannotExecuteMessageReason::InsufficientGas,
            details: self.signature.to_string(),
        })
    }

    async fn message_id(&self) -> Result<Option<String>, TransactionParsingError> {
        Ok(None)
    }
}
