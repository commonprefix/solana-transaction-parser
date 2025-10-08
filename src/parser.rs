use super::message_matching_key::MessageMatchingKey;
use crate::discriminators::{
    CPI_EVENT_DISC, ITS_INTERCHAIN_TOKEN_DEPLOYMENT_STARTED_EVENT_DISC,
    ITS_INTERCHAIN_TRANSFER_EVENT_DISC, ITS_LINK_TOKEN_STARTED_EVENT_DISC,
    ITS_TOKEN_METADATA_REGISTERED_EVENT_DISC,
};
use crate::error::TransactionParsingError;
use crate::instruction_index::InstructionIndex;
use crate::parser_call_contract::ParserCallContract;
use crate::parser_its_interchain_token_deployment_started::ParserInterchainTokenDeploymentStarted;
use crate::parser_its_interchain_transfer::ParserInterchainTransfer;
use crate::parser_its_link_token_started::ParserLinkTokenStarted;
use crate::parser_its_token_metadata_registered::ParserTokenMetadataRegistered;
use crate::parser_message_approved::ParserMessageApproved;
use crate::parser_message_executed::ParserMessageExecuted;
use crate::parser_native_gas_added::ParserNativeGasAdded;
use crate::parser_native_gas_paid::ParserNativeGasPaid;
use crate::parser_native_gas_refunded::ParserNativeGasRefunded;
use crate::parser_signers_rotated::ParserSignersRotated;
use crate::types::SolanaTransaction;
use anchor_lang::Discriminator;
use async_trait::async_trait;
use axelar_solana_gas_service::events::{GasAddedEvent, GasPaidEvent, GasRefundedEvent};
use axelar_solana_gateway::events::{
    CallContractEvent, MessageApprovedEvent, MessageExecutedEvent, VerifierSetRotatedEvent,
};
//use event_cpi::Discriminator;
use relayer_core::gmp_api::gmp_types::Event;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::UiInstruction;
use std::collections::HashMap;
use tracing::{info, warn};

#[async_trait]
pub trait Parser {
    async fn parse(&mut self) -> Result<bool, crate::error::TransactionParsingError>;
    async fn is_match(&mut self) -> Result<bool, crate::error::TransactionParsingError>;
    async fn key(&self) -> Result<MessageMatchingKey, crate::error::TransactionParsingError>;
    async fn event(
        &self,
        message_id: Option<String>,
    ) -> Result<Event, crate::error::TransactionParsingError>;
    async fn message_id(&self) -> Result<Option<String>, crate::error::TransactionParsingError>;
}

#[derive(Clone)]
pub struct TransactionParser {
    chain_name: String,
    gas_service_address: Pubkey,
    gateway_address: Pubkey,
    its_address: Pubkey,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TransactionParserTrait: Send + Sync {
    async fn parse_transaction(
        &self,
        transaction: String,
    ) -> Result<Vec<Event>, TransactionParsingError>;
}

#[async_trait]
impl TransactionParserTrait for TransactionParser {
    async fn parse_transaction(
        &self,
        transaction: String,
    ) -> Result<Vec<Event>, TransactionParsingError> {
        let mut events: Vec<Event> = Vec::new();
        let mut parsers: Vec<Box<dyn Parser + Send + Sync>> = Vec::new();
        let mut its_parsers: Vec<Box<dyn Parser + Send + Sync>> = Vec::new(); // ITS events that need mapping to call contract
        let mut call_contract: Vec<Box<dyn Parser + Send + Sync>> = Vec::new();
        let mut gas_credit_map: HashMap<MessageMatchingKey, Box<dyn Parser + Send + Sync>> =
            HashMap::new();

        let transaction = serde_json::from_str::<SolanaTransaction>(&transaction)
            .map_err(|e| TransactionParsingError::InvalidTransaction(e.to_string()))?;

        let (message_approved_count, message_executed_count) = self
            .create_parsers(
                transaction.clone(),
                &mut parsers,
                &mut its_parsers,
                &mut call_contract,
                &mut gas_credit_map,
                self.chain_name.clone(),
            )
            .await?;

        info!(
            "Parsing results: transaction signature={} parsers={}, call_contract={}, gas_credit_map={}",
            transaction.signature,
            parsers.len(),
            call_contract.len(),
            gas_credit_map.len()
        );

        if (parsers.len() + its_parsers.len() + call_contract.len() + gas_credit_map.len()) == 0 {
            warn!(
                "Transaction did not produce any parsers: transaction signature={}",
                transaction.signature
            );
        }

        for cc in call_contract.iter().clone() {
            let cc_key = cc.key().await?;
            events.push(cc.event(None).await?);
            if let Some(parser) = gas_credit_map.remove(&cc_key) {
                let message_id = cc.message_id().await?.ok_or_else(|| {
                    TransactionParsingError::Message("Missing message_id".to_string())
                })?;

                let event = parser.event(Some(message_id)).await?;
                events.push(event);
            }
        }

        for (i, its_parser) in its_parsers.iter().enumerate() {
            match call_contract.get(i) {
                Some(contract_parser) => {
                    let message_id = contract_parser.message_id().await?;
                    events.push(its_parser.event(message_id).await?);
                }
                None => {
                    return Err(TransactionParsingError::ITSWithoutPair(format!(
                        "No matching call_contract for ITS index {i}"
                    )));
                }
            }
        }

        for parser in parsers {
            let event = parser.event(None).await?;
            events.push(event);
        }

        self.add_cost_units(
            &mut events,
            message_approved_count,
            message_executed_count,
            transaction.cost_units,
        )
        .await?;

        Ok(events)
    }
}

impl TransactionParser {
    pub fn new(
        chain_name: String,
        gas_service_address: Pubkey,
        gateway_address: Pubkey,
        its_address: Pubkey,
    ) -> Self {
        Self {
            chain_name,
            gas_service_address,
            gateway_address,
            its_address,
        }
    }

    async fn create_parsers(
        &self,
        transaction: SolanaTransaction,
        parsers: &mut Vec<Box<dyn Parser + Send + Sync>>,
        its_parsers: &mut Vec<Box<dyn Parser + Send + Sync>>,
        call_contract: &mut Vec<Box<dyn Parser + Send + Sync>>,
        gas_credit_map: &mut HashMap<MessageMatchingKey, Box<dyn Parser + Send + Sync>>,
        chain_name: String,
    ) -> Result<(u64, u64), TransactionParsingError> {
        let mut message_approved_count = 0u64;
        let mut message_executed_count = 0u64;

        for group in transaction.ixs.iter() {
            for (inner_index, inst) in group.instructions.iter().enumerate() {
                if let UiInstruction::Compiled(ci) = inst {
                    let bytes = bs58::decode(&ci.data).into_vec().map_err(|e| {
                        warn!("invalid instruction data: {:?}", e);
                        TransactionParsingError::InvalidAccountAddress(e.to_string())
                    })?;
                    if bytes.len() < 16 {
                        warn!(
                            "instruction data is too short, transaction signature={}",
                            transaction.signature
                        );
                        continue;
                    }

                    if bytes.get(0..8) != Some(CPI_EVENT_DISC) {
                        warn!(
                            "expected event cpi discriminator, transaction signature={}",
                            transaction.signature
                        );
                        continue;
                    }

                    let index = InstructionIndex::new(
                        transaction.signature.to_string(),
                        group
                            .index
                            .checked_add(1)
                            .ok_or(TransactionParsingError::IndexOverflow(
                                "Outer index overflow".to_string(),
                            ))? as u8,
                        inner_index
                            .checked_add(1)
                            .ok_or(TransactionParsingError::IndexOverflow(
                                "Inner index overflow".to_string(),
                            ))? as u8,
                    );

                    let event_type_discriminator = match bytes.get(8..16) {
                        Some(event_type_discriminator) => event_type_discriminator,
                        None => {
                            warn!(
                                "event type discriminator is out of bounds, transaction signature={}",
                                transaction.signature
                            );
                            continue;
                        }
                    };

                    match event_type_discriminator {
                        x if x == GasPaidEvent::DISCRIMINATOR => {
                            let mut parser = ParserNativeGasPaid::new(
                                transaction.signature.to_string(),
                                ci.clone(),
                                self.gas_service_address,
                                transaction.account_keys.clone(),
                            )
                            .await?;
                            if parser.is_match().await? {
                                info!(
                                    "ParserNativeGasPaid matched, transaction signature={}",
                                    transaction.signature
                                );
                                parser.parse().await?;
                                let key = parser.key().await?;
                                gas_credit_map.insert(key, Box::new(parser));
                            }
                        }
                        x if x == GasAddedEvent::DISCRIMINATOR => {
                            let mut parser = ParserNativeGasAdded::new(
                                transaction.signature.to_string(),
                                ci.clone(),
                                self.gas_service_address,
                                transaction.account_keys.clone(),
                            )
                            .await?;
                            if parser.is_match().await? {
                                info!(
                                    "ParserNativeGasAdded matched, transaction signature={}",
                                    transaction.signature
                                );
                                parser.parse().await?;
                                parsers.push(Box::new(parser));
                            }
                        }
                        x if x == GasRefundedEvent::DISCRIMINATOR => {
                            let mut parser = ParserNativeGasRefunded::new(
                                transaction.signature.to_string(),
                                ci.clone(),
                                self.gas_service_address,
                                transaction.cost_units,
                                transaction.account_keys.clone(),
                            )
                            .await?;
                            if parser.is_match().await? {
                                info!(
                                    "ParserNativeGasRefunded matched, transaction signature={}",
                                    transaction.signature
                                );
                                parser.parse().await?;
                                parsers.push(Box::new(parser));
                            }
                        }
                        x if x == CallContractEvent::DISCRIMINATOR => {
                            let mut parser = ParserCallContract::new(
                                transaction.signature.to_string(),
                                ci.clone(),
                                transaction.account_keys.clone(),
                                chain_name.clone(),
                                index,
                                self.gateway_address,
                            )
                            .await?;
                            if parser.is_match().await? {
                                info!(
                                    "ParserCallContract matched, transaction signature={}",
                                    transaction.signature
                                );
                                parser.parse().await?;
                                call_contract.push(Box::new(parser));
                            }
                        }
                        x if x == MessageApprovedEvent::DISCRIMINATOR => {
                            let mut parser = ParserMessageApproved::new(
                                transaction.signature.to_string(),
                                ci.clone(),
                                self.gateway_address,
                                transaction.account_keys.clone(),
                            )
                            .await?;
                            if parser.is_match().await? {
                                info!(
                                    "ParserMessageApproved matched, transaction signature={}",
                                    transaction.signature
                                );
                                parser.parse().await?;
                                parsers.push(Box::new(parser));
                                message_approved_count += 1;
                            }
                        }
                        x if x == MessageExecutedEvent::DISCRIMINATOR => {
                            let mut parser = ParserMessageExecuted::new(
                                transaction.signature.to_string(),
                                ci.clone(),
                                self.gateway_address,
                                transaction.account_keys.clone(),
                            )
                            .await?;
                            if parser.is_match().await? {
                                info!(
                                    "ParserMessageExecuted matched, transaction signature={}",
                                    transaction.signature
                                );
                                parser.parse().await?;
                                parsers.push(Box::new(parser));
                                message_executed_count += 1;
                            }
                        }
                        x if x == VerifierSetRotatedEvent::DISCRIMINATOR => {
                            let mut parser = ParserSignersRotated::new(
                                transaction.signature.to_string(),
                                ci.clone(),
                                index,
                                self.gateway_address,
                                transaction.account_keys.clone(),
                            )
                            .await?;
                            if parser.is_match().await? {
                                info!(
                                    "ParserSignersRotated matched, transaction signature={}",
                                    transaction.signature
                                );
                                parser.parse().await?;
                                parsers.push(Box::new(parser));
                            }
                        }
                        x if x == ITS_INTERCHAIN_TRANSFER_EVENT_DISC => {
                            let mut parser = ParserInterchainTransfer::new(
                                transaction.signature.to_string(),
                                ci.clone(),
                                self.its_address,
                                transaction.account_keys.clone(),
                            )
                            .await?;
                            if parser.is_match().await? {
                                info!(
                                    "ParserInterchainTransfer matched, transaction signature={}",
                                    transaction.signature
                                );
                                parser.parse().await?;
                                its_parsers.push(Box::new(parser));
                            }
                        }
                        x if x == ITS_INTERCHAIN_TOKEN_DEPLOYMENT_STARTED_EVENT_DISC => {
                            let mut parser = ParserInterchainTokenDeploymentStarted::new(
                                transaction.signature.to_string(),
                                ci.clone(),
                                self.its_address,
                                transaction.account_keys.clone(),
                            )
                            .await?;
                            if parser.is_match().await? {
                                info!(
                                    "ParserInterchainTokenDeploymentStarted matched, transaction signature={}",
                                    transaction.signature
                                );
                                parser.parse().await?;
                                its_parsers.push(Box::new(parser));
                            }
                        }
                        x if x == ITS_LINK_TOKEN_STARTED_EVENT_DISC => {
                            let mut parser = ParserLinkTokenStarted::new(
                                transaction.signature.to_string(),
                                ci.clone(),
                                self.its_address,
                                transaction.account_keys.clone(),
                            )
                            .await?;
                            if parser.is_match().await? {
                                info!(
                                    "ParserLinkTokenStarted matched, transaction signature={}",
                                    transaction.signature
                                );
                                parser.parse().await?;
                                its_parsers.push(Box::new(parser));
                            }
                        }
                        x if x == ITS_TOKEN_METADATA_REGISTERED_EVENT_DISC => {
                            let mut parser = ParserTokenMetadataRegistered::new(
                                transaction.signature.to_string(),
                                ci.clone(),
                                self.its_address,
                                transaction.account_keys.clone(),
                            )
                            .await?;
                            if parser.is_match().await? {
                                info!(
                                    "ParserTokenMetadataRegistered matched, transaction signature={}",
                                    transaction.signature
                                );
                                parser.parse().await?;
                                its_parsers.push(Box::new(parser));
                            }
                        }
                        _ => {
                            // Unknown event type discriminator; skip
                            continue;
                        }
                    }
                }
            }
        }

        Ok((message_approved_count, message_executed_count))
    }

    pub async fn add_cost_units(
        &self,
        events: &mut [Event],
        message_approved_count: u64,
        message_executed_count: u64,
        cost_units: u64,
    ) -> Result<(), TransactionParsingError> {
        for e in events.iter_mut() {
            match e {
                Event::MessageApproved { cost, .. } => {
                    cost.amount = (cost_units
                        .checked_div(message_approved_count + message_executed_count))
                    .unwrap_or(0)
                    .to_string();
                }
                Event::MessageExecuted { cost, .. } => {
                    cost.amount = (cost_units
                        .checked_div(message_approved_count + message_executed_count))
                    .unwrap_or(0)
                    .to_string();
                }
                _ => {}
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::test_utils::fixtures::transaction_fixtures;

    #[tokio::test]
    async fn test_parser_converted_and_message_id_set() {
        let txs = transaction_fixtures();
        let parser = TransactionParser::new(
            "solana".to_string(),
            Pubkey::from_str("CJ9f8WFdm3q38pmg426xQf7uum7RqvrmS9R58usHwNX7").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
        );
        let events = parser
            .parse_transaction(serde_json::to_string(&txs[0]).unwrap())
            .await
            .unwrap();
        assert_eq!(events.len(), 2);

        let sig = txs[0].signature.clone().to_string();

        match events[0].clone() {
            Event::Call {
                message,
                destination_chain,
                ..
            } => {
                assert_eq!(destination_chain, "ethereum");
                assert_eq!(message.message_id, format!("{}-2.1", sig));
            }
            _ => panic!("Expected CallContract event"),
        }

        match events[1].clone() {
            Event::GasCredit {
                message_id,
                payment,
                ..
            } => {
                assert_eq!(message_id, format!("{}-2.1", sig));
                assert_eq!(payment.amount, "1000");
            }
            _ => panic!("Expected GasCredit event"),
        }
    }

    #[tokio::test]
    async fn test_message_executed() {
        let txs = transaction_fixtures();
        let parser = TransactionParser::new(
            "solana".to_string(),
            Pubkey::from_str("CJ9f8WFdm3q38pmg426xQf7uum7RqvrmS9R58usHwNX7").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
        );
        let events = parser
            .parse_transaction(serde_json::to_string(&txs[3]).unwrap())
            .await
            .unwrap();

        assert_eq!(events.len(), 1);

        match events[0].clone() {
            Event::MessageExecuted { cost, .. } => {
                assert_eq!(cost.amount, txs[3].cost_units.to_string());
                assert!(cost.token_id.is_none());
            }
            _ => panic!("Expected MessageExecuted event"),
        }
    }

    #[tokio::test]
    async fn test_multiple_message_executed() {
        let txs = transaction_fixtures();
        let parser = TransactionParser::new(
            "solana".to_string(),
            Pubkey::from_str("CJ9f8WFdm3q38pmg426xQf7uum7RqvrmS9R58usHwNX7").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
        );
        let events = parser
            .parse_transaction(serde_json::to_string(&txs[6]).unwrap())
            .await
            .unwrap();

        assert_eq!(events.len(), 2);

        match events[0].clone() {
            Event::MessageExecuted { cost, .. } => {
                assert_eq!(cost.amount, (txs[6].cost_units / 2).to_string());
                assert!(cost.token_id.is_none());
            }
            _ => panic!("Expected MessageExecuted event"),
        }
        match events[1].clone() {
            Event::MessageExecuted { cost, .. } => {
                assert_eq!(cost.amount, (txs[6].cost_units / 2).to_string());
                assert!(cost.token_id.is_none());
            }
            _ => panic!("Expected MessageExecuted event"),
        }
    }

    #[tokio::test]
    async fn test_message_approved() {
        let txs = transaction_fixtures();
        let parser = TransactionParser::new(
            "solana".to_string(),
            Pubkey::from_str("CJ9f8WFdm3q38pmg426xQf7uum7RqvrmS9R58usHwNX7").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
        );
        let events = parser
            .parse_transaction(serde_json::to_string(&txs[1]).unwrap())
            .await
            .unwrap();
        assert_eq!(events.len(), 1);

        match events[0].clone() {
            Event::MessageApproved { cost, .. } => {
                assert_eq!(cost.amount, txs[1].cost_units.to_string());
                assert!(cost.token_id.is_none());
            }
            _ => panic!("Expected MessageApproved event"),
        }
    }

    #[tokio::test]
    async fn test_multiple_message_approved() {
        let txs = transaction_fixtures();
        let parser = TransactionParser::new(
            "solana".to_string(),
            Pubkey::from_str("CJ9f8WFdm3q38pmg426xQf7uum7RqvrmS9R58usHwNX7").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
        );
        let events = parser
            .parse_transaction(serde_json::to_string(&txs[5]).unwrap())
            .await
            .unwrap();
        assert_eq!(events.len(), 2);

        match events[0].clone() {
            Event::MessageApproved { cost, .. } => {
                assert_eq!(cost.amount, (txs[5].cost_units / 2).to_string());
                assert!(cost.token_id.is_none());
            }
            _ => panic!("Expected MessageApproved event"),
        }

        match events[1].clone() {
            Event::MessageApproved { cost, .. } => {
                assert_eq!(cost.amount, (txs[5].cost_units / 2).to_string());
                assert!(cost.token_id.is_none());
            }
            _ => panic!("Expected MessageApproved event"),
        }
    }

    #[tokio::test]
    async fn test_gas_refunded() {
        let txs = transaction_fixtures();
        let parser = TransactionParser::new(
            "solana".to_string(),
            Pubkey::from_str("CJ9f8WFdm3q38pmg426xQf7uum7RqvrmS9R58usHwNX7").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
        );
        let events = parser
            .parse_transaction(serde_json::to_string(&txs[2]).unwrap())
            .await
            .unwrap();
        assert_eq!(events.len(), 1);

        match events[0].clone() {
            Event::GasRefunded { cost, .. } => {
                assert_eq!(cost.amount, txs[2].cost_units.to_string());
                assert!(cost.token_id.is_none());
            }
            _ => panic!("Expected GasRefunded event"),
        }
    }

    #[tokio::test]
    async fn test_gas_added() {
        let txs = transaction_fixtures();
        let parser = TransactionParser::new(
            "solana".to_string(),
            Pubkey::from_str("CJ9f8WFdm3q38pmg426xQf7uum7RqvrmS9R58usHwNX7").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
        );
        let events = parser
            .parse_transaction(serde_json::to_string(&txs[4]).unwrap())
            .await
            .unwrap();
        assert_eq!(events.len(), 1);

        match events[0].clone() {
            Event::GasCredit { .. } => {}
            _ => panic!("Expected GasCredit event"),
        }
    }

    #[tokio::test]
    async fn test_its_interchain_transfer() {
        let txs = transaction_fixtures();
        let parser = TransactionParser::new(
            "solana".to_string(),
            Pubkey::from_str("CJ9f8WFdm3q38pmg426xQf7uum7RqvrmS9R58usHwNX7").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
        );
        let events = parser
            .parse_transaction(serde_json::to_string(&txs[7]).unwrap())
            .await
            .unwrap();
        assert_eq!(events.len(), 2);

        match events[0].clone() {
            Event::Call { message, .. } => match events[1].clone() {
                Event::ITSInterchainTransfer { message_id, .. } => {
                    assert_eq!(message_id, message.message_id);
                }
                _ => panic!("Expected ITSInterchainTransfer event"),
            },
            _ => panic!("Expected Call event"),
        }
    }

    #[tokio::test]
    async fn test_its_link_token_started() {
        let txs = transaction_fixtures();
        let parser = TransactionParser::new(
            "solana".to_string(),
            Pubkey::from_str("CJ9f8WFdm3q38pmg426xQf7uum7RqvrmS9R58usHwNX7").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
        );
        let events = parser
            .parse_transaction(serde_json::to_string(&txs[8]).unwrap())
            .await
            .unwrap();
        assert_eq!(events.len(), 2);

        match events[0].clone() {
            Event::Call { message, .. } => match events[1].clone() {
                Event::ITSLinkTokenStarted { message_id, .. } => {
                    assert_eq!(message_id, message.message_id);
                }
                _ => panic!("Expected ITSLinkTokenStarted event"),
            },
            _ => panic!("Expected Call event"),
        }
    }

    #[tokio::test]
    async fn test_its_interchain_token_deployment_started() {
        let txs = transaction_fixtures();
        let parser = TransactionParser::new(
            "solana".to_string(),
            Pubkey::from_str("CJ9f8WFdm3q38pmg426xQf7uum7RqvrmS9R58usHwNX7").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
        );
        let events = parser
            .parse_transaction(serde_json::to_string(&txs[9]).unwrap())
            .await
            .unwrap();
        assert_eq!(events.len(), 2);

        match events[0].clone() {
            Event::Call { message, .. } => match events[1].clone() {
                Event::ITSInterchainTokenDeploymentStarted { message_id, .. } => {
                    assert_eq!(message_id, message.message_id);
                }
                _ => panic!("Expected ITSInterchainTokenDeploymentStarted event"),
            },
            _ => panic!("Expected Call event"),
        }
    }

    #[tokio::test]
    async fn test_its_token_metadata_registered() {
        let txs = transaction_fixtures();
        let parser = TransactionParser::new(
            "solana".to_string(),
            Pubkey::from_str("CJ9f8WFdm3q38pmg426xQf7uum7RqvrmS9R58usHwNX7").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
            Pubkey::from_str("8YsLGnLV2KoyxdksgiAi3gh1WvhMrznA2toKWqyz91bR").unwrap(),
        );
        let events = parser
            .parse_transaction(serde_json::to_string(&txs[10]).unwrap())
            .await
            .unwrap();
        assert_eq!(events.len(), 2);

        match events[0].clone() {
            Event::Call { message, .. } => match events[1].clone() {
                Event::ITSTokenMetadataRegistered { message_id, .. } => {
                    assert_eq!(message_id, message.message_id);
                }
                _ => panic!("Expected ITSTokenMetadataRegistered event"),
            },
            _ => panic!("Expected Call event"),
        }
    }
}
