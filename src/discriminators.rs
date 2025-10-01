pub const CPI_EVENT_DISC: &[u8] = &[228, 69, 165, 46, 81, 203, 154, 29]; // 0xe445a52e51cb9a1d (EVENT_IX_TAG in LE)

// gateway and gas_service events
pub const CANNOT_EXECUTE_MESSAGE_EVENT_DISC: &[u8] = &[232, 125, 221, 19, 212, 213, 137, 199]; // needs to be updated

// ITS events
pub const ITS_INTERCHAIN_TRANSFER_EVENT_DISC: &[u8] = &[211, 242, 38, 95, 148, 64, 42, 213];
pub const ITS_INTERCHAIN_TOKEN_DEPLOYMENT_STARTED_EVENT_DISC: &[u8] =
    &[145, 74, 199, 186, 210, 232, 147, 1];
pub const ITS_LINK_TOKEN_STARTED_EVENT_DISC: &[u8] = &[239, 72, 131, 181, 251, 1, 222, 130];
pub const ITS_TOKEN_METADATA_REGISTERED_EVENT_DISC: &[u8] = &[27, 31, 189, 251, 183, 41, 8, 124];
