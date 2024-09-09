//! This modules contains Rust-equivalents of Haskell types from `cardano-ledger` representing
//! errors that are sent from the cardano node in the local-TX-submission miniprotocol.
use pallas_codec::minicbor::{
    self,
    data::{Tag, Type},
    decode::{Error, Token},
    Decode, Decoder, Encode,
};
use pallas_primitives::conway::ScriptHash;
use pallas_utxorpc::TxHash;

use super::codec::NodeErrorDecoder;

/// https://github.com/IntersectMBO/cardano-ledger/blob/8fd7ab6ca9bcf9cdb1fa6f4059f84585a084efa5/eras/shelley/impl/src/Cardano/Ledger/Shelley/API/Mempool.hs#L221
#[derive(Debug, Clone)]
pub struct ApplyTxError {
    pub node_errors: Vec<ConwayLedgerPredFailure>,
}

impl Decode<'_, NodeErrorDecoder> for ApplyTxError {
    fn decode(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<Self, Error> {
        let mut non_script_errors = vec![];

        let mut probe = d.probe();
        if let Err(e) = next_token(&mut probe) {
            if e.is_end_of_input() {
                return Err(e);
            }
        }

        expect_definite_array(vec![2], d, ctx, "ApplyTxError_0")?;
        let tag = expect_u8(d, ctx)?;
        assert_eq!(tag, 2);
        expect_definite_array(vec![1], d, ctx, "ApplyTxError_1")?;
        expect_definite_array(vec![2], d, ctx, "ApplyTxError_2")?;

        // This tag is not totally understood (could represent the Cardano era).
        let _inner_tag = expect_u8(d, ctx)?;

        // Here we expect a definite array or variable size
        let num_errors = expect_definite_array(vec![], d, ctx, "ApplyTxError_3")?;
        // This top level array pop off context
        assert_eq!(
            ctx.context_stack.pop().unwrap(),
            OuterScope::Definite(num_errors)
        );
        for i in 0..num_errors {
            match ConwayLedgerPredFailure::decode(d, ctx) {
                Ok(err) => {
                    assert!(ctx.context_stack.is_empty());
                    non_script_errors.push(err);
                }
                Err(e) => {
                    if e.is_end_of_input() && (i + 1 < num_errors) {
                        return Err(e);
                    }
                }
            }
        }

        ctx.ix_start_unprocessed_bytes = d.position();
        Ok(Self {
            node_errors: non_script_errors,
        })
    }
}

impl Encode<()> for ApplyTxError {
    fn encode<W: minicbor::encode::Write>(
        &self,
        _e: &mut minicbor::Encoder<W>,
        _ctx: &mut (),
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        // We only ever decode node errors.
        unreachable!()
    }
}

#[derive(Debug, Clone)]
/// Top level type for ledger errors. See https://github.com/IntersectMBO/cardano-ledger/blob/8fd7ab6ca9bcf9cdb1fa6f4059f84585a084efa5/eras/shelley/impl/src/Cardano/Ledger/Shelley/Rules/Ledger.hs#L100
pub enum ConwayLedgerPredFailure {
    UtxowFailure(ConwayUtxowPredFailure),
    UnhandledError,
}

impl Decode<'_, NodeErrorDecoder> for ConwayLedgerPredFailure {
    fn decode(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<Self, Error> {
        if let Err(e) = expect_definite_array(vec![2, 3], d, ctx, "ConwayLedgerPredFailure") {
            if e.is_end_of_input() {
                return Err(e);
            }
            clear_unknown_entity(d, ctx)?;
        }
        match expect_u8(d, ctx) {
            Ok(tag) => match tag {
                1 => match ConwayUtxowPredFailure::decode(d, ctx) {
                    Ok(utxow_failure) => Ok(ConwayLedgerPredFailure::UtxowFailure(utxow_failure)),
                    Err(e) => {
                        if e.is_end_of_input() {
                            Err(e)
                        } else {
                            clear_unknown_entity(d, ctx)?;
                            Err(e)
                        }
                    }
                },
                _ => {
                    clear_unknown_entity(d, ctx)?;
                    Err(Error::message("not ShelleyLedgerPredFailure"))
                }
            },
            Err(e) => {
                if e.is_end_of_input() {
                    Err(e)
                } else {
                    add_collection_token_to_context(d, ctx)?;
                    clear_unknown_entity(d, ctx)?;
                    Err(Error::message(
                        "ShelleyLedgerPredFailure::decode: expected tag",
                    ))
                }
            }
        }
    }
}

/// https://github.com/IntersectMBO/cardano-ledger/blob/8fd7ab6ca9bcf9cdb1fa6f4059f84585a084efa5/eras/babbage/impl/src/Cardano/Ledger/Babbage/Rules/Utxo.hs#L109
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum ConwayUtxoPredFailure {
    /// Script-failure
    UtxosFailure(ConwayUtxosPredFailure),
    BadInputsUtxo(Vec<TxInput>),
    OutsideValidityIntervalUTxO,
    MaxTxSizeUTxO,
    InputSetEmptyUTxO,
    FeeTooSmallUTxO,
    ValueNotConservedUTxO {
        consumed_value: pallas_primitives::conway::Value,
        produced_value: pallas_primitives::conway::Value,
    },
    WrongNetwork,
    WrongNetworkWithdrawal,
    OutputTooSmallUTxO,
    OutputBootAddrAttrsTooBig,
    TriesToForgeADA,
    OutputTooBigUTxO,
    InsufficientCollateral,
    ScriptsNotPaidUTxO,
    ExUnitsTooBigUTxO,
    CollateralContainsNonADA,
    WrongNetworkInTxBody,
    OutsideForecast,
    TooManyCollateralInputs,
    NoCollateralInputs,
    IncorrectTotalCollateralField,
    BabbageOutputTooSmallUTxO,
    BabbageNonDisjointRefInputs,
}

impl Decode<'_, NodeErrorDecoder> for ConwayUtxoPredFailure {
    fn decode(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<Self, Error> {
        let arr_len = expect_definite_array(vec![2, 3], d, ctx, "ConwayUtxoPredFailure")?;
        match expect_u8(d, ctx) {
            Ok(tag) => match tag {
                0 if arr_len == 2 => {
                    // UTXOS failure (currently handle just script errors)
                    let utxos_failure = ConwayUtxosPredFailure::decode(d, ctx)?;
                    Ok(ConwayUtxoPredFailure::UtxosFailure(utxos_failure))
                }
                1 if arr_len == 2 => {
                    // BadInputsUtxo
                    let set_tag = d.tag()?;
                    assert_eq!(set_tag, Tag::Unassigned(258));
                    if let Some(num_bad_inputs) = d.array()? {
                        let mut bad_inputs = vec![];
                        for _ in 0..num_bad_inputs {
                            let tx_input = TxInput::decode(d, ctx)?;
                            bad_inputs.push(tx_input);
                        }
                        Ok(ConwayUtxoPredFailure::BadInputsUtxo(bad_inputs))
                    } else {
                        Err(Error::message("expected array of tx inputs"))
                    }
                }
                6 if arr_len == 3 => {
                    // ValueNotConservedUtxo

                    let consumed_value = decode_conway_value(d, ctx)?;
                    let produced_value = decode_conway_value(d, ctx)?;

                    Ok(ConwayUtxoPredFailure::ValueNotConservedUTxO {
                        consumed_value,
                        produced_value,
                    })
                }
                _ => Err(Error::message("not BabbageUtxoPredFailure")),
            },
            Err(e) => {
                if e.is_end_of_input() {
                    Err(e)
                } else {
                    add_collection_token_to_context(d, ctx)?;
                    Err(Error::message(
                        "BabbageUtxoPredFailure::decode: expected tag",
                    ))
                }
            }
        }
    }
}

/// https://github.com/IntersectMBO/cardano-ledger/blob/8fd7ab6ca9bcf9cdb1fa6f4059f84585a084efa5/eras/alonzo/impl/src/Cardano/Ledger/Alonzo/Rules/Utxos.hs#L398
#[derive(Debug, Clone)]
pub enum ConwayUtxosPredFailure {
    ValidationTagMismatch {
        is_valid: bool,
        description: TagMismatchDescription,
    },
    CollectErrors,
}

impl Decode<'_, NodeErrorDecoder> for ConwayUtxosPredFailure {
    fn decode(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<Self, Error> {
        let arr_len = expect_definite_array(vec![2, 3], d, ctx, "ConwayUtxosPredFailure")?;
        match expect_u8(d, ctx) {
            Ok(tag) => match tag {
                0 => {
                    if arr_len == 3 {
                        let is_valid = expect_bool(d, ctx)?;
                        let description = TagMismatchDescription::decode(d, ctx)?;
                        Ok(ConwayUtxosPredFailure::ValidationTagMismatch {
                            is_valid,
                            description,
                        })
                    } else {
                        Err(Error::message(
                            "ConwayUtxosPredFailure::decode: expected array(3) for `ValidationTagMismatch`",
                        ))
                    }
                }
                _ => Err(Error::message(format!(
                    "ConwayUtxosPredFailure::decode: unknown tag: {}",
                    tag
                ))),
            },
            Err(e) => {
                if e.is_end_of_input() {
                    Err(e)
                } else {
                    add_collection_token_to_context(d, ctx)?;
                    Err(Error::message(
                        "ConwayUtxosPredFailure::decode: expected tag",
                    ))
                }
            }
        }
    }
}

/// https://github.com/IntersectMBO/cardano-ledger/blob/8fd7ab6ca9bcf9cdb1fa6f4059f84585a084efa5/eras/alonzo/impl/src/Cardano/Ledger/Alonzo/Rules/Utxos.hs#L367
#[derive(Debug, Clone)]
pub enum TagMismatchDescription {
    PassUnexpectedly,
    FailUnexpectedly(Vec<FailureDescription>),
}

impl Decode<'_, NodeErrorDecoder> for TagMismatchDescription {
    fn decode(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<Self, Error> {
        expect_definite_array(vec![2], d, ctx, "TagMismatchDescription")?;
        match expect_u8(d, ctx) {
            Ok(tag) => match tag {
                0 => Ok(TagMismatchDescription::PassUnexpectedly),
                1 => {
                    let num_failures = expect_definite_array(
                        vec![],
                        d,
                        ctx,
                        "TagMismatchDescription: # failures",
                    )?;
                    let mut failures = Vec::with_capacity(num_failures as usize);
                    for _ in 0..num_failures {
                        let description = FailureDescription::decode(d, ctx)?;
                        failures.push(description);
                    }
                    Ok(TagMismatchDescription::FailUnexpectedly(failures))
                }
                _ => Err(Error::message(format!(
                    "TagMismatchDescription::decode: unknown tag: {}",
                    tag
                ))),
            },
            Err(e) => {
                if e.is_end_of_input() {
                    Err(e)
                } else {
                    add_collection_token_to_context(d, ctx)?;
                    Err(Error::message(
                        "TagMismatchDescription::decode: expected tag",
                    ))
                }
            }
        }
    }
}

// Describes script-error from the node. See: https://github.com/IntersectMBO/cardano-ledger/blob/8fd7ab6ca9bcf9cdb1fa6f4059f84585a084efa5/eras/alonzo/impl/src/Cardano/Ledger/Alonzo/Rules/Utxos.hs#L334
#[derive(Debug, Clone)]
pub struct FailureDescription {
    pub description: String,
    /// Hex-encoded base64 representation of the Plutus context
    pub plutus_context_base64: String,
}

impl Decode<'_, NodeErrorDecoder> for FailureDescription {
    fn decode(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<Self, Error> {
        expect_definite_array(vec![3], d, ctx, "FailureDescription")?;
        match expect_u8(d, ctx) {
            Ok(tag) => {
                if tag == 1 {
                    let description = d.str()?.to_string();
                    if let Some(OuterScope::Definite(n)) = ctx.context_stack.pop() {
                        if n > 1 {
                            ctx.context_stack.push(OuterScope::Definite(n - 1));
                        }
                    }
                    let plutus_context_base64 = hex::encode(d.bytes()?);
                    if let Some(OuterScope::Definite(n)) = ctx.context_stack.pop() {
                        if n > 1 {
                            ctx.context_stack.push(OuterScope::Definite(n - 1));
                        }
                    }
                    Ok(FailureDescription {
                        description,
                        plutus_context_base64,
                    })
                } else {
                    Err(Error::message(format!(
                        "FailureDescription::decode: expected tag == 1, got {}",
                        tag
                    )))
                }
            }
            Err(e) => {
                if e.is_end_of_input() {
                    Err(e)
                } else {
                    Err(Error::message(
                        "FailureDescription::decode: expected u8 tag",
                    ))
                }
            }
        }
    }
}

/// https://github.com/IntersectMBO/cardano-ledger/blob/8fd7ab6ca9bcf9cdb1fa6f4059f84585a084efa5/eras/alonzo/impl/src/Cardano/Ledger/Alonzo/Rules/Utxow.hs#L97
#[derive(Debug, Clone)]
pub enum ConwayUtxowPredFailure {
    UtxoFailure(ConwayUtxoPredFailure),
    MissingRedeemers,
    MissingRequiredDatums,
    NotAllowedSupplementalDatums,
    PPViewHashesDontMatch,
    UnspendableUtxoNoDatumHash,
    ExtraRedeemers,
    MalformedScriptWitnesses,
    MalformedReferenceScripts,
}

impl Decode<'_, NodeErrorDecoder> for ConwayUtxowPredFailure {
    fn decode(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<Self, Error> {
        expect_definite_array(vec![2, 3], d, ctx, "ConwayUtxowPredFailure")?;
        match expect_u8(d, ctx) {
            Ok(tag) => match tag {
                0 => {
                    let utxo_failure = ConwayUtxoPredFailure::decode(d, ctx)?;
                    Ok(ConwayUtxowPredFailure::UtxoFailure(utxo_failure))
                }
                _ => Err(Error::message(format!(
                    "AlonzoUtxowPredFailure unhandled tag {}",
                    tag
                ))),
            },
            Err(e) => {
                if e.is_end_of_input() {
                    Err(e)
                } else {
                    add_collection_token_to_context(d, ctx)?;
                    Err(Error::message(
                        "AlonzoUtxoPredwFailure::decode: expected tag",
                    ))
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TxInput {
    pub tx_hash: TxHash,
    pub index: u64,
}

impl Decode<'_, NodeErrorDecoder> for TxInput {
    fn decode(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<Self, Error> {
        expect_definite_array(vec![2], d, ctx, "TxInput")?;
        let bytes = expect_bytes(d, ctx)?;
        let tx_hash = TxHash::from(bytes.as_slice());
        match d.probe().int() {
            Ok(index) => {
                if let Some(OuterScope::Definite(n)) = ctx.context_stack.pop() {
                    if n > 1 {
                        ctx.context_stack.push(OuterScope::Definite(n - 1));
                    }
                }
                let _ = d.int()?;
                let index =
                    u64::try_from(index).map_err(|_| Error::message("Can't convert Int to u64"))?;
                Ok(TxInput { tx_hash, index })
            }
            Err(e) => {
                if e.is_end_of_input() {
                    Err(e)
                } else {
                    add_collection_token_to_context(d, ctx)?;
                    Err(Error::message("TxInput::decode: expected index (int)"))
                }
            }
        }
    }
}

/// Process the next CBOR token, adjusting the position if the outer scope is a definite array.
/// If this token represents a new collection, add new scope to the stack.
fn add_collection_token_to_context(
    d: &mut Decoder,
    ctx: &mut NodeErrorDecoder,
) -> Result<(), Error> {
    let t = next_token(d)?;
    if let Some(OuterScope::Definite(n)) = ctx.context_stack.pop() {
        if n > 1 {
            ctx.context_stack.push(OuterScope::Definite(n - 1));
        }
    }
    match t {
        Token::BeginArray | Token::BeginBytes | Token::BeginMap => {
            ctx.context_stack.push(OuterScope::Indefinite);
        }
        Token::Array(n) | Token::Map(n) => {
            ctx.context_stack.push(OuterScope::Definite(n));
        }

        Token::Tag(_) => {
            ctx.context_stack.push(OuterScope::Definite(1));
        }

        // Throw away the token
        _ => (),
    }

    Ok(())
}

fn expect_indefinite_array(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<(), Error> {
    match d.probe().array() {
        Ok(None) => {
            if let Some(OuterScope::Definite(inner_n)) = ctx.context_stack.pop() {
                if inner_n > 1 {
                    ctx.context_stack.push(OuterScope::Definite(inner_n - 1));
                }
            }
            let _ = d.array()?;
            Ok(())
        }
        Ok(Some(n)) => {
            if let Some(OuterScope::Definite(inner_n)) = ctx.context_stack.pop() {
                if inner_n > 1 {
                    ctx.context_stack.push(OuterScope::Definite(inner_n - 1));
                }
            }
            ctx.context_stack.push(OuterScope::Definite(n));
            Err(Error::message(format!(
                "Expected indefinite array, got array({}), response_bytes: {}",
                n,
                hex::encode(&ctx.response_bytes)
            )))
        }
        Err(e) => {
            if e.is_end_of_input() {
                Err(e)
            } else {
                add_collection_token_to_context(d, ctx)?;
                Err(Error::message(format!(
                    "Expected indefinite array, error: {:?}",
                    e
                )))
            }
        }
    }
}

fn expect_bytes(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<Vec<u8>, Error> {
    match d.probe().bytes() {
        Ok(bytes) => {
            if let Some(OuterScope::Definite(n)) = ctx.context_stack.pop() {
                if n > 1 {
                    ctx.context_stack.push(OuterScope::Definite(n - 1));
                }
            }
            let _ = d.bytes()?;
            Ok(bytes.to_vec())
        }
        Err(e) => {
            if e.is_end_of_input() {
                Err(e)
            } else {
                add_collection_token_to_context(d, ctx)?;
                Err(Error::message("TxInput::decode: expected bytes"))
            }
        }
    }
}

fn expect_definite_array(
    possible_lengths: Vec<u64>,
    d: &mut Decoder,
    ctx: &mut NodeErrorDecoder,
    calling_ctx: &str,
) -> Result<u64, Error> {
    match d.probe().array() {
        Ok(Some(len)) => {
            if let Some(OuterScope::Definite(inner_n)) = ctx.context_stack.pop() {
                if inner_n > 1 {
                    ctx.context_stack.push(OuterScope::Definite(inner_n - 1));
                }
            }
            ctx.context_stack.push(OuterScope::Definite(len));
            let _ = d.array()?;
            if possible_lengths.is_empty() || possible_lengths.contains(&len) {
                Ok(len)
            } else {
                Err(Error::message(format!(
                    "Expected array({:?}), got array({}), calling_context: {}, response_bytes: {}",
                    possible_lengths,
                    len,
                    calling_ctx,
                    hex::encode(&ctx.response_bytes)
                )))
            }
        }
        Ok(None) => {
            let t = next_token(d)?;
            assert!(matches!(t, Token::BeginArray));
            Err(Error::message(format!(
                "Expected array({:?}), got indefinite array, calling_context: {}, response_bytes: {}",
                possible_lengths, calling_ctx,
                    hex::encode(&ctx.response_bytes)
            )))
        }
        Err(e) => {
            if e.is_end_of_input() {
                // Must explicitly return this error, to allow decoding to stop early.
                Err(e)
            } else {
                add_collection_token_to_context(d, ctx)?;
                Err(Error::message(format!(
                    "Expected array({:?}), calling_context: {}, response_bytes: {}",
                    possible_lengths,
                    calling_ctx,
                    hex::encode(&ctx.response_bytes)
                )))
            }
        }
    }
}

fn expect_u8(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<u8, Error> {
    match d.probe().u8() {
        Ok(value) => {
            if let Some(OuterScope::Definite(n)) = ctx.context_stack.pop() {
                if n > 1 {
                    ctx.context_stack.push(OuterScope::Definite(n - 1));
                }
            }
            let _ = d.u8()?;
            Ok(value)
        }
        Err(e) => {
            if e.is_end_of_input() {
                Err(e)
            } else {
                add_collection_token_to_context(d, ctx)?;
                Err(Error::message(format!("Expected u8: error: {:?}", e)))
            }
        }
    }
}

fn expect_u64(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<u64, Error> {
    match d.probe().int() {
        Ok(value) => {
            if let Some(OuterScope::Definite(n)) = ctx.context_stack.pop() {
                if n > 1 {
                    ctx.context_stack.push(OuterScope::Definite(n - 1));
                }
            }
            let _ = d.int()?;
            Ok(u64::try_from(value).map_err(|e| Error::message(e.to_string()))?)
        }
        Err(e) => {
            if e.is_end_of_input() {
                Err(e)
            } else {
                add_collection_token_to_context(d, ctx)?;
                Err(Error::message(format!("Expected u64, error: {:?}", e)))
            }
        }
    }
}

fn expect_bool(d: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<bool, Error> {
    match d.probe().bool() {
        Ok(value) => {
            if let Some(OuterScope::Definite(n)) = ctx.context_stack.pop() {
                if n > 1 {
                    ctx.context_stack.push(OuterScope::Definite(n - 1));
                }
            }
            let _ = d.bool()?;
            Ok(value)
        }
        Err(e) => {
            if e.is_end_of_input() {
                Err(e)
            } else {
                add_collection_token_to_context(d, ctx)?;
                Err(Error::message(format!("Expected bool, error: {:?}", e)))
            }
        }
    }
}

fn decode_conway_value(
    d: &mut Decoder,
    ctx: &mut NodeErrorDecoder,
) -> Result<pallas_primitives::conway::Value, Error> {
    use pallas_primitives::conway::Value;
    match d.datatype() {
        Ok(dt) => {
            match dt {
                minicbor::data::Type::U8
                | minicbor::data::Type::U16
                | minicbor::data::Type::U32
                | minicbor::data::Type::U64 => {
                    if let Some(OuterScope::Definite(n)) = ctx.context_stack.pop() {
                        if n > 1 {
                            ctx.context_stack.push(OuterScope::Definite(n - 1));
                        }
                    }
                    Ok(Value::Coin(d.decode_with(ctx)?))
                }
                minicbor::data::Type::Array => {
                    expect_definite_array(vec![2], d, ctx, "decode_conway_value")?;
                    let coin = expect_u64(d, ctx)?;
                    let multiasset = d.decode_with(ctx)?;
                    // If multiasset is successfully decoded, let's manually update outer scope.
                    if let Some(OuterScope::Definite(n)) = ctx.context_stack.pop() {
                        if n > 1 {
                            ctx.context_stack.push(OuterScope::Definite(n - 1));
                        }
                    }

                    Ok(pallas_primitives::conway::Value::Multiasset(
                        coin, multiasset,
                    ))
                }
                _ => Err(minicbor::decode::Error::message(
                    "unknown cbor data type for Alonzo Value enum",
                )),
            }
        }
        Err(e) => {
            if e.is_end_of_input() {
                Err(e)
            } else {
                add_collection_token_to_context(d, ctx)?;
                Err(Error::message(format!(
                    "Can't decode Conway Value, error: {:?}",
                    e
                )))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuterScope {
    /// We are within a definite CBOR collection such as an array or map. The inner `u64` indicates
    /// the number of elements left to be processed within the collection.
    Definite(u64),
    /// We are within an indefinite collection.
    Indefinite,
}

fn clear_unknown_entity(decoder: &mut Decoder, ctx: &mut NodeErrorDecoder) -> Result<(), Error> {
    while let Some(e) = ctx.context_stack.pop() {
        let t = next_token(decoder)?;

        match e {
            OuterScope::Definite(num_left) => {
                if num_left > 1 {
                    ctx.context_stack.push(OuterScope::Definite(num_left - 1));
                }
            }
            OuterScope::Indefinite => ctx.context_stack.push(OuterScope::Indefinite),
        }

        match t {
            Token::BeginArray | Token::BeginBytes | Token::BeginMap => {
                ctx.context_stack.push(OuterScope::Indefinite);
            }

            Token::Array(n) | Token::Map(n) => {
                ctx.context_stack.push(OuterScope::Definite(n));
            }

            Token::Tag(_) => {
                ctx.context_stack.push(OuterScope::Definite(1));
            }

            Token::Break => {
                assert_eq!(e, OuterScope::Indefinite);
                assert_eq!(ctx.context_stack.pop(), Some(OuterScope::Indefinite));
            }

            // Throw away the token
            _ => (),
        }
    }
    Ok(())
}

fn next_token<'a>(decoder: &'a mut Decoder) -> Result<Token<'a>, Error> {
    match decoder.datatype()? {
        Type::Bool => decoder.bool().map(Token::Bool),
        Type::U8 => decoder.u8().map(Token::U8),
        Type::U16 => decoder.u16().map(Token::U16),
        Type::U32 => decoder.u32().map(Token::U32),
        Type::U64 => decoder.u64().map(Token::U64),
        Type::I8 => decoder.i8().map(Token::I8),
        Type::I16 => decoder.i16().map(Token::I16),
        Type::I32 => decoder.i32().map(Token::I32),
        Type::I64 => decoder.i64().map(Token::I64),
        Type::Int => decoder.int().map(Token::Int),
        Type::F16 => decoder.f16().map(Token::F16),
        Type::F32 => decoder.f32().map(Token::F32),
        Type::F64 => decoder.f64().map(Token::F64),
        Type::Bytes => decoder.bytes().map(Token::Bytes),
        Type::String => decoder.str().map(Token::String),
        Type::Tag => decoder.tag().map(Token::Tag),
        Type::Simple => decoder.simple().map(Token::Simple),
        Type::Array => {
            let p = decoder.position();
            if let Some(n) = decoder.array()? {
                Ok(Token::Array(n))
            } else {
                Err(Error::type_mismatch(Type::Array)
                    .at(p)
                    .with_message("missing array length"))
            }
        }
        Type::Map => {
            let p = decoder.position();
            if let Some(n) = decoder.map()? {
                Ok(Token::Map(n))
            } else {
                Err(Error::type_mismatch(Type::Array)
                    .at(p)
                    .with_message("missing map length"))
            }
        }
        Type::BytesIndef => {
            decoder.set_position(decoder.position() + 1);
            Ok(Token::BeginBytes)
        }
        Type::StringIndef => {
            decoder.set_position(decoder.position() + 1);
            Ok(Token::BeginString)
        }
        Type::ArrayIndef => {
            decoder.set_position(decoder.position() + 1);
            Ok(Token::BeginArray)
        }
        Type::MapIndef => {
            decoder.set_position(decoder.position() + 1);
            Ok(Token::BeginMap)
        }
        Type::Null => {
            decoder.set_position(decoder.position() + 1);
            Ok(Token::Null)
        }
        Type::Undefined => {
            decoder.set_position(decoder.position() + 1);
            Ok(Token::Undefined)
        }
        Type::Break => {
            decoder.set_position(decoder.position() + 1);
            Ok(Token::Break)
        }
        t @ Type::Unknown(_) => Err(Error::type_mismatch(t)
            .at(decoder.position())
            .with_message("unknown cbor type")),
    }
}

#[cfg(test)]
mod tests {
    use std::{iter::repeat, path::PathBuf};

    use itertools::Itertools;
    use pallas_codec::minicbor::{
        encode::{write::EndOfSlice, Error},
        Encoder,
    };

    use crate::miniprotocols::localtxsubmission::{
        cardano_node_errors::NodeErrorDecoder,
        codec::{DecodeCBORSplitPayload, DecodingResult},
        Message,
    };

    //#[test]
    //fn test_decode_malformed_error() {
    //    let buffer = encode_trace().unwrap();

    //    let mut cc = NodeErrorDecoder::new();
    //    let result = cc.try_decode_with_new_bytes(&buffer);
    //    if let Ok(DecodingResult::Complete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 1);
    //        assert_eq!(errors[0].node_errors.len(), 0);
    //    } else {
    //        panic!("")
    //    }
    //}

    const NON_SCRIPT_ERROR_0: &str = "82028182068582018203d9010281581c1f14754b4bedfd83f19c4dd2264af542ab8f69ce0f28bc5aac3e7fce8201820f8182010082018202d9010281581c970f87908520c94ec260888f5b3ea56fba14cb60e463cc46a9e01442820182008306821b00000001f288eeb4a1581c1f14754b4bedfd83f19c4dd2264af542ab8f69ce0f28bc5aac3e7fcea1491b00238d7ea4c6800001821b00000003e511dd68a1581c1f14754b4bedfd83f19c4dd2264af542ab8f69ce0f28bc5aac3e7fcea1491b00238d7ea4c6800001820182008201d901028182582000bd6295ae836ad03066712ca22c93d9263c6f18c04c0af62f76457d86d0010a03";

    //fn encode_trace() -> Result<Vec<u8>, Error<EndOfSlice>> {
    //    let mut buffer = repeat(0).take(24).collect_vec();
    //    let mut encoder = Encoder::new(&mut buffer[..]);

    //    let _e = encoder
    //        .array(2)?
    //        .u8(2)?
    //        .array(1)?
    //        .array(2)?
    //        .u8(5)?
    //        .begin_array()?
    //        // Encode ledger errors
    //        .array(2)?
    //        .u8(0)? // Tag for BabbageUtxowPredFailure
    //        .array(2)?
    //        .u8(2)? // Tag for BabbageUtxoPredFailure
    //        .array(2)?
    //        .u8(1)? // Tag for AlonzoUtxoPredFailure
    //        .array(2)?
    //        .u8(100)? // Unsupported Tag
    //        .array(1)? // dummy value
    //        .array(1)? // dummy value
    //        .array(1)? // dummy value
    //        .array(1)? // dummy value
    //        .array(1)? // dummy value
    //        .array(1)? // dummy value
    //        .u8(200)?
    //        .end()?;

    //    Ok(buffer)
    //}

    #[test]
    fn test_decode_non_script_error() {
        let bytes = hex::decode(NON_SCRIPT_ERROR_0).unwrap();

        let mut cc = NodeErrorDecoder::new();
        let result = cc.try_decode_with_new_bytes(&bytes);
        if let Ok(DecodingResult::Complete(Message::RejectTx(errors))) = result {
            dbg!(&errors);
            assert!(!cc.has_undecoded_bytes());
        } else {
            panic!("ZZZ: {:?}", result);
        }
    }

    #[test]
    fn test_decode_split_error() {
        let mut bytes = hex::decode(NON_SCRIPT_ERROR_0).unwrap();

        let tail = bytes.split_off(bytes.len() / 2);
        let mut cc = NodeErrorDecoder::new();
        let result = cc.try_decode_with_new_bytes(&bytes);
        println!("{:?}", result);
        if let Ok(DecodingResult::Incomplete(Message::RejectTx(errors))) = result {
            assert_eq!(errors.len(), 0);
            assert!(cc.has_undecoded_bytes());
        } else {
            panic!("");
        }
        let result = cc.try_decode_with_new_bytes(&tail);
        if let Ok(DecodingResult::Complete(Message::RejectTx(errors))) = result {
            dbg!(&errors);
            assert!(!cc.has_undecoded_bytes());
        } else {
            panic!("ZZZ: {:?}", result);
        }
    }

    const CONWAY_SCRIPT_ERROR_INCOMPLETE: &str = "8202818206818201820082008300f582018183017939a50a54686520506c75747573563220736372697074206661696c65643a0a4261736536342d656e636f646564207363726970742062797465733a0a2257516475415141414d6a49794d6a49794d694a544d77417a4a544d6a4d415577415441474e3152674247414f62716741784d6a49794d6a4d7a496949794d7a4d41454145415541524b4a45524b5a6d416f41474941496d526b706d5943774167705145794d7a4d41634163414977476742564d7a41554145457a4d4167414d4145416b556f47417741495944414168674c41426d3677774244414c4e3151415a75734d414577437a6455414762724441434d4173335641426d526b5a47526b5a475245526b5a4b5a6d417159434a674c47366f4145544a544d77466a4e3135674e6d3677774744497a6467627144415941424e3035674d67416d366f41464d42416b454141424d6a49794d6a49794d6a49794d6a49794d6a49794d6a49794d6a49794d6a49794d6c4d7a417655794d7a417741444579557a4d44457a63535a7543414a4e3170675747426d627167427a4e77536d5a6759674a695a75414d334141474145414643415962725441754d444d335641446941434b55464d7a41774154457741544e77426d344141674163416b564d7a41774153457741514342557a4d444177415143424d33456d626755674141436a4e77414134424970514579557a4d4445774c5441794e315141496d526b5a47526b5a47526b5a47526b5a4b5a6d42365a754a4d334241456d3630774f44412f4e3151435a6d3449415933576d42305948357571415446544d7750514252557a4d44304151564d7a4139414446544d77505141684142464b417051464b417051464b426d36384173794d6a49794d6a49794d335370414147594935676b41446d594935676b414447594935676b41436d594935756f41514d77527a424941454d77527a424941444d77527a424941434d77527a424941424d77527a64514163594a4a676b67416d43514143594934414a676a41416d434b59496f414a676941416d434741435948787571416e4d335867494148715a6d42305a754a4e317067666d43415949426767474341594942676547366f4355414d556f694161706d59484944676d41555a75414d334141436742674a43706d59484944596d4155414b4b6d5a67636d4155414b4a6d346b7a63436b4141416d5a754141444153464b426d346b41497a63475a7543414541504151557a4d4463426b544e77426d344142494145424151456a4e7749426f414a75744d4334774e7a645541495a7542414d41424e31706753474271627167416a416c41424d4459774d7a645541434c474251594752757141664e784a6d3446544d774c774568414f457a4d77495144774667465567426c4d7a41764153454173544d7a4168414d41574156534147454145556f47536d5a675a4141696c455449794d774151415141794a544d774e51415253674a6b706d59475a6d34383358474277414541494b55524d77417741774154413441424e31786761414f6d3677774d7a41304d4451774e4441304d4451774e4441304d4451774e4441304d4451774d44645541795a757641424d4449774d7a417a4d444d774d7a417a4d444d774d7a417a4d444d774c7a64554177594535675847366f4273774a6a41744e3151444267586d426759474267594742675947426759474267594668757141564e317067524742576271674644646159444a675647366f424d33576d425959467067576d426159467067556d366f42497a63434145414b5a7542557a4d435541635141524d7a4d42634149416f416c49415a544d774a5142784145457a4d77467742514367435567426a646159457867556d3673774a6a417041434d436b414533566d412b594568757141524e317067526d424d62717a416a4d43594149774a674154645759446867516d366f41777a636541476b5241444e78344169524151413358474179594478757141454e3178674c474136627167417a6463594335674f47366f414d335847416f59445a757141434d423077486a41654d423477486a41654d423477476a64554147594235674d6d366f414977435141525369594452674c6d366f4145556f6d4159594378757141424d42417746546455414752674b6d4173594378674c41416b52455a475a674167416743674245524b5a6d41715a7549534141414246544d774741416853414145794d6a4a544d7747444e783575754d426b414d416b5449794d6c4d7a41624d33486d363477484141774378414246544d774867416853414146544d77486a4168414345794d6c4d7a41644d33486d36347748674167445241424649414133576d41384143594541415173627254416341434d4238414977485141524d7a4147414741434d334141434a41416d3673774751416a416341444d426f4149574a544d77446a41464d413833564141695a47526b5a47526b5a47526b5a47526b5a47526b5a47526b5a47526b5a47526b706d59464a67574142435a47526b5a47535447526d41434143414d524b5a6d426541434b54435a47594159415a675a6742473634774d5141564d7a41704d4341774b6a645541514a6b5a47526b706d594742675a6742435a47535447536d5a67586d424d41434a6b5a4b5a6d426f59473441516d535447536d5a675a47425341434a6b5a4b5a6d427559485141516d535447425341434c47427741435947687571414346544d774d6a416f414245794d6a49794d6a4a544d774f7a412b4143464a685933576d42344143594867415275744d446f4145774f67416a6461594841414a676147366f4149574d4449335641416978676167416d42696271674178557a4d4338774a514152557a4d4449774d54645541474b54437773594635757141434d4349414d574d44454145774d51416a417641424d43733356414543796d5a675547412b59464a7571414c45794d6a4979557a4d4338774d6741685359574e3170675941416d42674145627254417541424d436f335641466978674e6747474130416d4c473677774b674154417141434e3178675541416d42514145594577414a67544142473630774a414154416b41434d43494145774967416a416741424d4341414933576d41384143594477415275744d42774145774841416a6461594451414a674e41424741774143594441415275754d42594145774667416a6463594367414a674947366f4145574a544d77445441454d413433564141695a47526b5a4b5a6d416f5943344151704d4c4736347746514154415641434e3178674a67416d41656271674152596a4a544d7744544145414245794d6c4d7a41534d42554149556d466a6463594359414a67486d366f4149564d7a414e4d414d4145544979557a4d424977465141685359574e3178674a67416d41656271674168597744546455414362683067416a634f6b4141526748474165594234414a47416159427867484741635942786748474163594278674841416d414359424275714145497743774154634f6b41494c4559424a67464141696b776d7973726d6c567a7171353556632b726f466443726f68220a5468652073637269707420686173682069733a5363726970744861736820223936663563316265653233343831333335666634616563653332666531646661316161343061393434613636643264366564633961396135220a54686520706c75747573206576616c756174696f6e206572726f722069733a2043656b4572726f7220416e206572726f7220686173206f636375727265643a0a546865206d616368696e65207465726d696e617465642062656361757365206f6620616e206572726f722c206569746865722066726f6d2061206275696c742d696e2066756e6374696f6e206f722066726f6d20616e206578706c6963697420757365206f6620276572726f72272e0a5468652070726f746f636f6c2076657273696f6e2069733a2056657273696f6e20390a4c6567616379506c75747573417267732032203a200a2020202052656465656d65723a0a2020202020202020205b5d0a20202020536372697074436f6e746578743a0a202020202020202020507572706f73653a20526577617264696e6720285374616b696e6748617368202853637269707443726564656e7469616c20393666356331626565323334383133333566663461656365333266653164666131616134306139343461363664326436656463396139613529290a2020202020202020205478496e666f3a0a2020202020202020202020547849643a20373662383732366336383864663636353132346434656433353939383365383462643930396366653164656661376466613736383438663530316261633165630a2020202020202020202020496e707574733a205b20323737666235646631343966363763323833353861353032623265636633643935376463313933643462386362363938326339613139356262636334333265342130202d3e202d2056616c7565207b67657456616c7565203d204d6170207b756e4d6170203d205b282c4d6170207b756e4d6170203d205b2822222c32333932303530295d7d292c2832306633626138316161643830336562336131656135366539373661613334323665646436383630653935623732373330393131303537372c4d6170207b756e4d6170203d205b282243617264616e6f20446f67676965222c3230333934303235295d7d295d7d7d2061646472657373656420746f0a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202053637269707443726564656e7469616c3a20343634656565653839663035616666373837643430303435616632613430613833666439366335313331393764333266626335346666303220285374616b696e6748617368205075624b657943726564656e7469616c3a206435346436643566653361363936343337636639396533663165356433353663643061383633633139626633656237633731663633303133290a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020207769746820646174756d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020696e6c696e6520646174756d203a20203c41413d3d2c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020206952664a6c39422b78356143442b666642757a413736375765433543574e74346c457a3941773d3d2c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c49504f3667617259412b7336487156756c32716a516d37646147447057334a7a4352454664773d3d2c0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020513246795a474675627942456232646e6157553d3e2c0a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202032303339343032352c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203630303030302c0a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202033303834393733342c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c2c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203e2c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c31353132363834393430383039383639352c0a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202031303030303030303030303030303030303e2c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203235303030302c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3c4f56353339346154794f7a7175646b364e35566e377a302f476b4a30474d4e75357a516c33513d3d3e2c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c3c3c31553174582b4f6d6c6b4e382b5a342f486c3031624e436f59384762382b74386366597745773d3d3e3e3e3e2c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020204f56353339346154794f7a7175646b364e35566e377a302f476b4a30474d4e75357a516c33513d3d2c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020205b3762387a3964626767356347534f4f5264635365776343543333613235714478527a354864673d3d5d3e0a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202077697468207265666572656e63655363726970740a0a202020202020202020202020202020202020202c20366636343038653332373031643665353438303035393365393931386536306333343663626137323633336332373362613865623430353061343863303639662131202d3e202d2056616c7565207b67657456616c7565203d204d6170207b756e4d6170203d205b282c4d6170207b756e4d6170203d205b2822222c3935353137393539295d7d292c2832306633626138316161643830336562336131656135366539373661613334323665646436383630653935623732373330393131303537372c4d6170207b756e4d6170203d205b282243617264616e6f20446f67676965222c393333323430383737295d7d292c2836336639343762386439353335626334653463653639313965336463303536353437653864333061646131326632396161356638323662382c4d6170207b756e4d6170203d205b283078616266613336313939376634646539383063396437313432346461386563303066323761616162616239316663373134353039313865646365343834376638312c31295d7d295d7d7d2061646472657373656420746f0a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202053637269707443726564656e7469616c3a20393035616238363939363162303934663162383139373237386366653135623435636265343966613866333263366230313466383561326420285374616b696e67486173682053637269707443726564656e7469616c3a206232663661626636306363646539326561653161326634666466363566326561663632303864383732633666306535393763633130623037290a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020207769746820646174756d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020696e6c696e6520646174756d203a20203c3c592f6c48754e6c545738546b7a6d6b5a343977465a55666f3077726145764b617066676d75413d3d2c0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020712f6f32475a66303370674d6e58464354616a7341504a367172713548386355554a474f334f53456634453d3e2c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c2c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203e2c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203c49504f3667617259412b7336487156756c32716a516d37646147447057334a7a4352454664773d3d2c0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020513246795a474675627942456232646e6157553d3e2c0a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202037343733373332393631342c0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020313237343831382c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203762387a3964626767356347534f4f5264635365776343543333613235714478527a354864673d3d2c0a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202031303939313137353030302c0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020206941663735754e7248445774627a62776d543476786e71323874734742427a364f6c504153673d3d2c0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020565532765069666c444978336c784f2b613663506c634e66492f42564b696a6c70364e4146413d3d3e0a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202077697468207265666572656e63655363726970740a0a202020202020202020202020202020202020202c20643563663637663165346334646563663532346665353031653430646233346334653162313065386261316538623463623738643030623131393938356666302132202d3e202d2056616c7565207b67657456616c7565203d204d6170207b756e4d6170203d205b282c4d6170207b756e4d6170203d205b2822222c31303731353634373038295d7d295d7d7d2061646472657373656420746f0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020205075624b657943726564656e7469616c3a20656462663333663564366530383339373036343865333931373563343965633163303933646637366236653661306631343733653437373620285374616b696e6748617368205075624b657943726564656e7469616c3a203039386438386335346532633339356164376365326661323530393464333362343733303463643136613961326366643634303134333530290a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020207769746820646174756d0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020206e6f20646174756d0a20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202077697468207265666572656e63655363726970740a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020205d0a20202020202020202020205265666572656e636520696e707574733a205b20623931656461323964313435616236633062633064366237303933636232346231333134343062376230313530333332303534373666333963363930613531662130202d3e202d2056616c7565207b67657456616c7565203d204d6170207b756e4d6170203d205b282c4d6170207b756e4d6170203d205b2822222c35353334303430295d7d295d7d7d2061646472657373656420746f0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202053637269707443726564656e7469616c3a20346563353066323632346261363230343362656534343434386263396233383866613137326530623733656639346333616232663830393420286e6f207374616b696e672063726564656e7469616c290a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020207769746820646174756d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020206e6f20646174756d0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202077697468207265666572656e63655363726970740a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202034363465656565383966303561666637383764343030343561663261343061383366643936633531333139376433326662633534666630320a20202020202020202020202020202020202020202020202020202020202c20623931656461323964313435616236633062633064366237303933636232346231333134343062376230313530333332303534373666333963363930613531662131202d3e202d2056616c7565207b67657456616c7565203d204d6170207b756e4d6170203d205b282c4d6170207b756e4d6170203d205b2822222c39313234323730295d7d295d7d7d2061646472657373656420746f0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202053637269707443726564656e7469616c3a20346563353066323632346261363230343362656534343434386263396233383866613137326530623733656639346333616232663830393420286e6f207374616b696e672063726564656e7469616c290a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020207769746820646174756d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020206e6f20646174756d0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202077697468207265666572656e63655363726970740a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202039366635633162656532333438313333356666346165636533326665316466613161613430613934346136366432643665646339613961350a20202020202020202020202020202020202020202020202020202020202c20633461353430616332653036633231376464346662336633396361333836336461333934626131333436373764616661396239383833306361373164353834642133202d3e202d2056616c7565207b67657456616c7565203d204d6170207b756e4d6170203d205b282c4d6170207b756e4d6170203d205b2822222c39353333373230295d7d295d7d7d2061646472657373656420746f0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202053637269707443726564656e7469616c3a20346563353066323632346261363230343362656534343434386263396233383866613137326530623733656639346333616232663830393420286e6f207374616b696e672063726564656e7469616c290a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020207769746820646174756d0a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020206e6f20646174756d0a2020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202077697468207265666572656e63655363726970740a202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020203930356162383639393631623039346631623831393732373863666531356234356362653439666138663332633662303134663835613264205d0a20202020202020202020204f7574707574733a205b202d2056616c7565207b67657456616c7565203d204d6170207b756e4d6170203d205b282c4d6170207b756e4d6170203d205b2822222c3332333739363030295d7d295d7d7d2061646472657373656420746f0a2020202020202020202020202020202020202020202020205075624b657943726564656e7469616c3a20333935653737663738363933633865636561623964393361333739353637656633643366316134323734313863333665653733343235646420285374616b696e6748617368205075624b657943726564656e7469616c3a206435346436643566653361363936343337636639396533663165356433353663643061383633633139626633656237633731663633303133290a2020202020202020202020202020202020202020202020207769746820646174756d0a2020202020202020202020202020202020202020202020206e6f20646174756d0a20202020202020202020202020202020202020202020202077697468207265666572656e63655363726970740a0a20202020202020202020202020202020202020202c202d2056616c7565207b67657456616c7565203d204d6170207b756e4d6170203d205b282c4d6170207b756e4d6170203d205b2822222c3634353930313436295d7d292c2832306633626138316161643830336562336131656135366539373661613334323665646436383630653935623732373330393131303537372c4d";
    #[test]
    fn test_decode_conway_script_incomplete() {
        let bytes = hex::decode(CONWAY_SCRIPT_ERROR_INCOMPLETE).unwrap();

        let mut cc = NodeErrorDecoder::new();
        let result = cc.try_decode_with_new_bytes(&bytes);
        if let Ok(DecodingResult::Incomplete(Message::RejectTx(errors))) = result {
            assert!(errors[0].node_errors.is_empty());
        } else {
            panic!("ZZZ: {:?}", result);
        }
    }

    //#[test]
    //fn test_decode_non_script_error_1() {
    //    let bytes = hex::decode(NON_SCRIPT_ERROR_1).unwrap();

    //    let mut cc = NodeErrorDecoder::new();
    //    let result = cc.try_decode_with_new_bytes(&bytes);
    //    if let Ok(DecodingResult::Complete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 1);
    //        assert!(!cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }
    //}

    //#[test]
    //fn test_decode_non_script_error_2() {
    //    let bytes = hex::decode(NON_SCRIPT_ERROR_2).unwrap();
    //    let mut cc = NodeErrorDecoder::new();
    //    let result = cc.try_decode_with_new_bytes(&bytes);
    //    matches!(
    //        result,
    //        Ok(DecodingResult::Complete(Message::RejectTx(_errors))),
    //    );
    //}

    //#[derive(Debug, PartialEq, Eq)]
    //struct ScriptError {
    //    error_description: String,
    //    plutus_context_bytes: Vec<u8>,
    //}

    //#[test]
    //fn complete_script_err() {
    //    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    //    path.push("test_resources/complete_script_error.txt");
    //    let bytes = hex::decode(
    //        std::fs::read_to_string(path).expect("Cannot load script_error_traces.txt"),
    //    )
    //    .unwrap();
    //    let mut cc = NodeErrorDecoder::new();
    //    let result = cc.try_decode_with_new_bytes(&bytes);
    //    if let Ok(DecodingResult::Complete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 1);
    //        assert!(!cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }
    //}

    //#[test]
    //fn split_script_err() {
    //    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    //    path.push("test_resources/complete_script_error.txt");
    //    let mut bytes = hex::decode(
    //        std::fs::read_to_string(path).expect("Cannot load script_error_traces.txt"),
    //    )
    //    .unwrap();
    //    let tail = bytes.split_off(bytes.len() / 2);
    //    let mut cc = NodeErrorDecoder::new();
    //    let result = cc.try_decode_with_new_bytes(&bytes);
    //    println!("{:?}", result);
    //    if let Ok(DecodingResult::Incomplete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 0);
    //        assert!(cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }

    //    let result = cc.try_decode_with_new_bytes(&tail);
    //    if let Ok(DecodingResult::Complete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 1);
    //        assert!(!cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }
    //}

    //#[test]
    //fn combined_splash_errors() {
    //    let mut bytes = hex::decode(NON_SCRIPT_ERROR_1).unwrap();
    //    bytes.extend_from_slice(&hex::decode(NON_SCRIPT_ERROR_0).unwrap());

    //    let mut cc = NodeErrorDecoder::new();
    //    let result = cc.try_decode_with_new_bytes(&bytes);
    //    println!("{:?}", result);
    //    if let Ok(DecodingResult::Complete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 2);
    //        assert!(!cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }
    //}

    //#[test]
    //fn neat_split_combined_splash_errors() {
    //    // We have 2 node errors side-by-side, where each error's bytes are cut in half
    //    // for partial processing.
    //    let mut bot_bytes_0 = hex::decode(NON_SCRIPT_ERROR_1).unwrap();
    //    let bot_bytes_1 = bot_bytes_0.split_off(bot_bytes_0.len() / 2);
    //    let mut dao_bytes_0 = hex::decode(NON_SCRIPT_ERROR_0).unwrap();
    //    let dao_bytes_1 = dao_bytes_0.split_off(dao_bytes_0.len() / 2);

    //    let mut cc = NodeErrorDecoder::new();
    //    let result = cc.try_decode_with_new_bytes(&bot_bytes_0);
    //    println!("{:?}", result);
    //    if let Ok(DecodingResult::Incomplete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 0);
    //        assert!(cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }

    //    let result = cc.try_decode_with_new_bytes(&bot_bytes_1);
    //    if let Ok(DecodingResult::Complete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 1);
    //        assert!(!cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }

    //    // Internal byte buffered has cleared from previous complete decoding. The incoming bytes does not
    //    // contain a complete `ApplyTxError` instance.
    //    let result = cc.try_decode_with_new_bytes(&dao_bytes_0);
    //    if let Ok(DecodingResult::Incomplete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 0);
    //        assert!(cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }

    //    let result = cc.try_decode_with_new_bytes(&dao_bytes_1);
    //    if let Ok(DecodingResult::Complete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 1);
    //        assert!(!cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }
    //}

    //#[test]
    //fn mixed_split_combined_splash_errors() {
    //    // We have 2 node errors side-by-side, where each error's bytes are cut in half
    //    // but this is followed by cutting off a part of the end of the first error and
    //    // prepending it to the 2nd error.
    //    let mut bot_bytes_0 = hex::decode(NON_SCRIPT_ERROR_1).unwrap();
    //    let mut bot_bytes_1 = bot_bytes_0.split_off(bot_bytes_0.len() / 2);
    //    let mut bot_bytes_2 = bot_bytes_1.split_off(bot_bytes_1.len() / 4);
    //    let mut dao_bytes_0 = hex::decode(NON_SCRIPT_ERROR_0).unwrap();
    //    let dao_bytes_1 = dao_bytes_0.split_off(dao_bytes_0.len() / 2);
    //    bot_bytes_2.extend(dao_bytes_0);

    //    let mut cc = NodeErrorDecoder::new();
    //    let result = cc.try_decode_with_new_bytes(&bot_bytes_0);
    //    if let Ok(DecodingResult::Incomplete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 0);
    //        assert!(cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }

    //    let result = cc.try_decode_with_new_bytes(&bot_bytes_1);
    //    if let Ok(DecodingResult::Incomplete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 0);
    //        assert!(cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }

    //    let result = cc.try_decode_with_new_bytes(&bot_bytes_2);
    //    if let Ok(DecodingResult::Incomplete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 1);
    //        assert!(cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }

    //    let result = cc.try_decode_with_new_bytes(&dao_bytes_1);
    //    if let Ok(DecodingResult::Complete(Message::RejectTx(errors))) = result {
    //        assert_eq!(errors.len(), 2);
    //        assert!(!cc.has_undecoded_bytes());
    //    } else {
    //        panic!("");
    //    }
    //}
}
