use pallas_codec::minicbor::data::Tag;
use pallas_codec::minicbor::{decode, encode, Decode, Decoder, Encode, Encoder};
use tracing::trace;

use crate::miniprotocols::localtxsubmission::{EraTx, Message};

use super::cardano_node_errors::{ApplyTxError, OuterScope};

impl<Tx, Reject> Encode<()> for Message<Tx, Reject>
where
    Tx: Encode<()>,
    Reject: Encode<()>,
{
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut (),
    ) -> Result<(), encode::Error<W::Error>> {
        match self {
            Message::SubmitTx(tx) => {
                e.array(2)?.u16(0)?;
                e.encode(tx)?;
                Ok(())
            }
            Message::AcceptTx => {
                e.array(1)?.u16(1)?;
                Ok(())
            }
            Message::RejectTx(rejection) => {
                e.array(2)?.u16(2)?;
                e.encode(rejection)?;
                Ok(())
            }
            Message::Done => {
                e.array(1)?.u16(3)?;
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub enum DecodingResult<Entity> {
    Complete(Entity),
    Incomplete,
}

impl<Entity: Encode<()>> Encode<()> for DecodingResult<Entity> {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut (),
    ) -> Result<(), encode::Error<W::Error>> {
        match self {
            DecodingResult::Complete(entity) => entity.encode(e, _ctx),
            DecodingResult::Incomplete => unreachable!(),
        }
    }
}

/// An implementor of this trait is able to decode an entity from CBOR with bytes that are split
/// over multiple payloads.
pub trait DecodeCBORSplitPayload {
    /// Type of entity to decode
    type Entity;
    /// Attempt to decode entity given a new slice of bytes.
    fn try_decode_with_new_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<DecodingResult<Self::Entity>, decode::Error>;
}

/// Decodes Cardano node errors whose CBOR byte representation could be split over multiple
/// payloads.
pub struct NodeErrorDecoder {
    /// When decoding the error responses of the node, we use a stack to track the location of the
    /// decoding relative to an outer scope (most often a definite array). We need it because if we
    /// come across an error that we cannot handle, we must still consume all the CBOR bytes that
    /// represent this error.
    pub context_stack: Vec<OuterScope>,
    /// Response bytes from the cardano node. Note that there are payload limits and so the bytes
    /// may be truncated.
    pub response_bytes: Vec<u8>,
}

impl NodeErrorDecoder {
    pub fn new() -> Self {
        Self {
            context_stack: vec![],
            response_bytes: vec![],
        }
    }
}

impl Default for NodeErrorDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DecodeCBORSplitPayload for NodeErrorDecoder {
    type Entity = Message<EraTx, ApplyTxError>;

    fn try_decode_with_new_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<DecodingResult<Self::Entity>, decode::Error> {
        self.response_bytes.extend_from_slice(bytes);

        let mut d = Decoder::new(&self.response_bytes);
        let mut probe = d.probe();
        if probe.array().is_err() {
            // If we don't have any unprocessed bytes the first element should be an array
            self.response_bytes.clear();
            return Err(decode::Error::message("Expecting an array"));
        }
        let label = probe.u16()?;
        let res = match label {
            0 => {
                d.array()?;
                d.u16()?;
                let tx = d.decode()?;
                Ok(DecodingResult::Complete(Message::SubmitTx(tx)))
            }
            1 => Ok(DecodingResult::Complete(Message::AcceptTx)),
            2 => {
                let bytes = self.response_bytes.clone();
                let mut decoder = Decoder::new(&bytes);

                match ApplyTxError::decode(&mut decoder, self) {
                    Ok(tx_err) => Ok(DecodingResult::Complete(Message::RejectTx(tx_err))),
                    Err(_) => Ok(DecodingResult::Incomplete),
                }
            }
            3 => Ok(DecodingResult::Complete(Message::Done)),
            _ => Err(decode::Error::message("can't decode Message")),
        };

        // Clear `response_bytes` buffer on a successful complete decoding of error, or a successful
        // decoding of any other message.
        if res.is_ok() {
            match res {
                Ok(DecodingResult::Incomplete) | Err(_) => (),
                Ok(_) => {
                    self.response_bytes.clear();
                }
            }
        }
        res
    }
}

impl<'b, C> Decode<'b, C> for DecodingResult<Message<EraTx, ApplyTxError>>
where
    C: DecodeCBORSplitPayload<Entity = Message<EraTx, ApplyTxError>>,
{
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, decode::Error> {
        ctx.try_decode_with_new_bytes(d.input())
    }
}

impl<'b> Decode<'b, ()> for EraTx {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut ()) -> Result<Self, decode::Error> {
        d.array()?;
        let era = d.u16()?;
        let tag = d.tag()?;
        if tag != Tag::Cbor {
            return Err(decode::Error::message("Expected encoded CBOR data item"));
        }
        Ok(EraTx(era, d.bytes()?.to_vec()))
    }
}

impl Encode<()> for EraTx {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut (),
    ) -> Result<(), encode::Error<W::Error>> {
        e.array(2)?;
        e.u16(self.0)?;
        e.tag(Tag::Cbor)?;
        e.bytes(&self.1)?;
        Ok(())
    }
}
