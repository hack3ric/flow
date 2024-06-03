use super::error::BGPError;
use std::borrow::Cow;
use std::io;
use strum::EnumDiscriminants;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use HeaderError::*;
use OpenError::*;
use UpdateError::*;

pub const MSG_OPEN: u8 = 1;
pub const MSG_UPDATE: u8 = 2;
pub const MSG_NOTIFICATION: u8 = 3;
pub const MSG_KEEPALIVE: u8 = 4;

pub const OPT_PARAM_CAP: u8 = 2;

pub const CAP_4B_ASN: u8 = 65;

pub const AS_TRANS: u16 = 23456;

#[derive(Debug, Clone, EnumDiscriminants)]
#[repr(u8)]
pub enum Message<'a> {
  Open(OpenMessage<'a>) = 1,
  // TODO: UPDATE
  Notification(Notification<'a>) = 3,
  Keepalive = 4,
}

impl Message<'_> {
  pub fn kind(&self) -> MessageDiscriminants {
    self.into()
  }
}

impl Message<'static> {
  pub async fn recv_raw<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, BGPError> {
    let mut header = [0; 19];
    reader.read_exact(&mut header).await?;
    if header[0..16] != [u8::MAX; 16] {
      return Err(Notification::Header(HeaderError::ConnNotSynced).into());
    }
    let len = u16::from_be_bytes(header[16..18].try_into().unwrap()) - 19;
    let msg_type = header[18];

    if len == 0 {
      return if msg_type == MSG_KEEPALIVE {
        Ok(Self::Keepalive)
      } else {
        Err(Notification::Header(BadLen(len)).into())
      };
    }

    let mut buf = vec![0; len.into()];
    reader.read_exact(&mut buf).await?;
    let mut ptr = &*buf;

    match msg_type {
      MSG_OPEN => {
        if ptr.read_u8().await? != 4 {
          return Err(Notification::Open(UnsupportedVersion(4)).into());
        }
        let mut msg = OpenMessage::default();
        msg.my_as = ptr.read_u16().await?.into();
        msg.hold_time = ptr.read_u16().await?;
        msg.bgp_id = ptr.read_u32().await?;

        while let Ok(x) = ptr.read_u16().await {
          let [param_type, param_len] = x.to_be_bytes();
          match param_type {
            OPT_PARAM_CAP => {
              let [cap_type, cap_len] = ptr.read_u16().await?.to_be_bytes();
              if cap_len != param_len - 2 {
                return Err(Notification::Open(Unspecific).into());
              }
              match cap_type {
                CAP_4B_ASN => {
                  if cap_len != 4 {
                    return Err(Notification::Open(Unspecific).into());
                  }
                  msg.my_as = ptr.read_u32().await?;
                  msg.enable_4b_asn = true;
                }
                _ => {
                  let mut cap_buf = vec![0; cap_len.into()];
                  ptr.read_exact(&mut cap_buf).await?;
                  msg.other_caps.push((cap_type, cap_buf.into()));
                }
              }
            }
            _ => {
              let mut param_buf = vec![0; param_len.into()];
              ptr.read_exact(&mut param_buf).await?;
              msg.other_opt_params.push((param_type, param_buf.into()));
            }
          }
        }
        Ok(Message::Open(msg))
      }

      MSG_NOTIFICATION => {
        let code = ptr.read_u8().await?;
        let subcode = ptr.read_u8().await?;
        let notification = match code {
          N_HEADER => {
            let subcode_p = match subcode {
              NH_CONN_NOT_SYNCED => Some(ConnNotSynced),
              NH_BAD_LEN => Some(BadLen(ptr.read_u16().await?)),
              NH_BAD_TYPE => Some(BadType(ptr.read_u8().await?)),
              _ => None,
            };
            subcode_p
              .map(|x| Notification::Header(x))
              .unwrap_or_else(|| Notification::Unknown(code, subcode, ptr.to_vec().into()))
          }
          N_OPEN => {
            let subcode_p = match subcode {
              NO_UNSPECIFIC => Some(OpenError::Unspecific),
              NO_UNSUPPORTED_VERSION => Some(UnsupportedVersion(ptr.read_u16().await?)),
              NO_BAD_PEER_AS => Some(BadPeerAS),
              NO_BAD_BGP_ID => Some(BadBGPID),
              NO_UNSUPPORTED_OPT_PARAM => Some(UnsupportedOptParam),
              NO_UNACCEPTABLE_HOLD_TIME => Some(UnacceptableHoldTime),
              _ => None,
            };
            subcode_p
              .map(|x| Notification::Open(x))
              .unwrap_or_else(|| Notification::Unknown(code, subcode, ptr.to_vec().into()))
          }
          N_UPDATE => {
            let subcode_p = match subcode {
              NU_MALFORMED_ATTR_LIST => Some(MalformedAttrList),
              NU_MISSING_WELL_KNOWN_ATTR => Some(MissingWellKnownAttr(ptr.read_u8().await?)),
              NU_INVALID_NETWORK => Some(InvalidNetwork),
              NU_MALFORMED_AS_PATH => Some(MalformedASPath),
              NU_UNRECOGNIZED_WELL_KNOWN_ATTR
              | NU_ATTR_FLAGS
              | NU_ATTR_LEN
              | NU_INVALID_ORIGIN
              | NU_INVALID_NEXT_HOP
              | NU_OPT_ATTR => {
                let discrim_fn = match subcode {
                  NU_UNRECOGNIZED_WELL_KNOWN_ATTR => UpdateError::UnrecognizedWellKnownAttr,
                  NU_ATTR_FLAGS => UpdateError::AttrFlags,
                  NU_ATTR_LEN => UpdateError::AttrLen,
                  NU_INVALID_ORIGIN => UpdateError::InvalidOrigin,
                  NU_INVALID_NEXT_HOP => UpdateError::InvalidNextHop,
                  NU_OPT_ATTR => UpdateError::OptAttr,
                  _ => unreachable!(),
                };
                Some(discrim_fn(
                  ptr.read_u8().await?,
                  ptr.read_u8().await?,
                  ptr.to_vec().into(),
                ))
              }
              _ => None,
            };
            subcode_p
              .map(|x| Notification::Update(x))
              .unwrap_or_else(|| Notification::Unknown(code, subcode, ptr.to_vec().into()))
          }
          N_HOLD_TIMER_EXPIRED => Notification::HoldTimerExpired,
          N_FSM => Notification::FSM,
          N_CEASE => Notification::Cease,
          _ => Notification::Unknown(code, subcode, ptr.to_vec().into()),
        };
        Ok(Message::Notification(notification))
      }

      MSG_KEEPALIVE => Err(Notification::Header(BadLen(len)).into()),
      _ => Err(Notification::Header(BadType(msg_type)).into()),
    }
  }

  pub async fn recv<S: AsyncWrite + AsyncRead + Unpin>(socket: &mut S) -> Result<Self, BGPError> {
    match Message::recv_raw(socket).await {
      Ok(Message::Notification(n)) => Err(n.into()),
      Err(BGPError::Notification(n)) => return n.send_and_return(socket).await.map(|_| unreachable!()),
      other => other,
    }
  }
}

#[derive(Debug, Clone, Default)]
pub struct OpenMessage<'a> {
  pub my_as: u32, // maybe 4b
  pub hold_time: u16,
  pub bgp_id: u32,

  pub enable_4b_asn: bool,

  pub other_caps: Vec<(u8, Cow<'a, [u8]>)>,
  pub other_opt_params: Vec<(u8, Cow<'a, [u8]>)>,
}

pub const N_HEADER: u8 = 1;
pub const N_OPEN: u8 = 2;
pub const N_UPDATE: u8 = 3;
pub const N_HOLD_TIMER_EXPIRED: u8 = 4;
pub const N_FSM: u8 = 5;
pub const N_CEASE: u8 = 6;

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[repr(u8)]
pub enum Notification<'a> {
  #[error("message header error: {0}")]
  Header(#[from] HeaderError) = N_HEADER,

  #[error("OPEN message error: {0}")]
  Open(#[from] OpenError) = N_OPEN,

  #[error("UPDATE message error: {0}")]
  Update(UpdateError<'a>) = N_UPDATE,

  #[error("hold timer expired")]
  HoldTimerExpired = N_HOLD_TIMER_EXPIRED,

  #[error("finite state machine error")]
  FSM = N_FSM,

  #[error("ceasing operation")]
  Cease = N_CEASE,

  #[error("unknown BGP error: ({0}, {1}, {2:02x?})")]
  Unknown(u8, u8, Cow<'a, [u8]>),
}

impl Notification<'_> {
  pub fn code(&self) -> u8 {
    match self {
      Self::Unknown(code, ..) => *code,
      _ => NotificationDiscriminants::from(self) as u8,
    }
  }

  pub fn subcode(&self) -> u8 {
    match self {
      Self::Header(x) => HeaderErrorDiscriminants::from(x) as u8,
      Self::Open(x) => OpenErrorDiscriminants::from(x) as u8,
      Self::Update(x) => UpdateErrorDiscriminants::from(x) as u8,
      Self::HoldTimerExpired | Self::FSM | Self::Cease => 0,
      Self::Unknown(_, subcode, _) => *subcode,
    }
  }

  pub fn serialize_data(&self, buf: &mut Vec<u8>) {
    match self {
      Self::Header(BadLen(x)) | Self::Open(UnsupportedVersion(x)) => buf.extend(u16::to_be_bytes(*x)),
      Self::Header(BadType(x)) | Self::Update(MissingWellKnownAttr(x)) => buf.push(*x),
      Self::Update(UnrecognizedWellKnownAttr(t, l, v))
      | Self::Update(AttrFlags(t, l, v))
      | Self::Update(AttrLen(t, l, v))
      | Self::Update(InvalidOrigin(t, l, v))
      | Self::Update(InvalidNextHop(t, l, v))
      | Self::Update(OptAttr(t, l, v)) => {
        buf.extend([t, l]);
        buf.extend(&v[..]);
      }
      Self::Unknown(_, _, data) => buf.extend(&data[..]),
      _ => {}
    }
  }
}

impl<'a> From<UpdateError<'a>> for Notification<'a> {
  fn from(value: UpdateError<'a>) -> Self {
    Self::Update(value)
  }
}

pub trait SendAndReturn {
  async fn send_and_return<W: AsyncWrite + Unpin>(self, writer: &mut W) -> Result<(), BGPError>;
}

impl<T: Into<Notification<'static>>> SendAndReturn for T {
  async fn send_and_return<W: AsyncWrite + Unpin>(self, writer: &mut W) -> Result<(), BGPError> {
    let n = self.into();
    n.send(writer).await?;
    Err(n.into())
  }
}

pub const NH_CONN_NOT_SYNCED: u8 = 1;
pub const NH_BAD_LEN: u8 = 2;
pub const NH_BAD_TYPE: u8 = 3;

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[repr(u8)]
pub enum HeaderError {
  #[error("connection not synchronised")]
  ConnNotSynced = NH_CONN_NOT_SYNCED,

  #[error("bad message length: {0}")]
  BadLen(u16) = NH_BAD_LEN,

  #[error("bad message type: {0}")]
  BadType(u8) = NH_BAD_TYPE,
}

pub const NO_UNSPECIFIC: u8 = 0;
pub const NO_UNSUPPORTED_VERSION: u8 = 1;
pub const NO_BAD_PEER_AS: u8 = 2;
pub const NO_BAD_BGP_ID: u8 = 3;
pub const NO_UNSUPPORTED_OPT_PARAM: u8 = 4;
// value 5 is deprecated
pub const NO_UNACCEPTABLE_HOLD_TIME: u8 = 6;

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[repr(u8)]
pub enum OpenError {
  #[error("malformed optional parameter")]
  Unspecific = NO_UNSPECIFIC,

  #[error("unsupported version number; we support at least/at most version {0}")]
  UnsupportedVersion(u16) = NO_UNSUPPORTED_VERSION,

  #[error("bad peer AS")]
  BadPeerAS = NO_BAD_PEER_AS,

  #[error("bad BGP ID")]
  BadBGPID = NO_BAD_BGP_ID,

  #[error("unsupported optional parameters")]
  UnsupportedOptParam = NO_UNSUPPORTED_OPT_PARAM,

  #[error("unacceptable hold time")]
  UnacceptableHoldTime = NO_UNACCEPTABLE_HOLD_TIME,
}

pub const NU_MALFORMED_ATTR_LIST: u8 = 1;
pub const NU_UNRECOGNIZED_WELL_KNOWN_ATTR: u8 = 2;
pub const NU_MISSING_WELL_KNOWN_ATTR: u8 = 3;
pub const NU_ATTR_FLAGS: u8 = 4;
pub const NU_ATTR_LEN: u8 = 5;
pub const NU_INVALID_ORIGIN: u8 = 6;
// value 7 is deprecated
pub const NU_INVALID_NEXT_HOP: u8 = 8;
pub const NU_OPT_ATTR: u8 = 9;
pub const NU_INVALID_NETWORK: u8 = 10;
pub const NU_MALFORMED_AS_PATH: u8 = 11;

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[repr(u8)]
pub enum UpdateError<'a> {
  #[error("malformed attribute list")]
  MalformedAttrList = NU_MALFORMED_ATTR_LIST,

  #[error("unrecognized well-known attribute ({0}, {1}, {2:02x?})")]
  UnrecognizedWellKnownAttr(u8, u8, Cow<'a, [u8]>) = NU_UNRECOGNIZED_WELL_KNOWN_ATTR,

  #[error("missing well-known attribute type {0}")]
  MissingWellKnownAttr(u8) = NU_MISSING_WELL_KNOWN_ATTR,

  #[error("attribute flags error: ({0}, {1}, {2:02x?})")]
  AttrFlags(u8, u8, Cow<'a, [u8]>) = NU_ATTR_FLAGS,

  #[error("attribute length error: ({0}, {1}, {2:02x?})")]
  AttrLen(u8, u8, Cow<'a, [u8]>) = NU_ATTR_LEN,

  #[error("invalid ORIGIN attribute: ({0}, {1}, {2:02x?})")]
  InvalidOrigin(u8, u8, Cow<'a, [u8]>) = NU_INVALID_ORIGIN,

  #[error("invalid NEXT_HOP attribute: ({0}, {1}, {2:02x?})")]
  InvalidNextHop(u8, u8, Cow<'a, [u8]>) = NU_INVALID_NEXT_HOP,

  #[error("optional attribute error: ({0}, {1}, {2:02x?})")]
  OptAttr(u8, u8, Cow<'a, [u8]>) = NU_OPT_ATTR,

  #[error("invalid network field")]
  InvalidNetwork = NU_INVALID_NETWORK,

  #[error("malformed AS_PATH")]
  MalformedASPath = NU_MALFORMED_AS_PATH,
}

pub trait MessageSend {
  fn serialize_data(&self, buf: &mut Vec<u8>);

  fn serialize(&self, buf: &mut Vec<u8>) {
    let start_pos = buf.len();
    buf.extend([u8::MAX; 16]); // marker
    buf.extend([0; 2]); // reserved for length
    self.serialize_data(buf);
    let total_len = u16::try_from(buf.len() - start_pos).expect("total_len should fit in u16");
    buf[start_pos..start_pos + 2].copy_from_slice(&total_len.to_be_bytes());
  }

  async fn send<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
    let mut buf = Vec::new();
    self.serialize(&mut buf);
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
  }
}

impl MessageSend for Message<'_> {
  fn serialize_data(&self, buf: &mut Vec<u8>) {
    match self {
      Self::Open(x) => x.serialize_data(buf),
      Self::Notification(x) => x.serialize_data(buf),
      Self::Keepalive => {}
    }
  }
}

impl MessageSend for OpenMessage<'_> {
  fn serialize_data(&self, buf: &mut Vec<u8>) {
    assert!(self.enable_4b_asn || self.my_as <= u16::MAX.into());
    assert!(self.my_as != AS_TRANS.into());

    buf.extend([MSG_OPEN, 4]); // message type, BGP version
    buf.extend(u16::to_be_bytes(self.my_as.try_into().unwrap_or(AS_TRANS))); // my AS (2b)
    buf.extend(u16::to_be_bytes(self.hold_time));
    buf.extend(u32::to_be_bytes(self.bgp_id));

    let opt_params_len_pos = buf.len();
    buf.push(0); // reserved for optional parameters length

    if self.enable_4b_asn {
      buf.extend([OPT_PARAM_CAP, 6, CAP_4B_ASN, 4]);
      buf.extend(u32::to_be_bytes(self.my_as));
    }
    self.other_caps.iter().for_each(|(kind, value)| {
      let len = u8::try_from(value.len() + 2).expect("opt_param_len should fit in u8");
      buf.extend([OPT_PARAM_CAP, len, *kind, len - 2]);
      buf.extend(&**value);
    });
    self.other_opt_params.iter().for_each(|(kind, value)| {
      let len = u8::try_from(value.len()).expect("opt_param_len should fit in u8");
      buf.extend([*kind, len]);
      buf.extend(&**value);
    });

    let opt_params_len = buf.len() - opt_params_len_pos - 1;
    buf[opt_params_len_pos] = opt_params_len.try_into().expect("opt_params_len should fit in u8");
  }
}

impl MessageSend for Notification<'_> {
  fn serialize_data(&self, buf: &mut Vec<u8>) {
    buf.extend([MSG_NOTIFICATION, self.code(), self.subcode()]);
    self.serialize_data(buf);
  }
}
