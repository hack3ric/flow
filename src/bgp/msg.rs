use std::borrow::Cow;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MSG_OPEN: u8 = 1;
pub const MSG_UPDATE: u8 = 2;
pub const MSG_NOTIFICATION: u8 = 3;
pub const MSG_KEEPALIVE: u8 = 4;

pub const OPT_PARAM_CAP: u8 = 2;

pub const CAP_4B_ASN: u8 = 65;

pub const AS_TRANS: u16 = 23456;

pub enum Message<'a> {
  Open(OpenMessage<'a>),
  Keepalive,
}

impl Message<'_> {
  pub fn serialize(&self, buf: &mut Vec<u8>) {
    let start_pos = buf.len();
    buf.extend([u8::MAX; 16]); // marker
    buf.extend([0; 2]); // reserved for length

    match self {
      Message::Open(msg) => {
        assert!(msg.enable_4b_asn || msg.my_as <= u16::MAX.into());
        assert!(msg.my_as != AS_TRANS.into());

        buf.extend([1, 4]); // message type, BGP version
        buf.extend(u16::to_be_bytes(msg.my_as.try_into().unwrap_or(AS_TRANS))); // my AS (2b)
        buf.extend(u16::to_be_bytes(msg.hold_time));
        buf.extend(u32::to_be_bytes(msg.bgp_id));

        let opt_params_len_pos = buf.len();
        buf.push(0); // reserved for optional parameters length

        if msg.enable_4b_asn {
          buf.extend([OPT_PARAM_CAP, 6, CAP_4B_ASN, 4]);
          buf.extend(u32::to_be_bytes(msg.my_as));
        }
        msg.other_caps.iter().for_each(|(t, v)| {
          let l = u8::try_from(v.len() + 2).expect("opt_param_len should fit in u8");
          buf.extend([OPT_PARAM_CAP, l, *t, l - 2]);
          buf.extend(&**v);
        });
        msg.other_opt_params.iter().for_each(|(t, v)| {
          let l = u8::try_from(v.len()).expect("opt_param_len should fit in u8");
          buf.extend([*t, l]);
          buf.extend(&**v);
        });

        let opt_params_len = buf.len() - opt_params_len_pos - 1;
        buf[opt_params_len_pos] = opt_params_len.try_into().expect("opt_params_len should fit in u8");
      }
      Message::Keepalive => {}
    }

    let total_len = u16::try_from(buf.len() - start_pos).expect("total_len should fit in u16");
    buf[start_pos..start_pos + 2].copy_from_slice(&total_len.to_be_bytes())
  }

  pub async fn send<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
    let mut buf = Vec::new();
    self.serialize(&mut buf);
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
  }

  pub async fn recv<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
    let mut header = [0; 19];
    reader.read_exact(&mut header).await?;
    if header[0..16] != [u8::MAX; 16] {
      return Err(io::Error::other("invalid BGP marker"));
    }
    let len = u16::from_be_bytes(header[16..18].try_into().unwrap()) - 19;
    let msg_type = header[18];

    if len == 0 {
      return if msg_type == MSG_KEEPALIVE {
        Ok(Self::Keepalive)
      } else {
        Err(io::Error::other("invalid message with zero-length payload"))
      };
    }

    let mut buf = vec![0; len.into()];
    reader.read_exact(&mut buf).await?;

    match msg_type {
      MSG_OPEN => {
        let mut ptr = &*buf;
        if ptr.read_u8().await? != 4 {
          return Err(io::Error::other("invalid BGP version"));
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
                return Err(io::Error::other("capability length mismatch"));
              }
              match cap_type {
                CAP_4B_ASN => {
                  if cap_len != 4 {
                    return Err(io::Error::other("capability length mismatch"));
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
      MSG_KEEPALIVE => Err(io::Error::other("invalid keepalive message with payload")),
      _ => Err(io::Error::other("invalid message type")),
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

pub struct NotificationMessage {}
