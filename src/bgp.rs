use pin_project::pin_project;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{tcp, TcpListener, TcpStream};
use tokio::select;
use tokio::task::{JoinError, JoinHandle};
use tokio_util::sync::{CancellationToken, DropGuard};
use futures::stream::FuturesUnordered;

#[derive(Debug)]
pub struct Bgp {
  conns: HashMap<IpAddr, Conn>,
  listener: TcpListener,
  recv: FuturesUnordered<ConnRecvHandle>,
}

impl Bgp {
  pub async fn new() -> io::Result<Self> {
    Ok(Self {
      conns: HashMap::new(),
      listener: TcpListener::bind("127.0.0.1:179").await?,
      recv: FuturesUnordered::new(),
    })
  }
}

#[derive(Debug)]
struct Conn {
  state: State,
}

impl Conn {
  async fn accept(my_asn: u32, bgp_id: u32, stream: TcpStream) -> io::Result<(Self, ConnRecvHandle)> {
    let msg = OpenMsg {
      version: 4,
      my_asn: my_asn.try_into().expect("4b ASN to be implemented"),
      hold_time: 4 * 60,
      bgp_id,
      params: Vec::new(),
    };
    let (rx, mut tx) = stream.into_split();
    msg.send(&mut tx).await?;

    let ct = CancellationToken::new();
    let conn = Conn {
      state: State::OpenSent(tx, ct.clone().drop_guard()),
    };
    let handle = ConnRecvHandle::new(rx, ct);
    Ok((conn, handle))
  }
}

#[pin_project]
struct ConnRecvHandle {
  #[pin]
  inner: JoinHandle<Option<((), tcp::OwnedReadHalf)>>,
  guard: Option<DropGuard>,
}

impl ConnRecvHandle {
  fn new(rx: tcp::OwnedReadHalf, ct: CancellationToken) -> Self {
    Self {
      inner: tokio::spawn(handle_recv(rx, ct.clone())),
      guard: Some(ct.drop_guard()),
    }
  }
}

impl Future for ConnRecvHandle {
  type Output = Result<Option<((), tcp::OwnedReadHalf, CancellationToken)>, JoinError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.project();
    let guard = this.guard.take().expect("ConnRecvHandle polled after completion");
    (this.inner)
      .poll(cx)
      .map_ok(|ret| ret.map(|(data, rx)| (data, rx, guard.disarm())))
  }
}

async fn handle_recv(rx: tcp::OwnedReadHalf, ct: CancellationToken) -> Option<((), tcp::OwnedReadHalf)> {
  select! {
    // TODO: read info from rx
    _ = ct.cancelled() => None,
  }
}

#[derive(Debug)]
pub enum State {
  Idle,
  Connect(tcp::OwnedWriteHalf, DropGuard),
  Active,
  OpenSent(tcp::OwnedWriteHalf, DropGuard),
  OpenConfirm(tcp::OwnedWriteHalf, DropGuard),
  Established(tcp::OwnedWriteHalf, DropGuard),
}

impl State {
  pub const fn writer(&self) -> Option<&tcp::OwnedWriteHalf> {
    use State::*;
    match self {
      Connect(x, _) | OpenSent(x, _) | OpenConfirm(x, _) | Established(x, _) => Some(x),
      _ => None,
    }
  }

  pub fn writer_mut(&mut self) -> Option<&mut tcp::OwnedWriteHalf> {
    use State::*;
    match self {
      Connect(x, _) | OpenSent(x, _) | OpenConfirm(x, _) | Established(x, _) => Some(x),
      _ => None,
    }
  }
}

// TODO: use enum
pub trait Msg {
  fn serialize(&self, buf: &mut Vec<u8>);

  async fn send<W: AsyncWrite + Unpin>(&self, stream: &mut W) -> io::Result<()> {
    let mut buf = vec![u8::MAX; 16];
    buf.extend([0; 2]); // reserved for length
    self.serialize(&mut buf);
    let total_len = u16::try_from(buf.len()).expect("total_len <= u16::MAX").to_be_bytes();
    buf[16] = total_len[0];
    buf[17] = total_len[1];
    stream.write_all(&buf).await?;
    stream.flush().await?;
    println!("flushed");
    Ok(())
  }
}

#[derive(Debug, Clone)]
pub struct OpenMsg {
  version: u8,
  my_asn: u16,
  hold_time: u16,
  bgp_id: u32,
  params: Vec<OpenParam>,
}

impl Msg for OpenMsg {
  fn serialize(&self, buf: &mut Vec<u8>) {
    buf.push(1); // type
    buf.push(4); // BGP version
    buf.extend(self.my_asn.to_be_bytes());
    buf.extend(self.hold_time.to_be_bytes());
    buf.extend(self.bgp_id.to_be_bytes());
    let param_len_pos = buf.len();
    buf.push(0); // reserved for optional parameters length
    self.params.iter().for_each(|p| match p {
      OpenParam::Other(t, v) => {
        buf.push(*t);
        buf.push(v.len().try_into().expect("v.len() <= u8::MAX"));
        buf.extend(v);
      }
    });
    let param_len = buf.len() - param_len_pos - 1;
    buf[param_len_pos] = param_len.try_into().expect("param_len <= u8::MAX");
  }
}

#[derive(Debug, Clone)]
pub enum OpenParam {
  Other(u8, Vec<u8>),
}
