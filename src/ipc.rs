use crate::args::RunArgs;
use crate::bgp::route::Routes;
use crate::bgp::{Session, StateView};
use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener, UnixStream};

pub struct IpcServer {
  path: PathBuf,
  listener: UnixListener,
}

impl IpcServer {
  pub fn new(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
    let path = path.into();
    Ok(Self { listener: UnixListener::bind(&path)?, path })
  }

  pub async fn accept(&mut self) -> anyhow::Result<UnixStream> {
    let (stream, _addr) = self.listener.accept().await?;
    Ok(stream)
  }
}

impl Drop for IpcServer {
  fn drop(&mut self) {
    let _ = std::fs::remove_file(&self.path);
  }
}

impl Session<BufReader<TcpStream>> {
  pub async fn write_states(&self, writer: &mut (impl AsyncWrite + Unpin)) -> anyhow::Result<()> {
    writer.write_all(&postcard::to_allocvec_cobs(self.config())?).await?;
    writer.write_all(&postcard::to_allocvec_cobs(&self.state().view())?).await?;
    writer.write_all(&postcard::to_allocvec_cobs(self.routes())?).await?;
    Ok(())
  }
}

pub async fn get_states(path: impl AsRef<Path>, buf: &mut Vec<u8>) -> anyhow::Result<(RunArgs, StateView, Routes)> {
  let mut stream = UnixStream::connect(path).await?;
  stream.read_to_end(buf).await?;
  let (config, buf) = postcard::take_from_bytes_cobs(buf)?;
  let (view, buf) = postcard::take_from_bytes_cobs(buf)?;
  let (routes, _) = postcard::take_from_bytes_cobs(buf)?;
  Ok((config, view, routes))
}

/// Network namespace-aware socket path.
#[cfg(target_os = "linux")]
pub fn get_sock_path(dir: &str) -> io::Result<String> {
  let stat = unsafe {
    let netns_path = CStr::from_bytes_with_nul_unchecked(b"/proc/self/ns/net\0");
    let mut buf = MaybeUninit::uninit();
    if libc::stat(netns_path.as_ptr(), buf.as_mut_ptr()) < 0 {
      return Err(io::Error::last_os_error());
    }
    buf.assume_init()
  };
  Ok(format!("{dir}/{:x}.sock", stat.st_ino))
}

#[cfg(not(target_os = "linux"))]
pub fn get_sock_path(dir: &str) -> io::Result<String> {
  Ok(format!("{dir}/flow.sock"))
}
