use crate::args::RunArgs;
use crate::bgp::route::Routes;
use crate::bgp::StateKind;
use crate::sync::RwLock;
use std::borrow::Cow;
use std::cell::Cell;
use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::path::Path;
use std::rc::Rc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

pub struct IpcServer<'a> {
  path: Cow<'a, Path>,
  listener: UnixListener,

  config: Rc<RunArgs>,
  state: Rc<Cell<StateKind>>,
  routes: Rc<RwLock<Routes>>,
}

impl<'a> IpcServer<'a> {
  pub fn new(
    path: &'a (impl AsRef<Path> + ?Sized + 'a),
    config: Rc<RunArgs>,
    state: Rc<Cell<StateKind>>,
    routes: Rc<RwLock<Routes>>,
  ) -> anyhow::Result<Self> {
    let path = Cow::Borrowed(path.as_ref());
    Ok(Self { listener: UnixListener::bind(&path)?, path, config, state, routes })
  }

  pub async fn process(&mut self) -> anyhow::Result<()> {
    let (mut stream, _addr) = self.listener.accept().await?;
    let routes = self.routes.read().await;
    stream.write_all(&postcard::to_stdvec_cobs(&*self.config)?).await?;
    stream.write_all(&postcard::to_stdvec_cobs(&self.state.get())?).await?;
    stream.write_all(&postcard::to_stdvec_cobs(&*routes)?).await?;
    Ok(())
  }
}

impl Drop for IpcServer<'_> {
  fn drop(&mut self) {
    let _ = std::fs::remove_file(&self.path);
  }
}

pub async fn get_state(path: impl AsRef<Path>) -> anyhow::Result<(RunArgs, StateKind, Routes)> {
  let mut stream = UnixStream::connect(path).await?;
  let mut buf = Vec::new();
  stream.read_to_end(&mut buf).await?;
  let (config, buf_ptr) = postcard::take_from_bytes_cobs(&mut buf)?;
  let (state, buf_ptr) = postcard::take_from_bytes_cobs(buf_ptr)?;
  let (routes, _) = postcard::take_from_bytes_cobs(buf_ptr)?;
  Ok((config, state, routes))
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
