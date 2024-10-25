use crate::bgp::route::{Routes, RoutesDisplay};
use crate::sync::RwLock;
use std::borrow::Cow;
use std::path::Path;
use std::rc::Rc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

pub struct IpcServer<'a> {
  path: Cow<'a, Path>,
  listener: UnixListener,
  routes: Rc<RwLock<Routes>>,
}

impl<'a> IpcServer<'a> {
  pub fn new(path: &'a (impl AsRef<Path> + ?Sized + 'a), routes: Rc<RwLock<Routes>>) -> anyhow::Result<Self> {
    let path = Cow::Borrowed(path.as_ref());
    Ok(Self { listener: UnixListener::bind(&path)?, path, routes })
  }

  pub async fn process(&mut self) -> anyhow::Result<()> {
    let (mut stream, _addr) = self.listener.accept().await?;
    let routes = self.routes.read().await;
    stream.write_all(&bincode::serialize(&*routes)?).await?;
    Ok(())
  }
}

impl Drop for IpcServer<'_> {
  fn drop(&mut self) {
    let _ = std::fs::remove_file(&self.path);
  }
}

pub async fn get_routes(path: impl AsRef<Path>) -> anyhow::Result<RoutesDisplay> {
  let mut stream = UnixStream::connect(path).await?;
  let mut buf = Vec::new();
  stream.read_to_end(&mut buf).await?;
  Ok(bincode::deserialize(&buf)?)
}
