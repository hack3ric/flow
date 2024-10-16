use crate::bgp;
use crate::bgp::route::Routes;
use crate::sync::RwLock;
use std::io;
use std::path::Path;
use std::rc::Rc;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;

pub struct IpcServer {
  listener: UnixListener,
  routes: Rc<RwLock<Routes>>,
}

impl IpcServer {
  pub fn new(addr: &Path, routes: Rc<RwLock<Routes>>) -> io::Result<Self> {
    Ok(Self { listener: UnixListener::bind(addr)?, routes })
  }

  pub async fn process(&mut self) -> bgp::Result<()> {
    let (mut stream, _addr) = self.listener.accept().await?;
    let routes = self.routes.read().await;
    stream.write_all(&bincode::serialize(&*routes)?).await?;
    Ok(())
  }
}
