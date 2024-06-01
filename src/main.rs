use bgp::Bgp;

mod bgp;
mod net;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
  let _bgp = Bgp::new().await?;
  // TODO: handle BGP events
  Ok(())
}
