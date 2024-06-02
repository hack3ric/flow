mod bgp;
mod net;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
  // let _bgp = Bgp::new(12345).await?;
  // TODO: handle BGP events
  Ok(())
}
