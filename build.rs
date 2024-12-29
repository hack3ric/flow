use cfg_aliases::cfg_aliases;

fn main() {
  cfg_aliases! {
    linux: { target_os = "linux" },
    freebsd: { target_os = "freebsd" },
    kernel_supported: { linux },
    rtnetlink_supported: { any(linux, freebsd) },
  }
}
