use anyhow::Context as _;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "5552")]
    port: u16,
    #[clap(short, long, default_value = "ens160")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    const PREFIX_USERSPACE: &str = "[USER SPACE]: ";
    let opt = Opt::parse();
    let Opt { iface, port: block_port } = opt;
    println!("{} starting ebpf rust firewall to the interface: {} on port: {}", PREFIX_USERSPACE, iface, block_port);

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf_rust_firewall"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = ebpf.program_mut("ebpf_rust_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    println!("{} module ebpf loaded and attached to {}", PREFIX_USERSPACE, iface);

    let mut blocklist: HashMap<_, u16, u16> =
        HashMap::try_from(ebpf.map_mut("BLOCKLIST").unwrap())?;

    blocklist.insert(block_port, 0, 0)?;
    println!("{} added {} to the interface {}", PREFIX_USERSPACE, block_port, iface);

    let ctrl_c = signal::ctrl_c();
    println!("{} Firewall started Ctrl-C... to Stop", PREFIX_USERSPACE);
    ctrl_c.await?;
    println!("{} exiting...", PREFIX_USERSPACE);

    Ok(())
}
