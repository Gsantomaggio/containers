#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]


use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;


use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use network_types::tcp::TcpHdr;

// RFC 791: IHL counts 32-bit words, not bytes.
const IPV4_WORD_LEN: usize = 4;

#[map] // (1)
static BLOCKLIST: HashMap<u16, u16> =
    HashMap::<u16, u16>::with_max_entries(1024, 0);


#[xdp]
pub fn ebpf_rust_firewall(ctx: XdpContext) -> u32 {
    match try_ebpf_rust_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}


// (2)
fn block_port(port: u16) -> bool {
    unsafe { BLOCKLIST.get(&port).is_some() }
}


fn try_ebpf_rust_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    if ihl < Ipv4Hdr::LEN / IPV4_WORD_LEN {
        return Err(());
    }
    let ipv4_header_len = ihl * IPV4_WORD_LEN;

    let tcp4Header: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + ipv4_header_len)? };
    let dest = u16::from_be(unsafe { (*tcp4Header).dest });

    // (3)
    let action = if block_port(dest) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };
    info!(&ctx, "ACTION: {}", action);


    Ok(action)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
