#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]


use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    // maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;


use core::mem;
use network_types::{
    // eth::{EthHdr, EtherType},
    eth::{EthHdr, EtherType},
    // ip::Ipv4Hdr,
};
use network_types::tcp::TcpHdr;

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
    port == 5552
    // unsafe { BLOCKLIST.get(&address).is_some() }
}


fn try_ebpf_rust_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let tcp4Header: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + TcpHdr::LEN)? };
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
