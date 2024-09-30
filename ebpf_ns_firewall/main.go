package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
)

func main() {
	args := os.Args
	networkInterface := "lo"
	port := uint64(5552)
	slogOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, slogOpts))

	if len(args) != 3 {
		log.Info("Usage: <network interface> <port>, but %s, %d will used", networkInterface, port)
	} else {
		networkInterface = args[1]
		port, _ = strconv.ParseUint(args[2], 10, 64)
	}

	const XdpTcpFirewall = "./kernel_module/xdp_tcp_firewall.o"
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error("failed to remove memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec(XdpTcpFirewall)
	if err != nil {
		log.Error("Error loading eBPF object file", "file", XdpTcpFirewall, "error", err)
		return
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Error("Error creating eBPF collection", "error", err)
		return
	}
	log.Info("eBPF object file loaded. ", "file", XdpTcpFirewall)

	ifce, err := net.InterfaceByName(networkInterface)
	if err != nil {
		log.Error("failed to get interface: %v", err)
	}

	log.Info("interfaces found", "interface", ifce.Name, "index", ifce.Index)

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["xdp_tcp_firewall"],
		Interface: ifce.Index,
	})
	if err != nil {
		log.Error("error", "failed to attach XDP program", "err", err)
	}

	//l2, err2 := link.Kprobe("tcp_v4_connect", coll.Programs["kprobe__tcp_v4_connect"])
	//l2, err2 := link.Kprobe("tcp_connect", coll.Programs["kprobe__tcp_connect"], nil)
	//if err != nil {
	//	return
	//}
	//if err2 != nil {
	//	log.Error("error", "failed to attach XDP program", "err", err2)
	//}

	//var value2 uint64
	//value2 = 5552

	if err := coll.Maps["port_filter"].Put(uint32(0), &port); err != nil {
		log.Error("failed to lookup map: %v", err)
	}

	log.Info("XDP firewall attached: ", "interface", ifce.Name, "port", port)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
	l.Close()
	//l2.Close()
	log.Info("XDP firewall detached: ", "interface", ifce.Name)

}
