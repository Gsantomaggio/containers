package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log/slog"
	"net"
	"os"
	"os/signal"
)

func main() {
	args := os.Args
	networkInterface := "lo"
	slogOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, slogOpts))

	if len(args) != 2 {
		log.Info("Usage: %s <network interface>", args[0])
		return
	} else {
		networkInterface = args[1]
	}

	const XdpTcpObj = "./kernel_module/xdp_tcp.o"
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error("failed to remove memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec(XdpTcpObj)
	if err != nil {
		log.Error("Error loading eBPF object file", "file", XdpTcpObj, "error", err)
		return
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Error("Error creating eBPF collection", "error", err)
		return
	}
	log.Info("eBPF object file loaded. ", "file", XdpTcpObj)

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

	var value2 uint64
	value2 = 5552

	if err := coll.Maps["port_filter"].Put(uint32(0), &value2); err != nil {
		log.Error("failed to lookup map: %v", err)
	}

	log.Info("XDP firewall attached: ", "interface", ifce.Name, "port", value2)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
	l.Close()
	log.Info("XDP firewall detached: ", "interface", ifce.Name)

}
