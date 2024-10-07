// Filename: main.go
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

//struct sys_enter_openat_args {
//    unsigned long long unused;
//    long syscall_nr;
//    long dfd;
//    const char *filename;
//    long flags;
//    long mode;
//};

//type sys_enter_openat_args struct {
//	Unused    uint64
//	SyscallNr int64
//	Dfd       int64
//	Filename  *byte
//	Flags     int64
//	Mode      int64
//}

// Struct for capturing the data sent from kernel space
type dataT struct {
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
}

func main() {
	// Load pre-compiled eBPF program

	objs := "./kernel_module/trace_sys_enter_openat.o"
	slogOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	llog := slog.New(slog.NewTextHandler(os.Stdout, slogOpts))
	if err := rlimit.RemoveMemlock(); err != nil {
		llog.Error("Failed to remove memlock limit", "error", err)
	}

	spec, err := ebpf.LoadCollection(objs)
	if err != nil {
		llog.Error("Error loading eBPF object file", "file", objs, "error", err)
		return
	}

	events := spec.Maps["events"]
	llog.Info("Loaded eBPF object file", "file", spec)
	rd, err := perf.NewReader(events, os.Getpagesize())

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create perf reader: %v\n", err)
		os.Exit(1)
	}
	defer rd.Close()
	//events, err := ebpf.NewMap(&ebpf.MapSpec{
	//	Type: ebpf.PerfEventArray,
	//	Name: "my_perf_array",
	//})
	tracepoint, err := link.Tracepoint("syscalls", "sys_enter_openat", spec.Programs["trace_openat"], nil)
	if err != nil {
		llog.Error("Error attaching tracepoint", "error", err)
	}

	defer tracepoint.Close()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Listening for syscalls...")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading from perf buffer: %v\n", err)
				return
			}

			// Parse the data received from kernel space
			//var event dataT
			event := dataT{}
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				//llog.Error("Error unmarshalling data", "error", err)
				continue
			}

			// Print syscall information
			fmt.Printf("CPU: %d, PID: %d COMM: %s FILENAME: %s\n",
				record.CPU, event.Pid, event.Comm, event.Filename)
		}
	}()

	<-sig
	fmt.Println("Exiting...")
}
