# Play with Linux Containers

## Introduction
This repository contains a collection of scripts and configuration files to play with Linux Containers.

## Prerequisites
A modern Linux distribution. Tested on Fedora VERSION="40 (Server Edition)".

## Everything in linux lives in a namespace

#### Default namespaces 

* A namespace is a way to isolate a process from the rest of the system.
* Let's see the default namespaces in a Linux system:`lsns` or `lsns -t pid` to see 
  the namespaces of a process. Default value is 4026531836.
* Check where the PID is running: `ls /proc/$$/ns -al`
* Run the golang program `scripts/1_get_my_pid/main.go` to get the PID of the process.
* Let's get the PID ` pidof main.go`
* Check the namespaces of the process `pidof main | xargs -n1 lsns -p`


#### PID namespace let's create my first container

* Let's create a new PID namespace: `unshare -fp --mount-proc zsh`
* Check the namespaces of the process `lsns -p $$`
* Run the golang program `go run scripts/1_get_my_pid/main.go &` to get the PID of the process.
* From another terminal check the namespaces of the process ` cat /proc/$(pidof main)/status | grep NSpid`
* Check the PID of the process `pidof main`
* Check all the namespaces `lsns -t pid`
* Let's enter to the PID namespace `nsenter -t $(lsns -t pid | tail -n1 | awk {'print $4'}) -p -r zsh`
* Let's check the list of the processes `ps aux` ( Seen ??"!)
* Let's kill the process `kill -9 $(pidof main)`

#### Network namespace let's create with ip netns

* Execute the script `scripts/network/2_create_network_namespace`
* Execute the script `ip netns exec blue zsh`
* Execute the script `ip netns exec red zsh`


#### Let's put UTS, PID, and Network namespaces together

* Execute the command `ip link add veth-red type veth peer name veth-blue`
* Execute the command to one terminal `unshare -f -p -n -u --mount-proc /bin/zsh`
* Set hostname `hostname blue`
* Get the net PID of the process `lsns -t net` and get the PID-BLUE
* Execute the command to second terminal `unshare -f -p -n -u --mount-proc /bin/zsh`
* Set hostname `hostname red`
* Get the net PID of the process `lsns -t net` and get the PID-RED

* ip link set veth-blue netns PID-BLUE
* ip link set veth-red netns PID-RED
* ip link set veth-red up
* ip link set veth-blue up
* ip addr add 192.168.15.1/30 dev veth-red
* ip addr add 192.168.15.2/30 dev veth-blue
* from the red `nc -lv 5552`
* from the blue `telnet 192.168.15.1 5552`
* check `lsns -t net`
* Execute the command to one terminal `nsenter -n -t PID-BLUE zsh`
* Execute the script `/ebpf_ns_firewall/make`
* Check `cat /sys/kernel/debug/tracing/trace_pipe`
* The firewall is blocking the connection `5552` from the blue to the red
* Try nc with another port `nc -lv 5553` and `telnet` again


#### [SKIP] UTS namespace let's create my first container

* Let's create a new UTS namespace: `unshare -fn zsh`
* Check the namespaces of the process `lsns -p $$`
* Let's change the hostname `hostname mycontainer`
* Let's check the hostname `hostname`
* Let's exit the UTS namespace `exit`


#### [SKIP] Mount namespace let's create my first container

* Let's create a new mount namespace: `unshare -fm zsh`
* Check the namespaces of the process `lsns -p $$`
* Let's check the mount points `mount`
* Let's create a new mount point `mkdir /tmp/mountpoint`
* Let's mount the proc filesystem `mount -t proc proc /tmp/mountpoint`
* Let's check the mount points `mount`
* Let's unmount the proc filesystem `umount /tmp/mountpoint`


