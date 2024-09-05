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

// maybe
#### Mount namespace let's create my first container

* Let's create a new mount namespace: `unshare -fm zsh`
* Check the namespaces of the process `lsns -p $$`
* Let's check the mount points `mount`
* Let's create a new mount point `mkdir /tmp/mountpoint`
* Let's mount the proc filesystem `mount -t proc proc /tmp/mountpoint`
* Let's check the mount points `mount`
* Let's unmount the proc filesystem `umount /tmp/mountpoint`