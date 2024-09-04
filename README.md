# Play with Linux Containers

## Introduction
This repository contains a collection of scripts and configuration files to play with Linux Containers.

## Prerequisites
A modern Linux distribution. Tested on Fedora VERSION="40 (Server Edition)".

## Everything in linux lives in a namespace

#### Default namespaces 

* A namespace is a way to isolate a process from the rest of the system.
* Let's see the default namespaces in a Linux system:`lsns` or `lsns -t pid` to see the namespaces of a process.
* Check where the PID is running: `ls /proc/$$/ns -al`
* Run the golang program `scripts/1_get_my_pid/main.go` to get the PID of the process.
* Let's get the PID ` pidof main.go`
* Check the namespaces of the process `pidof main | xargs -n1 lsns -p`


