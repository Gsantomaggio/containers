package main

import (
	"fmt"
	"os"
	"time"
)

func main() {

	for i := 0; i < 25500; i++ {
		fmt.Println("My PID is: ", os.Getpid(), " and I am running for the ", i, " time")
		time.Sleep(10 * time.Second)
	}
}
