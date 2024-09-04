package main

import (
	"fmt"
	"os"
	"time"
)

func main() {

	for i := 0; i < 25500; i++ {
		fmt.Println("My PID is: ", os.Getpid())
		time.Sleep(2 * time.Second)
	}
}
