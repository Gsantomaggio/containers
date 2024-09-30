package main

import (
	"bufio"
	"fmt"
	"os"
)

var array = []string{}

func main() {
	for i := 0; i < 10_000_000; i++ {
		bs := make([]byte, 1048576)
		array = append(array, string(bs))
		if i%100 == 0 {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("[%d] Bytes allocated %d: ", os.Getpid(), len(array)*1048576)
			_, err := reader.ReadString('\n')
			if err != nil {
				return
			}
		}
	}

	for i, s := range array {
		fmt.Printf("%d: %s", i, s)
	}

}
