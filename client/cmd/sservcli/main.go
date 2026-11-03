package main

import (
	"fmt"
	"os"
	"sservcli/client/internal/app"
)

func main() {
	if err := app.Main(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sservcli:", err)
		os.Exit(1)
	}
}
