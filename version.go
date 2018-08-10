package main

import "fmt"

func version() {
	fmt.Printf("wgctl %s\n\n", buildVersion)
	fmt.Println("Copyright © 2018 Antoine POPINEAU")
	fmt.Println("MIT Licence - https://github.com/apognu/wgctl")
}
