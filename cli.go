package main

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"code.cloudfoundry.org/bytefmt"
	"github.com/fatih/color"
)

var (
	tunnelColor  = color.New(color.Bold, color.FgRed)
	peerColor    = color.New(color.Bold, color.FgGreen)
	attrKeyColor = color.New(color.Faint)

	okColor  = color.New(color.FgGreen)
	errColor = color.New(color.FgRed)
)

func padding(pad int) {
	str := ""
	for i := 0; i < 2*pad; i++ {
		str = str + " "
	}
	fmt.Print(str)
}

// Line prints an empty line
func Line() {
	fmt.Println()
}

// PrintAttr prints a formatted and colored attribute to be used in `info` output, if predicate
// returns true, in the form of:
//   <padding><key>: <value>
func PrintAttr(pad int, key string, value string, predicate bool, args ...interface{}) {
	if predicate {
		padding(pad)

		attrKeyColor.Print(fmt.Sprintf("%s: ", key))

		fmt.Printf("%s\n", fmt.Sprintf(value, args...))
	}
}

// PrintSection prints a formatted and colored section header to be used in `info`, in the form of:
//   <padding><title>: <value>'
func PrintSection(pad int, key string, value string, color *color.Color, args ...interface{}) {
	padding(pad)

	color.Print(fmt.Sprintf("%s: ", key))
	fmt.Printf("%s\n", fmt.Sprintf(value, args...))
}

// FormatPSK formats a preshared key as a hex string
func FormatPSK(psk wgtypes.Key) string {
	return fmt.Sprintf("%x", psk[:])
}

// FormatSubnet formats a net.IPNet as a string
func FormatSubnet(sub net.IPNet) string {
	mask, _ := sub.Mask.Size()

	return fmt.Sprintf("%s/%d", sub.IP, mask)
}

// FormatInterval formats a duration as an amount of elapsed time.
func FormatInterval(then time.Time) string {
	delta := time.Since(then)

	if delta.Seconds() < 60 {
		return fmt.Sprintf("%d second(s) ago", int(delta.Seconds()))
	}
	if delta.Minutes() < 60 {
		return fmt.Sprintf("%d minute(s) ago", int(delta.Minutes()))
	}
	if delta.Hours() < 25 {
		return fmt.Sprintf("%d hour(s) ago", int(delta.Hours()))
	}
	return fmt.Sprintf("over a day ago")
}

// FormatTransfer formats transmitted and received bytes.
func FormatTransfer(rx, tx int64) string {
	return fmt.Sprintf("↓ %s ↑ %s", bytefmt.ByteSize(uint64(rx)), bytefmt.ByteSize(uint64(tx)))
}

// PrintStatus prints a status message ot be used for action return messages (OK or KO)
func PrintStatus(prefix, message string) {
	fmt.Printf("%s %s\n", prefix, message)
}

// Up is a formatted and colored helper for PrintStatus with an OK/up semantic
func Up(message string, args ...interface{}) {
	msg := fmt.Sprintf(message, args...)

	PrintStatus(okColor.Sprintf("[↑]"), msg)
}

// Down is a formatted and colored helper for PrintStatus with an KO/down semantic
func Down(message string, args ...interface{}) {
	msg := fmt.Sprintf(message, args...)

	PrintStatus(errColor.Sprintf("[↓]"), msg)
}
