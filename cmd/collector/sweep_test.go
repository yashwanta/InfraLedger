package main

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseMDNSPrinterResponse(t *testing.T) {
	name := func(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	b.StartAnswers()
	b.PTRResource(dnsmessage.ResourceHeader{Name: name("_ipp._tcp.local."), Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.PTRResource{PTR: name("Office Printer._ipp._tcp.local.")})
	b.StartAdditionals()
	b.SRVResource(dnsmessage.ResourceHeader{Name: name("Office Printer._ipp._tcp.local."), Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.SRVResource{Port: 631, Target: name("BRW123.local.")})
	b.TXTResource(dnsmessage.ResourceHeader{Name: name("Office Printer._ipp._tcp.local."), Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.TXTResource{TXT: []string{"ty=Brother HL-L2350DW", "usb_MFG=Brother", "rp=ipp/print"}})
	b.AResource(dnsmessage.ResourceHeader{Name: name("BRW123.local."), Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.AResource{A: [4]byte{10, 20, 30, 50}})
	packet, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	info := &Neighbor{}
	parseMDNS(packet, info)
	if len(info.Services) == 0 || info.Services[0] != "_ipp._tcp" || info.FriendlyName != "Office Printer" || info.Hostname != "BRW123" || info.Model != "Brother HL-L2350DW" || info.Manufacturer != "Brother" {
		t.Fatalf("%+v", info)
	}
}
