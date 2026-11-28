package app

import "testing"

func TestDescribeLocalDevice(t *testing.T) {
	cases := []struct {
		obs  M
		want string
	}{
		{M{"services": []any{"_ipp._tcp", "_http._tcp"}, "friendlyName": "Office Printer", "model": "HL-L2350DW"}, "Printer"},
		{M{"services": []any{"_googlecast._tcp"}, "friendlyName": "Living Room TV", "model": "Chromecast"}, categoryMedia},
		{M{"upnpType": "urn:schemas-upnp-org:device:MediaRenderer:1", "friendlyName": "[TV] Samsung"}, categoryMedia},
		{M{"services": []any{"_hap._tcp"}, "friendlyName": "Hue Bridge"}, categoryIoT},
		{M{"friendlyName": "DiskStation", "model": "DS920+", "services": []any{"_smb._tcp"}}, "Storage"},
		{M{"upnpType": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"}, "Router"},
		{M{"hostname": "Johns-iPhone"}, categoryPhone},
		{M{"services": []any{"_http._tcp"}}, "Network endpoint"},
	}
	for _, c := range cases {
		d := M{"category": "Network endpoint", "ip": "10.20.30.9"}
		describeLocalDevice(d, c.obs)
		if S(d, "category") != c.want {
			t.Fatalf("%v: got %q want %q", c.obs, S(d, "category"), c.want)
		}
	}
	vendorOnly := M{"category": "Network endpoint", "mac": "24:0a:c4:00:00:01"} // Espressif
	applyMACVendor(vendorOnly)
	describeLocalDevice(vendorOnly, M{})
	if S(vendorOnly, "category") != categoryIoT {
		t.Fatal("Espressif MAC should label an IoT device", vendorOnly)
	}
	manual := M{"category": "Server", "model": "R740"}
	describeLocalDevice(manual, M{"services": []any{"_ipp._tcp"}, "model": "Other"})
	if S(manual, "category") != "Server" || S(manual, "model") != "R740" {
		t.Fatal("hand-entered values were overwritten", manual)
	}
}
