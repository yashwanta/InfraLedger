package main

import "testing"

func TestEndpoint(t *testing.T) {
	for _, test := range []struct {
		input, host string
		port        int
	}{{"127.0.0.1:443", "127.0.0.1", 443}, {"[::1]:5432", "::1", 5432}, {"0.0.0.0:8080", "0.0.0.0", 8080}, {"*:*", "*", 0}} {
		host, port := endpoint(test.input)
		if host != test.host || port != test.port {
			t.Errorf("%s: got %s:%d", test.input, host, port)
		}
	}
}
