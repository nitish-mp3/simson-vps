package config

import "testing"

func TestEndpointTransportValidation(t *testing.T) {
	for _, test := range []struct {
		endpoint  string
		transport string
		valid     bool
	}{
		{"1701", "simson-udp", true},
		{"7112", "simson-udp-alt", true},
		{"desk-phone_1", "simson-tcp", true},
		{"", "simson-udp", false},
		{"1701\n[anonymous]", "simson-udp", false},
		{"1701", "simson-udp\nauth=", false},
		{"1701", "missing-transport", false},
	} {
		cfg := DefaultConfig()
		cfg.AdminToken = "test-token"
		cfg.Asterisk.EndpointTransports = map[string]string{test.endpoint: test.transport}
		if err := cfg.Validate(); (err == nil) != test.valid {
			t.Errorf("endpoint=%q transport=%q: error=%v, valid=%v", test.endpoint, test.transport, err, test.valid)
		}
	}
}

func TestNoQualifyEndpointValidation(t *testing.T) {
	for _, test := range []struct {
		endpoint string
		valid    bool
	}{
		{"6201", true},
		{"", false},
		{"6201\n[anonymous]", false},
	} {
		cfg := DefaultConfig()
		cfg.AdminToken = "test-token"
		cfg.Asterisk.NoQualifyEndpoints = []string{test.endpoint}
		if err := cfg.Validate(); (err == nil) != test.valid {
			t.Errorf("endpoint=%q: error=%v, valid=%v", test.endpoint, err, test.valid)
		}
	}
}
