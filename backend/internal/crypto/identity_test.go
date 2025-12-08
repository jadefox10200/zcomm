package crypto

import "testing"

func TestNormalizeDeskID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"5555443333", "5555443333"},
		{"555-444-3333", "5554443333"},
		{"(555) 444-3333", "5554443333"},
		{"Bob @ 5555-44-3333", "5555443333"},
		{"5555-44-3333", "5555443333"},
		{"Bob", ""},
		{"", ""},
		{"abc123def456", "123456"},
	}

	for _, test := range tests {
		result := NormalizeDeskID(test.input)
		if result != test.expected {
			t.Errorf("NormalizeDeskID(%q) = %q, expected %q", test.input, result, test.expected)
		}
	}
}