package main

import "testing"

func TestConfiguredIdentitySetRequiresEveryRecipient(t *testing.T) {
	t.Parallel()
	expected := []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	for name, test := range map[string]struct {
		supplied []string
		want     bool
	}{
		"same":      {[]string{expected[0], expected[1]}, true},
		"swapped":   {[]string{expected[1], expected[0]}, true},
		"missing":   {[]string{expected[0]}, false},
		"extra":     {[]string{expected[0], expected[1], "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}, false},
		"duplicate": {[]string{expected[0], expected[0]}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := matchesConfiguredIdentitySet(test.supplied, expected); got != test.want {
				t.Fatalf("matchesConfiguredIdentitySet() = %v, want %v", got, test.want)
			}
		})
	}
}
