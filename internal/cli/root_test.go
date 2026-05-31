package cli

import "testing"

func TestShouldLaunchTUI(t *testing.T) {
	cases := []struct {
		name        string
		isTTY       bool
		bareInvoke  bool
		interactive bool
		want        bool
	}{
		{"bare on tty", true, true, false, true},
		{"bare piped", false, true, false, false},
		{"-i on tty", true, false, true, true},
		{"-i piped", false, false, true, false},
		{"subcommand no -i", true, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shouldLaunchTUI(c.isTTY, c.bareInvoke, c.interactive)
			if got != c.want {
				t.Fatalf("shouldLaunchTUI(%v,%v,%v) = %v, want %v",
					c.isTTY, c.bareInvoke, c.interactive, got, c.want)
			}
		})
	}
}
