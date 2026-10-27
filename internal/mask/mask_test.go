package mask

import "testing"

func TestApplyRedactsRegisteredValues(t *testing.T) {
	m := New()
	m.Add("hunter2")
	m.Add("topsecret")
	got := m.Apply("password=hunter2 token=topsecret note=ok")
	want := "password=[REDACTED] token=[REDACTED] note=ok"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestAddIgnoresBlanks(t *testing.T) {
	m := New()
	m.Add("")
	m.Add("   ")
	if got := m.Apply("hello"); got != "hello" {
		t.Fatalf("blank secret leaked masking: %q", got)
	}
}

func TestOverlappingSecretsMaskLongerFirst(t *testing.T) {
	// If "hunter" gets replaced before "hunter2", the literal "2" leaks.
	m := New()
	m.Add("hunter")
	m.Add("hunter2")
	if got := m.Apply("password=hunter2 alt=hunter"); got != "password=[REDACTED] alt=[REDACTED]" {
		t.Fatalf("partial-leak guard failed: %q", got)
	}
}

func TestResetClears(t *testing.T) {
	m := New()
	m.Add("x")
	m.Reset()
	if got := m.Apply("x"); got != "x" {
		t.Fatalf("Reset did not clear: %q", got)
	}
}
