package groups

import "testing"

func TestParseName(t *testing.T) {
	name, err := ParseName(" Editors ")
	if err != nil {
		t.Fatal(err)
	}
	if name.String() != "editors" {
		t.Fatalf("name = %s", name.String())
	}
	if _, err = ParseName(""); err == nil {
		t.Fatal("empty name was accepted")
	}
	if _, err = ParseName("has space"); err == nil {
		t.Fatal("spaced name was accepted")
	}
}
