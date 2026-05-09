package main

import (
	"reflect"
	"testing"
)

func TestSplitRedirectURIs(t *testing.T) {
	t.Parallel()

	got := splitRedirectURIs(" https://a.example/callback,\nhttp://localhost:3008/callback ,https://a.example/callback ")
	want := []string{
		"https://a.example/callback",
		"http://localhost:3008/callback",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitRedirectURIs() = %#v, want %#v", got, want)
	}
}
