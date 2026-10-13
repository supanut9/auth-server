package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/supanut9/auth-server/internal/domain"
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

func TestSelectClientsFilters(t *testing.T) {
	all := []domain.OAuthClient{{ClientID: "a"}, {ClientID: "b"}, {ClientID: "c"}}
	if got := selectClients(all, nil); len(got) != 3 {
		t.Fatalf("no filter: got %d clients, want 3", len(got))
	}
	got := selectClients(all, []string{"c", "a"})
	if len(got) != 2 || got[0].ClientID != "c" || got[1].ClientID != "a" {
		t.Fatalf("filter: got %+v", got)
	}
}

func TestClientFilterFromEnv(t *testing.T) {
	t.Setenv("DEVSEED_CLIENTS_TEST", " portfolio-manager-web, macro-web\nx ")
	got := clientFilterFromEnv("DEVSEED_CLIENTS_TEST")
	if strings.Join(got, "|") != "portfolio-manager-web|macro-web|x" {
		t.Fatalf("got %q", got)
	}
}
