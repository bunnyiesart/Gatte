package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/registry"
)

func testImage(b string) string { return "localhost/casemgmt-mcp@sha256:" + strings.Repeat(b, 64) }

// TestRepository_UpdateImage_ChangesOnlyTheImage (design/adr/0043 item 2).
func TestRepository_UpdateImage_ChangesOnlyTheImage(t *testing.T) {
	_, repo := newTestRepo(t)
	ctx := context.Background()
	in := registry.UpstreamServer{Name: "casemgmt", Transport: registry.TransportOCI, Image: testImage("a"),
		Args: []string{"--network=slirp4netns"}, EnvVarNames: []string{"CASEMGMT_API_KEY"}}
	if err := repo.Register(ctx, in); err != nil {
		t.Fatal(err)
	}
	before, _ := repo.Get(ctx, "casemgmt")

	got, err := repo.UpdateImage(ctx, "casemgmt", testImage("b"))
	if err != nil {
		t.Fatal(err)
	}
	after, _ := repo.Get(ctx, "casemgmt")
	if after.Image != testImage("b") || got.Image != after.Image {
		t.Fatalf("image %q / %q", after.Image, got.Image)
	}
	if after.Name != before.Name || after.Transport != before.Transport || strings.Join(after.Args, " ") != strings.Join(before.Args, " ") ||
		strings.Join(after.EnvVarNames, " ") != strings.Join(before.EnvVarNames, " ") || !after.CreatedAt.Equal(before.CreatedAt) {
		t.Fatalf("more than the image changed: %+v -> %+v", before, after)
	}

	for name, tc := range map[string]struct {
		name, image string
		want        error
	}{
		"a tag":        {"casemgmt", "localhost/casemgmt-mcp:latest", registry.ErrInvalid},
		"no such name": {"ghost", testImage("c"), registry.ErrNotFound},
	} {
		if _, err := repo.UpdateImage(ctx, tc.name, tc.image); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if err := repo.Register(ctx, registry.UpstreamServer{Name: "logsearch", Transport: registry.TransportStdio, Command: "/bin/true"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateImage(ctx, "logsearch", testImage("c")); !errors.Is(err, registry.ErrInvalid) {
		t.Errorf("a stdio entry: %v, want ErrInvalid", err)
	}
	if now, _ := repo.Get(ctx, "casemgmt"); now.Image != testImage("b") {
		t.Fatalf("a refused update changed the image: %q", now.Image)
	}
}
