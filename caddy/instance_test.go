package caddymod

import (
	"path/filepath"
	"testing"
)

// TestAcquireReleaseSharedRefs verifies that several handlers pointing at the
// same database share one instance and that the instance is torn down exactly
// once, after the last reference is released.
func TestAcquireReleaseSharedRefs(t *testing.T) {
	cfg := handlerConfig{
		dbPath:      filepath.Join(t.TempDir(), "sentra.db"),
		adminListen: "off",
	}

	var instances []*instance
	for i := 0; i < 3; i++ {
		inst, err := acquire(cfg)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		instances = append(instances, inst)
	}
	for i := 1; i < len(instances); i++ {
		if instances[i] != instances[0] {
			t.Fatalf("expected a shared instance")
		}
	}
	if instances[0].refs != 3 {
		t.Fatalf("refs=%d, want 3", instances[0].refs)
	}

	for _, inst := range instances {
		release(inst)
	}
	if _, ok := reg[cfg.dbPath]; ok {
		t.Fatalf("instance still registered after last release")
	}
}

// TestReleaseIdempotent guards against a double Cleanup panicking on the
// janitor channel.
func TestReleaseIdempotent(t *testing.T) {
	cfg := handlerConfig{
		dbPath:      filepath.Join(t.TempDir(), "sentra.db"),
		adminListen: "off",
	}
	inst, err := acquire(cfg)
	if err != nil {
		t.Fatal(err)
	}
	release(inst)
	release(inst) // must not panic
}
