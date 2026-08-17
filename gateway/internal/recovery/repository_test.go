package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func writeArtifact(t *testing.T, directory, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRepositoryPublishesAndOpensRegisteredDigest(t *testing.T) {
	root := t.TempDir()
	repository, err := OpenRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte{0x5a}, 16_385)
	source := writeArtifact(t, t.TempDir(), "recovery.efi", content)

	artifact, err := repository.Publish(source)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(content)
	if artifact.Digest != expected || artifact.Size != uint64(len(content)) {
		t.Fatalf("wrong artifact: %#v", artifact)
	}
	file, registered, err := repository.OpenArtifact(artifact.Digest)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := io.ReadAll(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read=%v close=%v", err, closeErr)
	}
	if registered != artifact || !bytes.Equal(opened, content) {
		t.Fatal("registered artifact differs")
	}
	info, err := os.Stat(repository.artifactPath(artifact.Digest))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o444 {
		t.Fatalf("artifact mode %o", info.Mode().Perm())
	}
}

func TestRepositoryRejectsTraversalUnregisteredAndMutableReplacement(t *testing.T) {
	repository, err := OpenRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, identifier := range []string{"../artifact", "/tmp/artifact", "aa/../bb", "AA", "00"} {
		if _, _, err := repository.OpenHex(identifier); !errors.Is(err, ErrArtifactID) {
			t.Fatalf("identifier %q: %v", identifier, err)
		}
	}

	content := []byte("registered recovery artifact")
	source := writeArtifact(t, t.TempDir(), "recovery.efi", content)
	artifact, err := repository.Publish(source)
	if err != nil {
		t.Fatal(err)
	}
	unregistered := sha256.Sum256([]byte("not registered"))
	if err := os.WriteFile(repository.artifactPath(unregistered), []byte("not registered"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.OpenArtifact(unregistered); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("unregistered artifact: %v", err)
	}

	path := repository.artifactPath(artifact.Digest)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, len(content)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.OpenArtifact(artifact.Digest); !errors.Is(err, ErrArtifactChanged) {
		t.Fatalf("mutable replacement: %v", err)
	}
}

func TestRepositoryRejectsSymlinkAndEmptyArtifact(t *testing.T) {
	repository, err := OpenRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := writeArtifact(t, directory, "target.efi", []byte("artifact"))
	link := filepath.Join(directory, "link.efi")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Publish(link); !errors.Is(err, ErrArtifactSource) {
		t.Fatalf("symlink: %v", err)
	}
	empty := writeArtifact(t, directory, "empty.efi", nil)
	if _, err := repository.Publish(empty); !errors.Is(err, ErrArtifactSize) {
		t.Fatalf("empty: %v", err)
	}
}

func TestRepositoryConcurrentIdenticalPublicationIsIdempotent(t *testing.T) {
	repository, err := OpenRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("pbns"), 4096)
	source := writeArtifact(t, t.TempDir(), "recovery.efi", content)
	const workers = 8
	results := make(chan Artifact, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			artifact, publishErr := repository.Publish(source)
			if publishErr != nil {
				errors <- publishErr
				return
			}
			results <- artifact
		}()
	}
	group.Wait()
	close(results)
	close(errors)
	for publishErr := range errors {
		t.Error(publishErr)
	}
	expected := sha256.Sum256(content)
	for artifact := range results {
		if artifact.Digest != expected || artifact.Size != uint64(len(content)) {
			t.Fatalf("wrong concurrent result: %#v", artifact)
		}
	}
	identifier := hex.EncodeToString(expected[:])
	file, _, err := repository.OpenHex(identifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
