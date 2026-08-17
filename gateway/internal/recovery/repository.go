package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	ErrArtifactID      = errors.New("invalid recovery artifact identifier")
	ErrArtifactSource  = errors.New("invalid recovery artifact source")
	ErrArtifactSize    = errors.New("invalid recovery artifact size")
	ErrArtifactChanged = errors.New("recovery artifact changed")
	ErrUnregistered    = errors.New("recovery artifact is not registered")
	ErrRepository      = errors.New("invalid recovery repository")
)

type Artifact struct {
	Digest [sha256.Size]byte
	Size   uint64
}

type Repository struct {
	root         string
	artifactsDir string
	metadataDir  string
}

type artifactMetadata struct {
	Version uint64 `json:"version"`
	Digest  string `json:"sha256"`
	Size    uint64 `json:"size"`
}

func OpenRepository(root string) (*Repository, error) {
	if root == "" {
		return nil, ErrRepository
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, ErrRepository
	}
	if err := os.MkdirAll(absolute, 0o750); err != nil {
		return nil, fmt.Errorf("create recovery repository: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, ErrRepository
	}
	repository := &Repository{
		root: absolute, artifactsDir: filepath.Join(absolute, "artifacts"),
		metadataDir: filepath.Join(absolute, "metadata"),
	}
	for _, directory := range []string{repository.artifactsDir, repository.metadataDir} {
		if err := os.Mkdir(directory, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create recovery repository directory: %w", err)
		}
		entry, statErr := os.Lstat(directory)
		if statErr != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 ||
			entry.Mode().Perm()&0o022 != 0 {
			return nil, ErrRepository
		}
	}
	return repository, nil
}

func (repository *Repository) Publish(source string) (Artifact, error) {
	if repository == nil || source == "" {
		return Artifact{}, ErrArtifactSource
	}
	sourceInfo, err := os.Lstat(source)
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Mode()&os.ModeSymlink != 0 {
		return Artifact{}, ErrArtifactSource
	}
	if sourceInfo.Size() <= 0 || uint64(sourceInfo.Size()) > MaximumImageSize {
		return Artifact{}, ErrArtifactSize
	}
	sourceFile, err := os.Open(source)
	if err != nil {
		return Artifact{}, fmt.Errorf("open recovery artifact: %w", err)
	}
	openedInfo, err := sourceFile.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(sourceInfo, openedInfo) {
		_ = sourceFile.Close()
		return Artifact{}, ErrArtifactSource
	}

	staged, err := os.CreateTemp(repository.artifactsDir, ".incoming-")
	if err != nil {
		_ = sourceFile.Close()
		return Artifact{}, fmt.Errorf("create staged recovery artifact: %w", err)
	}
	stagedPath := staged.Name()
	defer func() { _ = os.Remove(stagedPath) }()
	if err := staged.Chmod(0o600); err != nil {
		_ = staged.Close()
		_ = sourceFile.Close()
		return Artifact{}, fmt.Errorf("protect staged recovery artifact: %w", err)
	}

	hash := sha256.New()
	buffer := make([]byte, 64*1024)
	written, copyErr := io.CopyBuffer(io.MultiWriter(staged, hash), sourceFile, buffer)
	sourceCloseErr := sourceFile.Close()
	if copyErr != nil || sourceCloseErr != nil || written != sourceInfo.Size() ||
		written <= 0 || uint64(written) > MaximumImageSize {
		_ = staged.Close()
		return Artifact{}, ErrArtifactChanged
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		return Artifact{}, fmt.Errorf("sync staged recovery artifact: %w", err)
	}
	if err := staged.Close(); err != nil {
		return Artifact{}, fmt.Errorf("close staged recovery artifact: %w", err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	artifact := Artifact{Digest: digest, Size: uint64(written)}
	destination := repository.artifactPath(digest)
	if err := os.Link(stagedPath, destination); err != nil && !errors.Is(err, os.ErrExist) {
		return Artifact{}, fmt.Errorf("install recovery artifact: %w", err)
	}
	if err := os.Chmod(destination, 0o444); err != nil {
		return Artifact{}, fmt.Errorf("protect recovery artifact: %w", err)
	}
	if err := verifyArtifactFile(destination, artifact); err != nil {
		return Artifact{}, err
	}
	if err := syncDirectory(repository.artifactsDir); err != nil {
		return Artifact{}, err
	}
	if err := repository.installMetadata(artifact); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

func (repository *Repository) OpenHex(identifier string) (*os.File, Artifact, error) {
	if len(identifier) != sha256.Size*2 {
		return nil, Artifact{}, ErrArtifactID
	}
	decoded, err := hex.DecodeString(identifier)
	if err != nil || hex.EncodeToString(decoded) != identifier {
		return nil, Artifact{}, ErrArtifactID
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	return repository.OpenArtifact(digest)
}

func (repository *Repository) OpenArtifact(digest [sha256.Size]byte) (*os.File, Artifact, error) {
	if repository == nil {
		return nil, Artifact{}, ErrRepository
	}
	metadata, err := repository.readMetadata(digest)
	if err != nil {
		return nil, Artifact{}, err
	}
	artifact := Artifact{Digest: digest, Size: metadata.Size}
	path := repository.artifactPath(digest)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o444 {
		return nil, Artifact{}, ErrArtifactChanged
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, Artifact{}, ErrArtifactChanged
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, Artifact{}, ErrArtifactChanged
	}
	hash := sha256.New()
	read, err := io.Copy(hash, file)
	if err != nil || read < 0 || uint64(read) != artifact.Size ||
		!bytes.Equal(hash.Sum(nil), artifact.Digest[:]) {
		_ = file.Close()
		return nil, Artifact{}, ErrArtifactChanged
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, Artifact{}, ErrArtifactChanged
	}
	return file, artifact, nil
}

func (repository *Repository) artifactPath(digest [sha256.Size]byte) string {
	return filepath.Join(repository.artifactsDir, hex.EncodeToString(digest[:]))
}

func (repository *Repository) metadataPath(digest [sha256.Size]byte) string {
	return filepath.Join(repository.metadataDir, hex.EncodeToString(digest[:])+".json")
}

func (repository *Repository) installMetadata(artifact Artifact) error {
	metadata := artifactMetadata{
		Version: 1, Digest: hex.EncodeToString(artifact.Digest[:]), Size: artifact.Size,
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encode recovery metadata: %w", err)
	}
	encoded = append(encoded, '\n')
	staged, err := os.CreateTemp(repository.metadataDir, ".incoming-")
	if err != nil {
		return fmt.Errorf("create staged recovery metadata: %w", err)
	}
	stagedPath := staged.Name()
	defer func() { _ = os.Remove(stagedPath) }()
	writeErr := staged.Chmod(0o600)
	if writeErr == nil {
		_, writeErr = staged.Write(encoded)
	}
	if writeErr == nil {
		writeErr = staged.Sync()
	}
	closeErr := staged.Close()
	if writeErr != nil || closeErr != nil {
		return fmt.Errorf("write recovery metadata: %w", errors.Join(writeErr, closeErr))
	}
	destination := repository.metadataPath(artifact.Digest)
	if err := os.Link(stagedPath, destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("install recovery metadata: %w", err)
		}
		existing, readErr := os.ReadFile(destination)
		if readErr != nil || !bytes.Equal(existing, encoded) {
			return ErrArtifactChanged
		}
	}
	if err := os.Chmod(destination, 0o444); err != nil {
		return fmt.Errorf("protect recovery metadata: %w", err)
	}
	return syncDirectory(repository.metadataDir)
}

func (repository *Repository) readMetadata(digest [sha256.Size]byte) (artifactMetadata, error) {
	path := repository.metadataPath(digest)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return artifactMetadata{}, ErrUnregistered
		}
		return artifactMetadata{}, ErrArtifactChanged
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o444 ||
		info.Size() <= 0 || info.Size() > 1024 {
		return artifactMetadata{}, ErrArtifactChanged
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return artifactMetadata{}, ErrArtifactChanged
	}
	var metadata artifactMetadata
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return artifactMetadata{}, ErrArtifactChanged
	}
	canonical, err := json.Marshal(metadata)
	if err != nil || !bytes.Equal(encoded, append(canonical, '\n')) || metadata.Version != 1 ||
		metadata.Digest != hex.EncodeToString(digest[:]) || metadata.Size == 0 ||
		metadata.Size > MaximumImageSize {
		return artifactMetadata{}, ErrArtifactChanged
	}
	return metadata, nil
}

func verifyArtifactFile(path string, artifact Artifact) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 0 || uint64(info.Size()) != artifact.Size {
		return ErrArtifactChanged
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrArtifactChanged
	}
	hash := sha256.New()
	read, readErr := io.Copy(hash, file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || read < 0 || uint64(read) != artifact.Size ||
		!bytes.Equal(hash.Sum(nil), artifact.Digest[:]) {
		return ErrArtifactChanged
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open recovery repository directory: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("sync recovery repository directory: %w", errors.Join(syncErr, closeErr))
	}
	return nil
}
