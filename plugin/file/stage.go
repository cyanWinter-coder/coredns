package file

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/coredns/coredns/plugin/file/tree"

	"github.com/miekg/dns"
)

// zoneStage is a temporary, complete zone file. The live zone is only replaced
// after the staged file has been parsed and Commit has atomically renamed it.
type zoneStage struct {
	file      *os.File
	writer    *bufio.Writer
	path      string
	finalPath string
	closed    bool
	committed bool
}

func newZoneStage(finalPath string) (*zoneStage, error) {
	dir := ""
	if finalPath != "" && finalPath != "stdin" && filepath.Clean(finalPath) != "." {
		dir = filepath.Dir(finalPath)
	}
	f, err := os.CreateTemp(dir, ".zone-transfer-*.tmp")
	if err != nil {
		return nil, err
	}
	return &zoneStage{
		file:      f,
		writer:    bufio.NewWriterSize(f, 256*1024),
		path:      f.Name(),
		finalPath: finalPath,
	}, nil
}

func (s *zoneStage) WriteString(p string) (int, error) {
	return s.writer.WriteString(p)
}

func (s *zoneStage) FlushClose() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if err := s.writer.Flush(); err != nil {
		_ = s.file.Close()
		return err
	}
	if err := s.file.Sync(); err != nil {
		_ = s.file.Close()
		return err
	}
	return s.file.Close()
}

// Parse parses and validates the staged zone without making it live.
func (s *zoneStage) Parse(origin string) (*Zone, error) {
	if err := s.FlushClose(); err != nil {
		return nil, err
	}
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, origin, s.path, -1)
}

// Validate parses every staged record but does not retain the parsed tree. It
// is useful after applying an IXFR to an already constructed candidate.
func (s *zoneStage) Validate(origin string) error {
	if err := s.FlushClose(); err != nil {
		return err
	}
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()

	p := dns.NewZoneParser(f, dns.Fqdn(origin), s.path)
	p.SetIncludeAllowed(true)
	seenSOA := false
	for rr, ok := p.Next(); ok; rr, ok = p.Next() {
		if _, ok := rr.(*dns.SOA); ok {
			seenSOA = true
		}
	}
	if err := p.Err(); err != nil {
		return fmt.Errorf("failed to validate staged zone %q for %s: %w", s.path, origin, err)
	}
	if !seenSOA {
		return fmt.Errorf("staged zone %q for %s has no SOA", s.path, origin)
	}
	return nil
}

// Commit atomically installs the staged file at finalPath. Symbolic in-memory
// file names such as "stdin" have no on-disk destination; their stage is
// removed after validation.
func (s *zoneStage) Commit() error {
	if s.committed {
		return nil
	}
	if err := s.FlushClose(); err != nil {
		return err
	}

	if s.finalPath == "" || s.finalPath == "stdin" || filepath.Clean(s.finalPath) == "." {
		s.committed = true
		return os.Remove(s.path)
	}

	mode := os.FileMode(0o644)
	if fi, err := os.Stat(s.finalPath); err == nil {
		mode = fi.Mode()
	}
	if err := os.Chmod(s.path, mode); err != nil {
		return err
	}
	if err := os.Rename(s.path, s.finalPath); err != nil {
		return err
	}
	s.committed = true

	// Persist the rename itself when the destination directory is fsync-able.
	if d, err := os.Open(filepath.Dir(s.finalPath)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Abort closes and removes an uncommitted stage. It is safe to call after a
// successful Commit.
func (s *zoneStage) Abort() {
	if s == nil || s.committed {
		return
	}
	_ = s.FlushClose()
	_ = os.Remove(s.path)
}

func writeZone(w io.Writer, z *Zone) error {
	ap, tr := z.snapshot()
	apex, err := ap.records()
	if err != nil {
		return err
	}
	for _, rr := range apex {
		if _, err := io.WriteString(w, rr.String()+"\n"); err != nil {
			return err
		}
	}
	if tr == nil {
		return nil
	}
	return tr.Walk(func(e *tree.Elem, _ map[uint16][]dns.RR) error {
		for _, rr := range e.All() {
			if _, err := io.WriteString(w, rr.String()+"\n"); err != nil {
				return err
			}
		}
		return nil
	})
}
