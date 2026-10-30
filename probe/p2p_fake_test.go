package probe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"sync"
)

// memStore 是测试用的块缓存：和 chunk.Store 一样，Put 校验 sha256。
type memStore struct {
	mu      sync.Mutex
	data    map[string][]byte
	evictFn func(h string) bool // Evict 时不在 keep 里、且这个函数说删的才删；nil = 不删
	keeps   []map[string]bool   // 每次 Evict 收到的 keep
}

var errHashMismatch = errors.New("块哈希不符")

func newMemStore(chunks ...[]byte) *memStore {
	s := &memStore{data: map[string][]byte{}}
	for _, c := range chunks {
		s.data[hashOf(c)] = c
	}
	return s
}

func hashOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func (s *memStore) Has(h string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data[h]
	return ok
}

func (s *memStore) Open(h string) (io.ReadSeekCloser, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data[h]
	if !ok {
		return nil, 0, os.ErrNotExist
	}
	return nopCloser{bytes.NewReader(b)}, int64(len(b)), nil
}

func (s *memStore) Put(h string, r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if hashOf(b) != h {
		return errHashMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[h] = b
	return nil
}

func (s *memStore) List() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var l []string
	for h := range s.data {
		l = append(l, h)
	}
	sort.Strings(l)
	return l
}

func (s *memStore) Evict(keep map[string]bool) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keeps = append(s.keeps, keep)
	var del []string
	for h := range s.data {
		if !keep[h] && s.evictFn != nil && s.evictFn(h) {
			delete(s.data, h)
			del = append(del, h)
		}
	}
	return del
}

type nopCloser struct{ io.ReadSeeker }

func (nopCloser) Close() error { return nil }
