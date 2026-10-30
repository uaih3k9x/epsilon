package boot

// boot 与 loader 共用的约定（docs/boot.md），loader 只读这些、不改。冻结范围。

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// 根目录下的文件名（冻结）。
const (
	StateFile   = "boot-state.json"
	StagedFile  = "staged.json"
	EventsFile  = "boot-events.jsonl"
	ReleaseFile = "release.json"
)

// Staged 是 loader 交给 boot 的"槽已备好"。版本只作参考，boot 以槽里验过的清单为准。
type Staged struct {
	Slot    string `json:"slot"`
	Version string `json:"version"`
}

// Event 是 boot-events.jsonl 的一行。
type Event struct {
	Time   string `json:"time"` // RFC3339
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// ReadState 读 <root>/boot-state.json；不存在返回空状态。
func ReadState(root string) (State, error) {
	var s State
	raw, err := os.ReadFile(filepath.Join(root, StateFile))
	if os.IsNotExist(err) {
		err = nil
	} else if err == nil {
		err = json.Unmarshal(raw, &s)
	}
	if s.Versions == nil {
		s.Versions = map[string]string{}
	}
	return s, err
}

// VerifySlot 验一个槽：release.json 签名、min_boot 不超过本引导器、每个文件大小和 sha256。
func VerifySlot(dir string, keys []ed25519.PublicKey) (Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ReleaseFile))
	if err != nil {
		return Manifest{}, err
	}
	var s Signed
	if err := json.Unmarshal(raw, &s); err != nil {
		return Manifest{}, err
	}
	m, err := s.Verify(keys)
	if err != nil {
		return m, err
	}
	if m.MinBoot > Version {
		return m, fmt.Errorf("版本 %s 要引导器 %d，本机是 %d", m.Version, m.MinBoot, Version)
	}
	for _, f := range m.Files {
		n, sum, err := sumFile(filepath.Join(dir, f.Path))
		if err != nil || n != f.Size || sum != f.SHA256 {
			return m, fmt.Errorf("%s 对不上清单", f.Path)
		}
	}
	return m, nil
}
