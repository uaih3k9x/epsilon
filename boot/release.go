// Package boot 是引导器（设计书 11.9）：从主控取签名的本体发布，装进 A/B 槽，试启动，确认后转正，失败回退。
// 它要冻结进镜像，所以只做这几件事，别往里加功能。
package boot

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Version 是引导器版本；发布清单里的 MinBoot 比它大就拒绝。
const Version = 1

type File struct {
	Path   string `json:"path"` // 槽目录下的文件名，不许带目录
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Version string `json:"version"`
	MinBoot int    `json:"min_boot"`
	Files   []File `json:"files"`
}

// Signed 原样保存清单文本，验签对的是这段字节，不是重新序列化的结果。
type Signed struct {
	Manifest string `json:"manifest"`
	Sig      string `json:"sig"` // base64(ed25519)
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func Sign(m Manifest, priv ed25519.PrivateKey) (Signed, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Signed{}, err
	}
	return Signed{Manifest: string(b), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))}, nil
}

// Verify 任一公钥验过即可（一主一备，换钥匙不用重做镜像）。
func (s Signed) Verify(keys []ed25519.PublicKey) (Manifest, error) {
	var m Manifest
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil || s.Manifest == "" {
		return m, errors.New("清单或签名为空")
	}
	ok := false
	for _, k := range keys {
		ok = ok || ed25519.Verify(k, []byte(s.Manifest), sig)
	}
	if !ok {
		return m, errors.New("验签失败")
	}
	if err := json.Unmarshal([]byte(s.Manifest), &m); err != nil {
		return m, err
	}
	if m.Version == "" {
		return m, errors.New("清单没有版本号")
	}
	for _, f := range m.Files {
		if !safeName.MatchString(f.Path) {
			return m, fmt.Errorf("非法文件名 %q", f.Path)
		}
	}
	return m, nil
}
