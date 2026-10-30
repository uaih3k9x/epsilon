package loader

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// PublicKeys 是发布签名公钥，一主一备。
// 和 cmd/epsilon-boot/keys.go 的 publicKeys 是同一份，两份必须一致（keys_test.go 会比对）。
var PublicKeys = []string{
	"fx7iOV5D9Af4zQ+jtKXgQqrenDldPIFlftjVqUxCsoU=", // release-main
	"GIbArjrI18FIhV/10spF4JOnF6dKk2nFd3irMFBWxlo=", // release-backup
}

// ParseKeys 把 base64 公钥解出来。
func ParseKeys(ss []string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, k := range ss {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("公钥坏了: %q", k)
		}
		keys = append(keys, b)
	}
	return keys, nil
}
