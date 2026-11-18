package boot_test

// 模糊测试的私钥是固定种子算出来的（boot/fuzz_test.go 的 fuzzPriv），公开仓库里谁都能算出来，
// 种子语料里也有用它签的清单。它的公钥绝不能进正式的公钥列表：loader.PublicKeys，以及
// cmd/epsilon-boot 的 publicKeys（loader/keys_test.go 保证两份一致）。

import (
	"encoding/base64"
	"slices"
	"testing"

	"epsilon/boot"
	"epsilon/loader"
)

func TestFuzzKeyNotInReleaseKeys(t *testing.T) {
	k := base64.StdEncoding.EncodeToString(boot.FixedKeyPublic())
	if slices.Contains(loader.PublicKeys, k) {
		t.Fatalf("模糊测试的公钥 %s 出现在 loader.PublicKeys 里：它的私钥是公开的", k)
	}
}
