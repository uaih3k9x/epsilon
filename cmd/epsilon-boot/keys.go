package main

// 发布签名公钥，一主一备（私钥在 Mac 的 dist/keys/，不进仓库）。改这里就得重新下发引导器。
// loader/keys.go 里有一份同样的 PublicKeys，两份必须一致（loader/keys_test.go 会比对）。
var publicKeys = []string{
	"fx7iOV5D9Af4zQ+jtKXgQqrenDldPIFlftjVqUxCsoU=", // release-main
	"GIbArjrI18FIhV/10spF4JOnF6dKk2nFd3irMFBWxlo=", // release-backup
}
