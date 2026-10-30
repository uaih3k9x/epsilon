package main

// 发布签名公钥，一主一备（私钥在 Mac 的 dist/keys/，不进仓库）。改这里就得重新下发引导器。
var publicKeys = []string{
	"fx7iOV5D9Af4zQ+jtKXgQqrenDldPIFlftjVqUxCsoU=", // release-main
	"GIbArjrI18FIhV/10spF4JOnF6dKk2nFd3irMFBWxlo=", // release-backup
}
