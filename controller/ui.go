package controller

// 网页控制台：一个打包进主控的静态页面，数据全走 /v1/* 接口（要 api key）。机房没外网，页面不引任何外部资源。

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui
var uiFiles embed.FS

func uiHandler() http.Handler {
	sub, _ := fs.Sub(uiFiles, "ui")
	return http.StripPrefix("/ui/", http.FileServer(http.FS(sub)))
}
