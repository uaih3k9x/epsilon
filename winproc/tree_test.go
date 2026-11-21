package winproc

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 测试二进制自己当进程树：parent 起一个 child，打印 child 的 pid，然后两个都睡着不走。
func TestMain(m *testing.M) {
	switch os.Getenv("WINPROC_HELPER") {
	case "parent":
		c := exec.Command(os.Args[0])
		c.Env = append(os.Environ(), "WINPROC_HELPER=child")
		if err := c.Start(); err != nil {
			os.Exit(2)
		}
		fmt.Println(c.Process.Pid)
		time.Sleep(time.Hour)
		os.Exit(0)
	case "child":
		time.Sleep(time.Hour)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestTreeKillTakesChildren(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "WINPROC_HELPER=parent")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	tree, err := StartTree(cmd)
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	child, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	if !Alive(child) {
		t.Fatal("孙进程应该还活着")
	}
	tree.Kill()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("主进程没被杀")
	}
	tree.Close()
	deadline := time.Now().Add(5 * time.Second)
	for Alive(child) {
		if time.Now().After(deadline) {
			t.Fatal("孙进程没被一起杀掉")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestTreeCloseKillsLeftovers(t *testing.T) {
	// 主进程自己退出、留下孙进程：Close 也要把它杀掉（任务结束整棵树一起杀）
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "WINPROC_HELPER=parent")
	out, _ := cmd.StdoutPipe()
	tree, err := StartTree(cmd)
	if err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(out).ReadString('\n')
	child, _ := strconv.Atoi(strings.TrimSpace(line))
	cmd.Process.Kill() // 只杀主进程
	cmd.Wait()
	if !Alive(child) {
		t.Fatal("孙进程应该还活着")
	}
	tree.Close()
	deadline := time.Now().Add(5 * time.Second)
	for Alive(child) {
		if time.Now().After(deadline) {
			t.Fatal("Close 没杀掉剩下的进程")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
