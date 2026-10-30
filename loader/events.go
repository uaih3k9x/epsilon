package loader

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"epsilon/boot"
	"epsilon/proto"
)

// SentFile 记 boot-events.jsonl 已转发到的字节偏移，只有 loader 写。
const SentFile = "boot-events.sent"

// ForwardEvents 把 boot-events.jsonl 里还没发的完整行逐条 POST /v1/events，发成功一条推进一次偏移。
// 文件被 boot 轮转过（比偏移短，或偏移前一个字节不是换行——新文件已经长过了旧偏移）就从 0 开始。
func (l *Loader) ForwardEvents(ctx context.Context) error {
	sentPath := filepath.Join(l.Root, SentFile)
	var off int64
	if b, err := os.ReadFile(sentPath); err == nil {
		off, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	data, off, err := readEvents(filepath.Join(l.Root, boot.EventsFile), off)
	if err != nil || data == nil {
		return err
	}
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return nil // 剩下的半行等 boot 写完
		}
		line := bytes.TrimSpace(data[:i])
		data = data[i+1:]
		var ev boot.Event
		if len(line) > 0 {
			if err := json.Unmarshal(line, &ev); err != nil || ev.Kind == "" {
				log.Printf("引导器事件坏行，跳过: %q", line)
			} else if err := l.post(ctx, "/v1/events", proto.Event{Node: l.Node, Kind: ev.Kind, Detail: detail(ev)}); err != nil {
				return err
			}
		}
		off += int64(i + 1)
		if err := writeAtomic(sentPath, []byte(strconv.FormatInt(off, 10))); err != nil {
			return err
		}
	}
}

// readEvents 读偏移之后的内容，读完马上关文件：Windows 上开着的文件 boot 改名轮转会失败，不能边读边等网络。
// 返回实际起读的偏移（判断为轮转过时是 0）；文件不存在返回 nil。
func readEvents(path string, off int64) ([]byte, int64, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if off < 0 || off > st.Size() {
		off = 0
	}
	if off > 0 {
		b := make([]byte, 1)
		if _, err := f.ReadAt(b, off-1); err != nil || b[0] != '\n' {
			off = 0 // 偏移落在行中间：不是记偏移时的那个文件了
		}
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, 0, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 4<<20)) // boot 1 MB 就轮转，这里给足余量
	return data, off, err
}

// detail 带上 boot 记的时间：转发可能晚很久，主控记的是收到的时间。
func detail(ev boot.Event) string {
	if ev.Time == "" {
		return ev.Detail
	}
	return ev.Detail + "（引导器 " + ev.Time + "）"
}
