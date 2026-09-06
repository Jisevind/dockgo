package stacks

import "bytes"

// StreamWriter buffers bytes and emits complete lines to the callback.
type StreamWriter struct {
	cb  func(string)
	buf []byte
}

// NewStreamWriter creates a StreamWriter that emits each complete line to the
// callback.
func NewStreamWriter(cb func(string)) *StreamWriter {
	return &StreamWriter{cb: cb}
}

// Write buffers bytes and emits complete lines to the callback.
func (sw *StreamWriter) Write(p []byte) (n int, err error) {
	sw.buf = append(sw.buf, p...)

	for {
		idx := bytes.IndexByte(sw.buf, '\n')
		if idx == -1 {
			break
		}

		line := sw.buf[:idx]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		sw.cb(string(line))

		sw.buf = sw.buf[idx+1:]
	}

	return len(p), nil
}
