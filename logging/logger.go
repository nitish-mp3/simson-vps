package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Level represents log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel converts a string to Level.
func ParseLevel(s string) Level {
	switch s {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// Logger writes structured JSON logs to stdout.
type Logger struct {
	mu    sync.Mutex
	level Level
}

type logEntry struct {
	Time    string         `json:"time"`
	Level   string         `json:"level"`
	Msg     string         `json:"msg"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// New creates a logger at the given level.
func New(level string) *Logger {
	return &Logger{level: ParseLevel(level)}
}

func (l *Logger) log(lvl Level, msg string, fields map[string]any) {
	if lvl < l.level {
		return
	}
	entry := logEntry{
		Time:   time.Now().UTC().Format(time.RFC3339),
		Level:  lvl.String(),
		Msg:    msg,
		Fields: fields,
	}
	data, _ := json.Marshal(entry)
	l.mu.Lock()
	fmt.Fprintln(os.Stdout, string(data))
	l.mu.Unlock()
}

func (l *Logger) Debug(msg string, fields map[string]any) { l.log(LevelDebug, msg, fields) }
func (l *Logger) Info(msg string, fields map[string]any)  { l.log(LevelInfo, msg, fields) }
func (l *Logger) Warn(msg string, fields map[string]any)  { l.log(LevelWarn, msg, fields) }
func (l *Logger) Error(msg string, fields map[string]any) { l.log(LevelError, msg, fields) }
