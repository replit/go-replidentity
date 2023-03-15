// Package repl contains additional implementations on top of the protobuf default
package repl

import (
	"fmt"
	"strconv"
	"strings"
)

// MarshalText implements the encoding.TextMarshaler interface
func (u *UserId) MarshalText() (text []byte, err error) {
	out := fmt.Sprintf("%d:%d", u.GetId(), u.GetEnvironment())
	return []byte(out), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (u *UserId) UnmarshalText(text []byte) error {
	strtxt := string(text)

	if strtxt == "null" {
		return nil
	}

	split := strings.Index(strtxt, ":")
	if split == -1 {
		return fmt.Errorf("cannot unmarshal UserId from %s", strtxt)
	}

	id, err := strconv.ParseInt(strtxt[:split], 10, 64)
	if err != nil {
		return fmt.Errorf("cannot unmarshal UserID: %w", err)
	}
	u.Id = id

	env, err := strconv.ParseInt(strtxt[split+1:], 10, 32)
	if err != nil {
		return fmt.Errorf("cannot unmarshal UserID: %w", err)
	}
	u.Environment = Environment(env)

	return nil
}
