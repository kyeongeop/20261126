package main

import (
	"fmt"
	"strconv"
)

// parseFlags converts --key value / --key=value style arguments into a map.
func parseFlags(args []string) (map[string]string, error) {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) < 3 || arg[0:2] != "--" {
			return nil, fmt.Errorf("unexpected argument %q", arg)
		}
		name := arg[2:]
		value := ""
		if eq := indexByte(name, '='); eq >= 0 {
			value = name[eq+1:]
			name = name[:eq]
		} else {
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("flag --%s requires a value", name)
			}
			value = args[i]
		}
		out[name] = value
	}
	return out, nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func require(flags map[string]string, names ...string) (map[string]string, error) {
	for _, n := range names {
		if flags[n] == "" {
			return nil, fmt.Errorf("missing required flag --%s", n)
		}
	}
	return flags, nil
}

func optionalInt(flags map[string]string, name string, def int) (int, error) {
	if flags[name] == "" {
		return def, nil
	}
	n, err := strconv.Atoi(flags[name])
	if err != nil || n < 0 {
		return 0, fmt.Errorf("flag --%s must be a non-negative integer", name)
	}
	return n, nil
}
