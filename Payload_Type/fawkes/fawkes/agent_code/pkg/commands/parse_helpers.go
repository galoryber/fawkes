package commands

import (
	"encoding/json"
	"reflect"
	"strings"

	"fawkes/pkg/structs"
)

// paramHints returns a summary of expected JSON fields from struct tags.
func paramHints[T any]() string {
	var zero T
	t := reflect.TypeOf(zero)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return ""
	}
	var fields []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		fields = append(fields, name)
	}
	if len(fields) == 0 {
		return ""
	}
	return " (expected fields: " + strings.Join(fields, ", ") + ")"
}

// unmarshalParams is a generic helper that parses JSON task parameters into a typed struct.
func unmarshalParams[T any](task structs.Task) (T, *structs.CommandResult) {
	var args T
	if task.Params == "" {
		return args, nil
	}
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		result := errorf("Error parsing parameters: %v%s", err, paramHints[T]())
		return args, &result
	}
	return args, nil
}

// requireParams is like unmarshalParams but returns an error if params are empty.
func requireParams[T any](task structs.Task) (T, *structs.CommandResult) {
	var args T
	if task.Params == "" {
		result := errorf("Error: parameters required%s", paramHints[T]())
		return args, &result
	}
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		result := errorf("Error parsing parameters: %v%s", err, paramHints[T]())
		return args, &result
	}
	return args, nil
}
