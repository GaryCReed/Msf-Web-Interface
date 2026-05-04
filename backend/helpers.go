package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

func parseJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func encodeJSON(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	return string(data), err
}

func decodeJSON(data string, v interface{}) error {
	return json.Unmarshal([]byte(data), v)
}

// shellQuoteArgs returns a shell-safe representation of args for display.
// Args containing shell-special characters are wrapped in single quotes.
func shellQuoteArgs(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " \t&|;()<>\"'`$\\!^{}") {
			quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			quoted[i] = a
		}
	}
	return strings.Join(quoted, " ")
}
