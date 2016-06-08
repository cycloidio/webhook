package hook

import (
	"io/ioutil"
	"encoding/json"
	"strings"
)


// Hook type is a structure containing details for a single hook
type Hook struct {
	ID                       string          `json:"id,omitempty"`
	ExecuteCommand           string          `json:"execute-command,omitempty"`
	CommandWorkingDirectory  string          `json:"command-working-directory,omitempty"`
	ResponseMessage          string          `json:"response-message,omitempty"`
	ResponseHeaders          ResponseHeaders `json:"response-headers,omitempty"`
	CaptureCommandOutput     bool            `json:"include-command-output-in-response,omitempty"`
	PassEnvironmentToCommand []Argument      `json:"pass-environment-to-command,omitempty"`
	PassArgumentsToCommand   []Argument      `json:"pass-arguments-to-command,omitempty"`
	JSONStringParameters     []Argument      `json:"parse-parameters-as-json,omitempty"`
	TriggerRule              *Rules          `json:"trigger-rule,omitempty"`
}

// ParseJSONParameters decodes specified arguments to JSON objects and replaces the
// string with the newly created object
func (h *Hook) ParseJSONParameters(headers, query, payload *map[string]interface{}) error {
	for i := range h.JSONStringParameters {
		if arg, ok := h.JSONStringParameters[i].Get(headers, query, payload); ok {
			var newArg map[string]interface{}

			decoder := json.NewDecoder(strings.NewReader(string(arg)))
			decoder.UseNumber()

			err := decoder.Decode(&newArg)

			if err != nil {
				return &ParseError{err}
			}

			var source *map[string]interface{}

			switch h.JSONStringParameters[i].Source {
			case SourceHeader:
				source = headers
			case SourcePayload:
				source = payload
			case SourceQuery:
				source = query
			}

			if source != nil {
				ReplaceParameter(h.JSONStringParameters[i].Name, source, newArg)
			} else {
				return &SourceError{h.JSONStringParameters[i]}
			}
		} else {
			return &ArgumentError{h.JSONStringParameters[i]}
		}
	}

	return nil
}

// ExtractCommandArguments creates a list of arguments, based on the
// PassArgumentsToCommand property that is ready to be used with exec.Command()
func (h *Hook) ExtractCommandArguments(headers, query, payload *map[string]interface{}) ([]string, error) {
	var args = make([]string, 0)

	args = append(args, h.ExecuteCommand)

	for i := range h.PassArgumentsToCommand {
		if arg, ok := h.PassArgumentsToCommand[i].Get(headers, query, payload); ok {
			args = append(args, arg)
		} else {
			args = append(args, "")
			return args, &ArgumentError{h.PassArgumentsToCommand[i]}
		}
	}

	return args, nil
}

// ExtractCommandArgumentsForEnv creates a list of arguments in key=value
// format, based on the PassEnvironmentToCommand property that is ready to be used
// with exec.Command().
func (h *Hook) ExtractCommandArgumentsForEnv(headers, query, payload *map[string]interface{}) ([]string, error) {
	var args = make([]string, 0)

	for i := range h.PassEnvironmentToCommand {
		if arg, ok := h.PassEnvironmentToCommand[i].Get(headers, query, payload); ok {
			args = append(args, EnvNamespace+h.PassEnvironmentToCommand[i].Name+"="+arg)
		} else {
			return args, &ArgumentError{h.PassEnvironmentToCommand[i]}
		}
	}

	return args, nil
}

// Hooks is an array of Hook objects
type Hooks []Hook

// LoadFromFile attempts to load hooks from specified JSON file
func (h *Hooks) LoadFromFile(path string) error {
	if path == "" {
		return nil
	}

	// parse hook file for hooks
	file, e := ioutil.ReadFile(path)

	if e != nil {
		return e
	}

	e = json.Unmarshal(file, h)
	return e
}

// Match iterates through Hooks and returns first one that matches the given ID,
// if no hook matches the given ID, nil is returned
func (h *Hooks) Match(id string) *Hook {
	for i := range *h {
		if (*h)[i].ID == id {
			return &(*h)[i]
		}
	}

	return nil
}

// MatchAll iterates through Hooks and returns all of the hooks that match the
// given ID, if no hook matches the given ID, nil is returned
func (h *Hooks) MatchAll(id string) []*Hook {
	var matchedHooks []*Hook
	for i := range *h {
		if (*h)[i].ID == id {
			matchedHooks = append(matchedHooks, &(*h)[i])
		}
	}

	if len(matchedHooks) > 0 {
		return matchedHooks
	}

	return nil
}

// CommandStatusResponse type encapsulates the executed command exit code, message, stdout and stderr
type CommandStatusResponse struct {
	ResponseMessage string `json:"message,omitempty"`
	Output          string `json:"output,omitempty"`
	Error           string `json:"error,omitempty"`
}
