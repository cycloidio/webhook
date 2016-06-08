package hook

import (
	"fmt"
	"strings"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"reflect"
	"strconv"
	"encoding/json"
)

// Constants used to specify the parameter source
const (
	SourceHeader        string = "header"
	SourceQuery         string = "url"
	SourcePayload       string = "payload"
	SourceString        string = "string"
	SourceEntirePayload string = "entire-payload"
	SourceEntireQuery   string = "entire-query"
	SourceEntireHeaders string = "entire-headers"
)

const (
	// EnvNamespace is the prefix used for passing arguments into the command
	// environment.
	EnvNamespace string = "HOOK_"
)

// SignatureError describes an invalid payload signature passed to Hook.
type SignatureError struct {
	Signature string
}

func (e *SignatureError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("invalid payload signature %s", e.Signature)
}

// ArgumentError describes an invalid argument passed to Hook.
type ArgumentError struct {
	Argument Argument
}

func (e *ArgumentError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("couldn't retrieve argument for %+v", e.Argument)
}

// SourceError describes an invalid source passed to Hook.
type SourceError struct {
	Argument Argument
}

func (e *SourceError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("invalid source for argument %+v", e.Argument)
}

// ParseError describes an error parsing user input.
type ParseError struct {
	Err error
}

func (e *ParseError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Err.Error()
}

// CheckPayloadSignature calculates and verifies SHA1 signature of the given payload
func CheckPayloadSignature(payload []byte, secret string, signature string) (string, error) {
	if strings.HasPrefix(signature, "sha1=") {
		signature = signature[5:]
	}

	mac := hmac.New(sha1.New, []byte(secret))
	_, err := mac.Write(payload)
	if err != nil {
		return "", err
	}
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedMAC)) {
		return expectedMAC, &SignatureError{expectedMAC}
	}
	return expectedMAC, err
}

// ReplaceParameter replaces parameter value with the passed value in the passed map
// (please note you should pass pointer to the map, because we're modifying it)
// based on the passed string
func ReplaceParameter(s string, params interface{}, value interface{}) bool {
	if params == nil {
		return false
	}

	if paramsValue := reflect.ValueOf(params); paramsValue.Kind() == reflect.Slice {
		if paramsValueSliceLength := paramsValue.Len(); paramsValueSliceLength > 0 {

			if p := strings.SplitN(s, ".", 2); len(p) > 1 {
				index, err := strconv.ParseUint(p[0], 10, 64)

				if err != nil || paramsValueSliceLength <= int(index) {
					return false
				}

				return ReplaceParameter(p[1], params.([]interface{})[index], value)
			}
		}

		return false
	}

	if p := strings.SplitN(s, ".", 2); len(p) > 1 {
		if pValue, ok := params.(map[string]interface{})[p[0]]; ok {
			return ReplaceParameter(p[1], pValue, value)
		}
	} else {
		if _, ok := (*params.(*map[string]interface{}))[p[0]]; ok {
			(*params.(*map[string]interface{}))[p[0]] = value
			return true
		}
	}

	return false
}

// GetParameter extracts interface{} value based on the passed string
func GetParameter(s string, params interface{}) (interface{}, bool) {
	if params == nil {
		return nil, false
	}

	if paramsValue := reflect.ValueOf(params); paramsValue.Kind() == reflect.Slice {
		if paramsValueSliceLength := paramsValue.Len(); paramsValueSliceLength > 0 {

			if p := strings.SplitN(s, ".", 2); len(p) > 1 {
				index, err := strconv.ParseUint(p[0], 10, 64)

				if err != nil || paramsValueSliceLength <= int(index) {
					return nil, false
				}

				return GetParameter(p[1], params.([]interface{})[index])
			}

			index, err := strconv.ParseUint(s, 10, 64)

			if err != nil || paramsValueSliceLength <= int(index) {
				return nil, false
			}

			return params.([]interface{})[index], true
		}

		return nil, false
	}

	if p := strings.SplitN(s, ".", 2); len(p) > 1 {
		if paramsValue := reflect.ValueOf(params); paramsValue.Kind() == reflect.Map {
			if pValue, ok := params.(map[string]interface{})[p[0]]; ok {
				return GetParameter(p[1], pValue)
			}
		} else {
			return nil, false
		}
	} else {
		if pValue, ok := params.(map[string]interface{})[p[0]]; ok {
			return pValue, true
		}
	}

	return nil, false
}

// ExtractParameterAsString extracts value from interface{} as string based on the passed string
func ExtractParameterAsString(s string, params interface{}) (string, bool) {
	if pValue, ok := GetParameter(s, params); ok {
		return fmt.Sprintf("%v", pValue), true
	}
	return "", false
}

// Argument type specifies the parameter key name and the source it should
// be extracted from
type Argument struct {
	Source string `json:"source,omitempty"`
	Name   string `json:"name,omitempty"`
}

// Get Argument method returns the value for the Argument's key name
// based on the Argument's source
func (ha *Argument) Get(headers, query, payload *map[string]interface{}) (string, bool) {
	var source *map[string]interface{}

	switch ha.Source {
	case SourceHeader:
		source = headers
	case SourceQuery:
		source = query
	case SourcePayload:
		source = payload
	case SourceString:
		return ha.Name, true
	case SourceEntirePayload:
		r, err := json.Marshal(payload)

		if err != nil {
			return "", false
		}

		return string(r), true
	case SourceEntireHeaders:
		r, err := json.Marshal(headers)

		if err != nil {
			return "", false
		}

		return string(r), true
	case SourceEntireQuery:
		r, err := json.Marshal(query)

		if err != nil {
			return "", false
		}

		return string(r), true
	}

	if source != nil {
		return ExtractParameterAsString(ha.Name, *source)
	}

	return "", false
}
