package hook

import "regexp"

// Rules is a structure that contains one of the valid rule types
type Rules struct {
	And   *AndRule   `json:"and,omitempty"`
	Or    *OrRule    `json:"or,omitempty"`
	Not   *NotRule   `json:"not,omitempty"`
	Match *MatchRule `json:"match,omitempty"`
}

// Evaluate finds the first rule property that is not nil and returns the value
// it evaluates to
func (r Rules) Evaluate(headers, query, payload *map[string]interface{}, body *[]byte) (bool, error) {
	switch {
	case r.And != nil:
		return r.And.Evaluate(headers, query, payload, body)
	case r.Or != nil:
		return r.Or.Evaluate(headers, query, payload, body)
	case r.Not != nil:
		return r.Not.Evaluate(headers, query, payload, body)
	case r.Match != nil:
		return r.Match.Evaluate(headers, query, payload, body)
	}

	return false, nil
}

// AndRule will evaluate to true if and only if all of the ChildRules evaluate to true
type AndRule []Rules

// Evaluate AndRule will return true if and only if all of ChildRules evaluate to true
func (r AndRule) Evaluate(headers, query, payload *map[string]interface{}, body *[]byte) (bool, error) {
	res := true

	for _, v := range r {
		rv, err := v.Evaluate(headers, query, payload, body)
		if err != nil {
			return false, err
		}

		res = res && rv
		if res == false {
			return res, nil
		}
	}

	return res, nil
}

// OrRule will evaluate to true if any of the ChildRules evaluate to true
type OrRule []Rules

// Evaluate OrRule will return true if any of ChildRules evaluate to true
func (r OrRule) Evaluate(headers, query, payload *map[string]interface{}, body *[]byte) (bool, error) {
	res := false

	for _, v := range r {
		rv, err := v.Evaluate(headers, query, payload, body)
		if err != nil {
			return false, err
		}

		res = res || rv
		if res == true {
			return res, nil
		}
	}

	return res, nil
}

// NotRule will evaluate to true if any and only if the ChildRule evaluates to false
type NotRule Rules

// Evaluate NotRule will return true if and only if ChildRule evaluates to false
func (r NotRule) Evaluate(headers, query, payload *map[string]interface{}, body *[]byte) (bool, error) {
	rv, err := Rules(r).Evaluate(headers, query, payload, body)
	return !rv, err
}

// MatchRule will evaluate to true based on the type
type MatchRule struct {
	Type      string   `json:"type,omitempty"`
	Regex     string   `json:"regex,omitempty"`
	Secret    string   `json:"secret,omitempty"`
	Value     string   `json:"value,omitempty"`
	Parameter Argument `json:"parameter,omitempty"`
}

// Constants for the MatchRule type
const (
	MatchValue    string = "value"
	MatchRegex    string = "regex"
	MatchHashSHA1 string = "payload-hash-sha1"
)

// Evaluate MatchRule will return based on the type
func (r MatchRule) Evaluate(headers, query, payload *map[string]interface{}, body *[]byte) (bool, error) {
	if arg, ok := r.Parameter.Get(headers, query, payload); ok {
		switch r.Type {
		case MatchValue:
			return arg == r.Value, nil
		case MatchRegex:
			return regexp.MatchString(r.Regex, arg)
		case MatchHashSHA1:
			_, err := CheckPayloadSignature(*body, r.Secret, arg)
			return err == nil, err
		}
	}
	return false, nil
}


