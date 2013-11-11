// Copyright 2013 Webconnex, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
)

type Auth struct {
	Scheme   string
	RawValue string
}

func Parse(s string) (*Auth, error) {
	offset, err := nextToken(s, 0, false)
	if err != nil {
		return nil, err
	}
	scheme, err := readToken(s, offset)
	if err != nil {
		return nil, err
	}
	offset, err = nextToken(s, offset+len(scheme), false)
	if err != nil {
		return nil, err
	}
	return &Auth{string(scheme), string(s[offset:])}, nil
}

func (a *Auth) Values() Values {
	v, _ := ParseValues(a.RawValue)
	return v
}

func (a *Auth) Basic() (username, password string) {
	username, password, _ = ParseBasic(a.RawValue)
	return
}

func ParseBasic(s string) (string, string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", "", nil
	}
	p := bytes.SplitN(b, []byte{':'}, 2)
	if len(p) < 2 {
		return "", "", errors.New("unknown credential format")
	}
	return string(p[0]), string(p[1]), nil
}

type Values map[string]string

func ParseValues(s string) (m Values, err error) {
	m = make(Values)
	err = parseValues(m, s, 0)
	return
}

func (v Values) Encode() string {
	if v == nil {
		return ""
	}
	buf := make([]byte, 0, 64)
	for key, value := range v {
		if len(buf) > 0 {
			buf = append(buf, ',', ' ')
		}
		buf = append(buf, key...)
		buf = append(buf, '=', '"')
		buf = append(buf, value...)
		buf = append(buf, '"')
	}
	return string(buf)
}

func nextToken(s string, offset int, comma bool) (int, error) {
	var i = offset
	var err error
	var commas = 0
Loop:
	for length := len(s); i < length; i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':

		case ',':
			if !comma || commas > 0 {
				err = errors.New("unexpected ','" +
					" at position " + strconv.Itoa(i))
				break Loop
			}
			commas++
		case '(', ')', '<', '>', '@',
			';', ':', '\\', '"', '/',
			'[', ']', '?', '=', '{', '}':
			err = errors.New("unexpected '" + string(s[i]) +
				"' at position " + strconv.Itoa(i))
			break Loop
		default:
			if s[i] < ' ' || s[i] >= 127 {
				err = errors.New("invalid char at position " + strconv.Itoa(i))
			}
			break Loop
		}
	}
	return i, err
}

func readToken(s string, offset int) (string, error) {
	var i = offset
	var err error
Loop:
	for length := len(s); i < length; i++ {
		c := s[i]
		switch c {
		case '(', ')', '<', '>', '@',
			',', ';', ':', '\\', '"',
			'/', '[', ']', '?', '=',
			'{', '}', ' ', '\t',
			'\r', '\n':
			break Loop
		default:
			if c < ' ' || c >= 127 {
				err = errors.New("invalid char at position " + strconv.Itoa(i))
				break Loop
			}
		}
	}
	if err != nil {
		return "", err
	}
	return s[offset:i], nil
}

func readQuoted(s string, offset int) (string, error) {
	var i = offset
	var err error
	var escape bool
	if s[i] != '"' {
		return "", errors.New("unexpected '" +
			string(s[i]) + "' at position " +
			strconv.Itoa(i) + " expecting '\"'")
	}
	i += 1
	for length := len(s); i < length; i++ {
		c := s[i]
		if escape && c <= 127 {
			escape = true
			continue
		}
		if c == 127 || (c < ' ' && c != '\t' && c != '\r' && c != '\n') {
			err = errors.New("invalid char at position " + strconv.Itoa(i))
			break
		} else if c == '"' {
			break
		} else if c == '\\' {
			escape = true
		}
	}
	if s[i] != '"' {
		return "", errors.New("expecting '\"' but reached end")
	}
	if err != nil {
		return "", err
	}
	return s[offset+1 : i], nil
}

func parseValues(m Values, s string, offset int) error {
	var i int = offset
	var err error
	for length := len(s); ; {
		// Skip empty space and eat comma
		i, err = nextToken(s, i, i != 0)
		if err != nil {
			break
		}
		if i == length {
			break
		}
		// Read name token
		var name string
		name, err = readToken(s, i)
		if err != nil {
			break
		}
		i += len(name)
		// Eat expected '='
		if s[i] != '=' {
			err = errors.New("unexpected '" + string(s[i]) +
				"' expecting '=' at position " + strconv.Itoa(i))
			break
		}
		i += 1
		// Read value token or quoted string
		var value string
		if s[i] == '"' {
			value, err = readQuoted(s, i)
			i += 2
		} else {
			value, err = readToken(s, i)
		}
		if err != nil {
			break
		}
		m[name] = value
		i += len(value)
	}
	return err
}
