package operatorca

/*
Copyright The CryptOS Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"errors"
	"unicode"
	"unicode/utf8"
)

const maxFullNameLength = 128

// ValidateFullName checks an operator's full name: 1 to 128 characters of
// valid UTF-8 with no control characters.
func ValidateFullName(name string) error {
	if !utf8.ValidString(name) {
		return errors.New("operatorca: the full name is not valid UTF-8")
	}
	if n := utf8.RuneCountInString(name); n < 1 || n > maxFullNameLength {
		return errors.New("operatorca: the full name must be 1 to 128 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("operatorca: the full name must not contain control characters")
		}
	}
	return nil
}
