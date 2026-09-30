package main

/*
Apache License 2.0

Copyright 2026 Shane

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
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/CryptOS-PKI/manager/internal/authz"
)

// run encodes the access-level extension value for the given level token and
// writes it as a YAML byte sequence (e.g. "[19, 5, 97, 100, 109, 105, 110]")
// to w. This is the form a cryptos profile's extra_extensions value takes: the
// field is a Go []byte, which yaml.v3 decodes from a sequence of byte integers
// (it does not base64-decode a scalar into []byte).
func run(level string, w io.Writer) error {
	_, value, err := authz.MarshalLevelExtension(level)
	if err != nil {
		return err
	}
	parts := make([]string, len(value))
	for i, b := range value {
		parts[i] = strconv.Itoa(int(b))
	}
	_, err = fmt.Fprintf(w, "[%s]\n", strings.Join(parts, ", "))
	return err
}

func main() {
	level := flag.String("level", "", "access level: viewer|operator|admin")
	flag.Parse()
	if err := run(*level, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "opext:", err)
		os.Exit(1)
	}
}
