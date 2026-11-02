package ctl

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
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

// Output formats.
const (
	formatTable = "table"
	formatJSON  = "json"
	formatYAML  = "yaml"
)

func checkFormat(f string) error {
	switch f {
	case formatTable, formatJSON, formatYAML:
		return nil
	}
	return fmt.Errorf("--output must be table, json or yaml, not %q", f)
}

func writeJSON(w io.Writer, msg proto.Message) error {
	b, err := protojson.MarshalOptions{Multiline: true, Indent: "  ", UseProtoNames: true}.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

func writeYAML(w io.Writer, msg proto.Message) error {
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encode yaml: %w", err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("encode yaml: %w", err)
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode yaml: %w", err)
	}
	_, err = w.Write(out)
	return err
}

// render writes msg in the chosen format. table is the human layout; a
// command with no table of its own passes nil, and gets YAML, which reads well.
func (o *options) render(msg proto.Message, table func(io.Writer) error) error {
	switch {
	case o.output == formatJSON:
		return writeJSON(o.streams.Out, msg)
	case o.output == formatYAML || table == nil:
		return writeYAML(o.streams.Out, msg)
	}
	return table(o.streams.Out)
}

// rows writes an aligned table with a header.
func rows(w io.Writer, header []string, body [][]string) error {
	t := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	line := func(cols []string) {
		for i, c := range cols {
			if i > 0 {
				_, _ = fmt.Fprint(t, "\t")
			}
			_, _ = fmt.Fprint(t, c)
		}
		_, _ = fmt.Fprintln(t)
	}
	line(header)
	for _, r := range body {
		line(r)
	}
	return t.Flush()
}
