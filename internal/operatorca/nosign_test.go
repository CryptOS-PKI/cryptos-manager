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
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The Fleet Manager never signs an operator credential. These scans pin
// that down across every non-test Go file in internal/ and cmd/.

// signingAllowList is where the manager may create a certificate at all: its
// own self-signed server certificate and the node-admin pin certificate it
// mints for adopted nodes. Neither may be a CA.
var signingAllowList = map[string]bool{
	"cmd/manager/selfsigned.go":         true,
	"internal/fleet/adopt_bootstrap.go": true,
}

type goFile struct {
	rel  string
	file *ast.File
}

func sourceFiles(t *testing.T) []goFile {
	t.Helper()
	root := filepath.Join("..", "..")
	var out []goFile
	fset := token.NewFileSet()
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			out = append(out, goFile{rel: filepath.ToSlash(rel), file: f})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if len(out) < 50 {
		t.Fatalf("found only %d source files; the scan isn't looking in the right place", len(out))
	}
	return out
}

func selectorName(e ast.Expr) (pkg, name string) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", sel.Sel.Name
	}
	return id.Name, sel.Sel.Name
}

func TestNoSigning_CreateCertificateOnlyInTheAllowList(t *testing.T) {
	found := map[string]bool{}
	for _, f := range sourceFiles(t) {
		ast.Inspect(f.file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				switch pkg, name := selectorName(n.Fun); {
				case pkg == "x509" && name == "CreateCertificate":
					found[f.rel] = true
					if !signingAllowList[f.rel] {
						t.Errorf("%s calls x509.CreateCertificate outside the allow list", f.rel)
					}
				case pkg == "x509" && name == "CreateRevocationList":
					t.Errorf("%s calls x509.CreateRevocationList; the manager never signs a CRL", f.rel)
				}
			case *ast.KeyValueExpr:
				if k, ok := n.Key.(*ast.Ident); ok && k.Name == "IsCA" {
					if v, ok := n.Value.(*ast.Ident); !ok || v.Name != "false" {
						t.Errorf("%s sets IsCA to something other than false", f.rel)
					}
				}
			}
			return true
		})
	}
	for rel := range signingAllowList {
		if !found[rel] {
			t.Errorf("%s is allow-listed but no longer calls x509.CreateCertificate; drop it from the list", rel)
		}
	}
}

func TestNoSigning_NoOperatorProfileIssuance(t *testing.T) {
	for _, f := range sourceFiles(t) {
		ast.Inspect(f.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if _, name := selectorName(call.Fun); name != "IssueLeaf" {
				return true
			}
			for _, arg := range call.Args {
				ast.Inspect(arg, func(n ast.Node) bool {
					if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if s, err := strconv.Unquote(lit.Value); err == nil && strings.HasPrefix(s, "operator-") {
							t.Errorf("%s calls IssueLeaf with an operator- profile (%q)", f.rel, s)
						}
					}
					return true
				})
			}
			return true
		})
	}
}
