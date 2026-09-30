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

// Command errorcodes prints the manager's error-code table, so the committed
// docs/error-codes.md is generated rather than maintained by hand (#64).
//
//	go run ./tools/errorcodes > docs/error-codes.md
//
// TestErrorCodesDocIsCurrent fails if the committed file drifts from this.
import (
	"fmt"

	"github.com/CryptOS-PKI/manager/internal/apperr"
)

func main() {
	fmt.Print(apperr.Doc())
}
