// Copyright 2021 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package errtypes_test

import (
	"errors"
	"testing"

	"cloud.google.com/go/cloudsqlconn/errtypes"
)

func TestErrorFormatting(t *testing.T) {
	tc := []struct {
		desc string
		err  error
		want string
	}{
		{
			desc: "client error message",
			err:  errtypes.NewConfigError("error message", "proj:reg:inst"),
			want: "Client error: error message (connection name = \"proj:reg:inst\")",
		},
		{
			desc: "refresh error message without internal error",
			err:  errtypes.NewRefreshError("error message", "proj:reg:inst", nil),
			want: "Refresh error: error message (connection name = \"proj:reg:inst\")",
		},
		{
			desc: "refresh error message with internal error",
			err:  errtypes.NewRefreshError("error message", "proj:reg:inst", errors.New("inner-error")),
			want: "Refresh error: error message (connection name = \"proj:reg:inst\"): inner-error",
		},
		{
			desc: "Dial error without inner error",
			err: errtypes.NewDialError(
				"message",
				"proj:reg:inst",
				nil, // no error here
			),
			want: "Dial error: message (connection name = \"proj:reg:inst\")",
		},
		{
			desc: "Dial error with inner error",
			err: errtypes.NewDialError(
				"message",
				"proj:reg:inst",
				errors.New("inner-error"),
			),
			want: "Dial error: message (connection name = \"proj:reg:inst\"): inner-error",
		},
	}

	for _, c := range tc {
		if got := c.err.Error(); got != c.want {
			t.Errorf("%v, got = %q, want = %q", c.desc, got, c.want)
		}
	}
}
