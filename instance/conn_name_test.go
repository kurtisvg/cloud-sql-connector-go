// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package instance

import "testing"

func TestParseConnName(t *testing.T) {
	tests := []struct {
		name string
		want ConnName
	}{
		{
			name: "project:region:instance",
			want: ConnName{project: "project", region: "region", name: "instance"},
		},
		{
			name: "google.com:project:region:instance",
			want: ConnName{project: "google.com:project", region: "region", name: "instance"},
		},
		{
			name: "project:instance", // missing region
			want: ConnName{},
		},
	}

	for _, tc := range tests {
		c, err := ParseConnName(tc.name)
		if err != nil && tc.want != (ConnName{}) {
			t.Errorf("unexpected error: %e", err)
		}
		if c != tc.want {
			t.Errorf("ParseConnName(%s) failed: want %v, got %v", tc.name, tc.want, c)
		}
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{
			domain: "prod-db.mycompany.example.com",
			want:   true,
		},
		{
			domain: "example.com.", // trailing dot
			want:   true,
		},
		{
			domain: "-example.com", // leading hyphen
			want:   false,
		},
		{
			domain: "example", // missing TLD
			want:   false,
		},
		{
			domain: "127.0.0.1", // IPv4 address
			want:   false,
		},
		{
			domain: "0:0:0:0:0:0:0:1", // IPv6 address
			want:   false,
		},
	}

	for _, tc := range tests {
		v := IsValidDomain(tc.domain)
		if v != tc.want {
			t.Errorf("IsValidDomainName(%s) failed: want %v, got %v", tc.domain, tc.want, v)
		}
	}
}
