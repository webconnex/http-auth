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
	"testing"
)

func TestBasic(t *testing.T) {
	auth, err := Parse("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
	if err != nil {
		t.Fatal(err)
	}
	if auth.Scheme != "Basic" {
		t.Fatalf(`Expected "Basic" but got %q`, auth.Scheme)
	}
	username, password, err := ParseBasic(auth.RawValue)
	if err != nil {
		t.Fatal(err)
	}
	if username != "Aladdin" {
		t.Fatalf(`Expected "Aladdin" but got %q`, username)
	}
	if password != "open sesame" {
		t.Fatalf(`Expected "open sesame" but got %q`, username)
	}
}

func TestValues(t *testing.T) {
	auth, err := Parse(`Digest username="Mufasa",
	                           realm="testrealm@host.com",
	                           nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
	                           uri="/dir/index.html",
	                           qop=auth,
	                           nc=00000001,
	                           cnonce="0a4f113b",
	                           response="6629fae49393a05397450978507c4ef1",
	                           opaque="5ccc069c403ebaf9f0171e9517f40e41"`)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Scheme != "Digest" {
		t.Fatalf(`Expected "Digest" but got %q`, auth.Scheme)
	}
	values, err := ParseValues(auth.RawValue)
	if err != nil {
		t.Fatal(err)
	}
	if num := len(values); num != 9 {
		t.Fatalf(`Expected 9 values but got %d`, num)
	}
	if v := values["username"]; v != "Mufasa" {
		t.Fatalf(`Expected "Mufasa" but got %q`, v)
	}
	if v := values["qop"]; v != "auth" {
		t.Fatalf(`Expected "auth" but got %q`, v)
	}
}
