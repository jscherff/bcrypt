// Copyright 2017 John Scherff
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

package main

import (
	`flag`
	`golang.org/x/crypto/bcrypt`
)

var (
	fReader = flag.String(`in`, ``, `Source file for cleartext data (default stdin)`)
	fWriter = flag.String(`out`, ``, `Destination file for hash results (default stdout)`)
	fLogfile = flag.String(`log`, ``, `Destination file for log messages (default stderr)`)
	fCost = flag.Int(`cost`, bcrypt.DefaultCost, `Bcrypt hash key expansion cost`)
	fWorkers = flag.Int(`workers`, 10, `Number of concurrent worker routines`)
	fQueue = flag.Int(`queue`, 1000, `Maximum length of worker input queues`)
)
