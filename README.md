# FLDR L7 denial-of-service testing toolkit

:warning: This repository is purely for educational and/or proof-of-concept purposes! :warning:
I am **not** responsible for any legal trouble caused by this program (as described in LICENSE).

## Installation

```
$ go build -ldflags "-X main.postbackBase=https://example.org"
```

Go should automagically download all needed dependencies :sparkles: :package:  
...and build a file named "fldr" compatible with your OS and arch.

`https://example.org` should be a URL pointing to the root of an `fldr-bouncer` instance.

## Usage

`./fldr [threads] [supervisor count]`

Final thread count = threads * supervisor count

## License

```
FLDR L7 denial-of-service testing toolkit
Copyright (C) 2021 Matthew Coal

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
