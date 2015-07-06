kitchen-sync
============

Do you wish your test-kitchen runs were faster? Do I ever have the gem for you!

kitchen-sync provides alternate file transfer implementations for test-kitchen,
most of which are faster than the default, thus speeding up your test runs.

Quick Start
-----------

Add `gem 'kitchen-sync'` to your Gemfile and then at the top of your
`.kitchen.yml`:

```
#<% require 'kitchen-sync' %>
```

Available Transfer Methods
--------------------------

You can select the transfer mode using the `KITCHEN_SYNC_MODE` environment
variable. If not present, it defaults to `sftp`.

### SFTP

The default mode uses SFTP for file transfers, as well as a helper script to
avoid recopying files that are already present on the test host. If SFTP is
disabled, this will automatically fall back to the SCP mode.

### SCP

The SCP mode is just a copy of the implementation from test-kitchen. It is
present as a fallback and for benchmark comparisons, and generally won't be
used directly.

### Rsync

The rsync mode is based on the work done by [Mikhail Bautin](https://github.com/test-kitchen/test-kitchen/pull/359).
This is the fastest mode, but it does have a few downsides. The biggest is that
you must be using `ssh-agent` and have an identity loaded for it to use. It also
requires that rsync be available on the remote side. Consider this implementation
more experimental than the others at this time.

### SSH-Tar

SSH-Tar mode is based on piping native ssh and tar commands, so that all files are
transferred as a single ssh stream providing dramatic performance improvements.
This transport will only work with TK 1.4 and *nix like systems with mentioned
binaries available in the PATH.

.kitchen.yml snippet to activate SSH-Tar transport:
```
transport:
  name: sshtar
```

License
-------

Copyright 2014, Noah Kantrowitz

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
