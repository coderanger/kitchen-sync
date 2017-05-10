kitchen-sync
============

Do you wish your test-kitchen runs were faster? Do I ever have the gem for you!

kitchen-sync provides alternate file transfer implementations for test-kitchen,
most of which are faster than the default, thus speeding up your test runs.

Quick Start
-----------

Run `chef gem install kitchen-sync` and then set your transport to `sftp`:

```
transport:
  name: sftp
```

Available Transfer Methods
--------------------------

### `sftp`

The default mode uses SFTP for file transfers, as well as a helper script to
avoid recopying files that are already present on the test host. If SFTP is
disabled, this will automatically fall back to the SCP mode.

By default this will use the Chef omnibus Ruby, you can customize the path to
Ruby via `ruby_path`:

```
transport:
  name: sftp
  ruby_path: /usr/bin/ruby
```

### `rsync`

The Rsync mode is based on the work done by [Mikhail Bautin](https://github.com/test-kitchen/test-kitchen/pull/359).
This is the fastest mode, but it does have a few downsides. The biggest is that
you must be using `ssh-agent` and have an identity loaded for it to use. It also
requires that rsync be available on the remote side. Consider this implementation
more experimental than `sftp` at this time.

Windows Guests
--------------

Windows is not specifically supported at this time, though if you have an SSH
server it will probably work. There is no support for WinRM.

Upgrading from 1.x
------------------

As of version 2.0, kitchen-sync uses Test Kitchen's modular transport system
rather than monkey patch overrides. To upgrade, remove the `<% require 'kitchen-sync' %>`
from your `.kitchen.yml` and add the transport configuration mentioned above.
The `$KITCHEN_SYNC_MODE` environment variable is no longer needed as configuration
can happen in the normal Yaml file.

License
-------

Copyright 2014-2016, Noah Kantrowitz

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
