#
# Author:: Noah Kantrowitz <noah@coderanger.net>
#
# Copyright 2013-2014, Fletcher Nichol
# Copyright 2014, Noah Kantrowitz
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'kitchen-sync/base'

require 'net/scp'

class KitchenSync
  class SCP < Base
    def upload(local, remote, recursive=true)
      true_remote = File.join(remote, File.basename(local))
      @session.exec!("rm -rf #{true_remote}")
      @session.scp.upload!(local, remote, recursive: recursive) do |ch, name, sent, total|
        if sent == total
          @logger.debug("Uploaded #{name} (#{total} bytes)")
        end
      end
    end
  end
end
