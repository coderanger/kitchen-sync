#
# Author:: Noah Kantrowitz <noah@coderanger.net>
#
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

# ┻━┻ ︵ヽ(`Д´)ﾉ︵ ┻━┻
module Kitchen
  class SSH

    #old_upload = instance_method(:upload!)
    define_method(:upload!) do |local, remote, options = {}, &progress|
      @kitchen_sync ||= KitchenSync.new(logger, session, @options)
      @kitchen_sync.upload(local, remote, options)
    end

    # Monkey patch the shutdown to tear down the SFTP connection too.
    old_shutdown = instance_method(:shutdown)
    define_method(:shutdown) do
      begin
        @kitchen_sync.shutdown if @kitchen_sync
      ensure
        old_shutdown.bind(self).call
      end
    end

    private

    # Bug fix for session.loop never terminating if there is an SFTP conn active
    # since as far as it is concerned there is still active stuff.
    # This function is Copyright Fletcher Nichol
    def exec_with_exit(cmd)
      exit_code = nil
      session.open_channel do |channel|

        channel.request_pty

        channel.exec(cmd) do |ch, success|

          channel.on_data do |ch, data|
            logger << data
          end

          channel.on_extended_data do |ch, type, data|
            logger << data
          end

          channel.on_request("exit-status") do |ch, data|
            exit_code = data.read_long
          end
        end
      end
      session.loop { !exit_code } # THERE IS A CHANGE ON THIS LINE, PAY ATTENTION!!!!!!
      exit_code
    end
  end

  # Monkey patch to prevent the deletion of everything
  module Provisioner
    class ChefBase < Base
      def init_command
        "mkdir -p #{config[:root_path]}"
      end
    end
  end
end
