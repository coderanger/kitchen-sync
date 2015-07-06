#
# Author:: Ilja Bobkevic <ilja.bobkevi@unibet.com>
#
# Copyright 2015, North Development AB
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

require 'kitchen/transport/ssh'

module Kitchen
  module Transport
    class Sshtar < Ssh

      def create_new_connection(options, &block)
        if @connection
          logger.debug("[SSH] shutting previous connection #{@connection}")
          @connection.close
        end

        @connection_options = options
        @connection = self.class::Connection.new(options, &block)
      end

      class Connection < Ssh::Connection
        def upload(locals, remote)
          Array(locals).each do |local|
            full_remote = File.join(remote, File.basename(local))
            recursive = File.directory?(local)
            execute("mkdir -p #{full_remote}") if recursive
            time = Benchmark.realtime do
              tar_command = "tar -C #{local} -c#{@logger.debug? ? 'v' : ''}f - ./"
              untar_command = "tar --warning=no-unknown-keyword -C #{full_remote} -x#{@logger.debug? ? 'v' : ''}f -"
              ssh_command = [login_command.command, login_command.arguments].flatten.join(' ')
              sync_command = "#{tar_command} | #{ssh_command} '#{untar_command}'"
              @logger.debug("[SSH-TAR] Running ssh-tar command: #{sync_command}")
              system(sync_command)
            end
            logger.info("[SSH-TAR] Time taken to upload #{local} to #{self}:#{full_remote}: %.2f sec" % time)
          end
        end
      end

    end
  end
end