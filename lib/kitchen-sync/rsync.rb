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

require 'kitchen-sync/scp'

class KitchenSync
  class Rsync < SCP
    def upload(local, remote, recursive=true)
      upload_done = false
      if !@rsync_failed && recursive && File.exists?('/usr/bin/rsync')
        ssh_command = "ssh #{ssh_args.join(' ')}"
        ssh_identity ||= ENV["KITCHEN_SYNC_IDENTITY"].to_i
        if ssh_identity
          ssh_identity_key = `ssh-add -l`.split("\n")[ssh_identity]
          @logger.info("[sync:rsync] Using SSH identity ##{ssh_identity} key => #{ssh_identity_key}.")
          copy_identity(ssh_identity)
        else
          @logger.info("[sync:rsync] Using default ssh_config IdentityFile configuration.")
        end
        rsync_cmd = "/usr/bin/rsync -e '#{ssh_command}' -az #{local} #{@session.options[:user]}@#{@session.host}:#{remote}"
        @logger.info("[sync:rsync] Running rsync command: #{rsync_cmd}")
        if system(rsync_cmd)
          upload_done = true
        else
          @logger.warn("[sync:rsync] rsync exited with status #{$?.exitstatus}, using Net::SCP instead")
          @rsync_failed = true
        end
      end

      # Fall back to SCP
      super unless upload_done
    end

    # Copy your SSH identity, creating a new one if needed
    def copy_identity(ssh_identity)
      return if @copied_identity
      key = Net::SSH::Authentication::Agent.connect.identities[ssh_identity]
      if key
        enc_key = Base64.encode64(key.to_blob).gsub("\n", '')
        identitiy = "ssh-rsa #{enc_key} #{key.comment}"
        @session.exec! <<-EOT
          test -e ~/.ssh || mkdir ~/.ssh
          test -e ~/.ssh/authorized_keys || touch ~/.ssh/authorized_keys
          if ! grep -q "#{identitiy}" ~/.ssh/authorized_keys ; then
            chmod go-w ~ ~/.ssh ~/.ssh/authorized_keys ; \
            echo "#{identitiy}" >> ~/.ssh/authorized_keys
          fi
        EOT
        @copied_identity = true
        @logger.info("[sync:rsync] Successfully copied SSH identity ##{ssh_identity}.")
      else
        @logger.warn("[sync:rsync] Failed to copy SSH identity ##{ssh_identity}.\
          Falling back to default ssh_config IdentityFile configuration")
      end
    end

    def ssh_args
      args = %W{ -o UserKnownHostsFile=/dev/null }
      args += %W{ -o StrictHostKeyChecking=no }
      args += %W{ -o IdentitiesOnly=yes } if @options[:keys]
      args += %W{ -o LogLevel=#{@logger.debug? ? "VERBOSE" : "ERROR"} }
      args += %W{ -o ForwardAgent=#{options[:forward_agent] ? "yes" : "no"} } if @options.key? :forward_agent
      Array(@options[:keys]).each { |ssh_key| args += %W{ -i #{ssh_key}} }
      args += %W{ -p #{@session.options[:port]}}
    end
  end
end
