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

require 'benchmark'
require 'digest/sha1'
require 'json'

require 'kitchen/ssh'
require 'kitchen/provisioner/chef_base'
require 'net/sftp'

require 'kitchen-sync/sftp'
require 'kitchen-sync/version'


class KitchenSync
  def initialize(logger, session)
    @logger = logger
    @session = session
    @impl = load_implementation
  end

  def load_implementation(default_mode='sftp')
    mode = ENV['KITCHEN_SYNC_MODE'] || default_mode
    @logger.debug("[sync] Using transfer mode #{mode}")
    case mode
    when 'rsync'
      # TODO
    when 'scp'
      SCP.new(@logger, @session)
    when 'sftp'
      begin
        SFTP.new(@logger, @session)
      rescue Net::SFTP::Exception
        # This means SFTP isn't enabled, fall back to SCP
        @logger.debug("[sync] SFTP unavailable, falling back to SCP")
        SCP.new(@logger, @session) # This could be a smarter SCP at some point
      end
    end
  end

  def upload(local, remote, options)
    # This is set even for single files, so make it something that matters again
    options[:recursive] = File.directory?(local)
    time = Benchmark.realtime do
      @impl.upload(local, remote, options[:recursive])
    end
    @logger.info("[sync] Time taken to upload #{local} to #{@session}:#{remote}: " +
             "%.2f sec" % time)
  end
end

# ┻━┻ ︵ヽ(`Д´)ﾉ︵ ┻━┻
module Kitchen
  class SSH

    #old_upload = instance_method(:upload!)
    define_method(:upload!) do |local, remote, options = {}, &progress|
      KitchenSync.new(logger, session).upload(local, remote, options)
    end

    # Monkey patch the shutdown to tear down the SFTP connection too.
    old_shutdown = instance_method(:shutdown)
    define_method(:shutdown) do
      #require 'pry'; binding.pry
      begin
        if session && !session.sftp.closed?
          logger.debug("[SFTP] closing connection to #{self}")
          session.sftp.close_channel
        end
      ensure
        old_shutdown.bind(self).call
      end
    end

    private

    # Bug fix for session.loop never terminating if there is an SFTP conn active
    # since as far as it is concerned there is still active stuff.
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


    # Copy your SSH identity, creating a new one if needed
    def copy_identity
      return if @copied_identity
      key = Net::SSH::Authentication::Agent.connect.identities.first
      enc_key = Base64.encode64(key.to_blob).gsub("\n", '')
      identitiy = "ssh-rsa #{enc_key} #{key.comment}"
      session.exec <<-EOT
        test -e ~/.ssh || mkdir ~/.ssh
        test -e ~/.ssh/authorized_keys || touch ~/.ssh/authorized_keys
        if ! grep -q "#{identitiy}" ~/.ssh/authorized_keys ; then
          chmod go-w ~ ~/.ssh ~/.ssh/authorized_keys ; \
          echo "#{identitiy}" >> ~/.ssh/authorized_keys
        fi
      EOT
      @copied_identity = true
    end

    def ssh_args
      args = %W{ -o UserKnownHostsFile=/dev/null }
      args += %W{ -o StrictHostKeyChecking=no }
      args += %W{ -o IdentitiesOnly=yes } if options[:keys]
      args += %W{ -o LogLevel=#{logger.debug? ? "VERBOSE" : "ERROR"} }
      args += %W{ -o ForwardAgent=#{options[:forward_agent] ? "yes" : "no"} } if options.key? :forward_agent
      Array(options[:keys]).each { |ssh_key| args += %W{ -i #{ssh_key}} }
      args += %W{ -p #{port}}
    end

    def rsync_upload(local, remote, options = {}, &progress)
      upload_done = false
      if !@rsync_failed &&
         File.directory?(local) && options[:recursive] &&
         File.exists?('/usr/bin/rsync')
        ssh_command = "ssh #{ssh_args.join(' ')}"
        copy_identity
        rsync_cmd = "/usr/bin/rsync -e '#{ssh_command}' -az #{local} #{username}@#{hostname}:#{remote}"
        logger.info("Running rsync command: #{rsync_cmd}")
        if system(rsync_cmd)
          upload_done = true
        else
          logger.warn("rsync exited with status #{$?.exitstatus}, using Net::SCP instead")
          @rsync_failed = true
        end
      end

      unless upload_done
        if progress.nil?
          progress = lambda { |ch, name, sent, total|
            if sent == total
              logger.debug("Uploaded #{name} (#{total} bytes)")
            end
          }
        end

        session.scp.upload!(local, remote, options, &progress)
      end
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
