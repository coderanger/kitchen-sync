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

    CHECKSUMS_PATH = File.expand_path('../kitchen-sync/checksums.rb', __FILE__)
    CHECKSUMS_HASH = Digest::SHA1.file(CHECKSUMS_PATH)
    CHECKSUMS_REMOTE_PATH = File.join('', 'tmp', "checksums-#{CHECKSUMS_HASH}.rb")

    def copy_checksums_script
      return if @checksums_copied
      session.sftp.upload!(CHECKSUMS_PATH, CHECKSUMS_REMOTE_PATH)
      @checksums_copied = true
    end

    def sftp_upload(local, remote, options = {}, &progress)


      copy_checksums_script
      remote = File.join(remote, File.basename(local)) if options[:recursive]
      checksum_cmd = "/opt/chef/embedded/bin/ruby #{CHECKSUMS_REMOTE_PATH} #{remote}"
      logger.info("Running #{checksum_cmd}")
      checksums = JSON.parse(session.exec!(checksum_cmd))
      glob_path = if options[:recursive]
        File.join(local, '**', '*')
      else
        local
      end
      pending = []
      Dir.glob(glob_path, File::FNM_PATHNAME | File::FNM_DOTMATCH).each do |path|
        next unless File.file?(path)
        rel_path = path[local.length..-1]
        remote_hash = checksums[rel_path]
        pending << rel_path unless remote_hash && remote_hash == Digest::SHA1.file(path).hexdigest
      end
      logger.info("Pending transfers for:\n#{pending.map{|s| "  #{s}\n"}.join('')}")
      xfers = []
      while !pending.empty?
        while xfers.length <= 32
          path = pending.pop
          break unless path
          # Check for dirs that need to be created
          parts = path.split(File::SEPARATOR)
          parts.pop # Drop the filename since we are only checking dirs
          parts_to_check = []
          until parts.empty?
            parts_to_check << parts.shift
            path_to_check = File.join(*parts_to_check)
            unless checksums[path_to_check]
              logger.debug("Creating directory #{remote}#{path_to_check}")
              xfers << session.sftp.mkdir("#{remote}#{path_to_check}")
              checksums[path_to_check] = true
            end
          end
          logger.debug("Starting transfer for #{local}#{path} to #{remote}#{path}")
          xfers << session.sftp.upload("#{local}#{path}", "#{remote}#{path}")
        end
        xfers.pop.wait
      end
      xfers.each {|xfer| xfer.wait}
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
