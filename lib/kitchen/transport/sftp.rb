#
# Copyright 2014-2016, Noah Kantrowitz
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

require 'kitchen/transport/ssh'
require 'net/sftp'

require 'kitchen-sync/core_ext'


module Kitchen
  module Transport
    class Sftp < Ssh
      CHECKSUMS_PATH = File.expand_path('../../../kitchen-sync/checksums.rb', __FILE__)
      CHECKSUMS_HASH = Digest::SHA1.file(CHECKSUMS_PATH)
      CHECKSUMS_REMOTE_PATH = "/tmp/checksums-#{CHECKSUMS_HASH}.rb" # This won't work on Windows targets
      MAX_TRANSFERS = 64

      default_config :ruby_path, '/opt/chef/embedded/bin/ruby'

      def finalize_config!(instance)
        super.tap do
          if defined?(Kitchen::Verifier::Inspec) && instance.verifier.is_a?(Kitchen::Verifier::Inspec)
            instance.verifier.send(:define_singleton_method, :runner_options_for_sftp) do |config_data|
              runner_options_for_ssh(config_data)
            end
          end
        end
      end

      # Copy-pasta from Ssh#create_new_connection because I need the SFTP
      # connection class.
      # Tracked in https://github.com/test-kitchen/test-kitchen/pull/726
      def create_new_connection(options, &block)
        if @connection
          logger.debug("[SSH] shutting previous connection #{@connection}")
          @connection.close
        end

        @connection_options = options
        @connection = self.class::Connection.new(config, options, &block)
      end

      class Connection < Ssh::Connection
        def initialize(config, options, &block)
          @config = config
          super(options, &block)
        end

        # Wrap Ssh::Connection#close to also shut down the SFTP connection.
        def close
          if @sftp_session
            logger.debug("[SFTP] closing connection to #{self}")
            begin
              sftp_session.close_channel
            rescue Net::SSH::Disconnect
              # Welp, we tried.
            rescue IOError
              # Can happen with net-ssh 4.x, no idea why.
              # See https://github.com/net-ssh/net-ssh/pull/493
            end
          end
        ensure
          @sftp_session = nil
          # Make sure we can turn down the session even if closing the channels
          # fails in the middle because of a remote disconnect.
          saved_session = @session
          begin
            super
          rescue Net::SSH::Disconnect
            # Boooo zlib warnings.
            saved_session.transport.close if saved_session
          end
        end

        def upload(locals, remote)
          Array(locals).each do |local|
            full_remote = File.join(remote, File.basename(local))
            options = {
              recursive: File.directory?(local),
              purge: File.basename(local) != 'cache',
            }
            recursive = File.directory?(local)
            time = Benchmark.realtime do
              sftp_upload!(local, full_remote, options)
            end
            logger.info("[SFTP] Time taken to upload #{local} to #{self}:#{full_remote}: %.2f sec" % time)
          end
        end

        private

        def sftp_upload!(local, remote, recursive: true, purge: true)
          # Fast path check, if the remote path doesn't exist at all we just run a direct transfer
          unless safe_stat(remote)
            logger.debug("[SFTP] Fast path upload from #{local} to #{remote}")
            sftp_session.mkdir!(remote) if recursive
            sftp_session.upload!(local, remote, requests: MAX_TRANSFERS)
            return
          end
          # Get checksums for existing files on the remote side.
          logger.debug("[SFTP] Slow path upload from #{local} to #{remote}")
          copy_checksums_script!
          checksum_cmd = "#{@config[:ruby_path]} #{CHECKSUMS_REMOTE_PATH} #{remote}"
          logger.debug("[SFTP] Running #{checksum_cmd}")
          checksums = JSON.parse(session.exec!(checksum_cmd))
          # Sync files that have changed.
          files_to_upload(checksums, local, recursive).each do |rel_path|
            upload_file(checksums, local, remote, rel_path)
          end
          purge_files(checksums, remote) if purge
          # Wait until all xfers are complete.
          sftp_loop(0)
        end

        # Bug fix for session.loop never terminating if there is an SFTP conn active
        # since as far as it is concerned there is still active stuff.
        # This function is Copyright Fletcher Nichol
        # Tracked in https://github.com/test-kitchen/test-kitchen/pull/724
        def execute_with_exit_code(command)
          exit_code = nil
          closed = false
          session.open_channel do |channel|

            channel.request_pty

            channel.exec(command) do |_ch, _success|

              channel.on_data do |_ch, data|
                logger << data
              end

              channel.on_extended_data do |_ch, _type, data|
                logger << data
              end

              channel.on_request("exit-status") do |_ch, data|
                exit_code = data.read_long
              end

              channel.on_close do |ch| # This block is new.
                closed = true
              end
            end
          end
          session.loop { exit_code.nil? && !closed } # THERE IS A CHANGE ON THIS LINE, PAY ATTENTION!!!!!!
          exit_code
        end

        # Create the SFTP session and block until it is ready.
        #
        # @return [Net::SFTP::Session]
        def sftp_session
          @sftp_session ||= session.sftp
        end

        # Return if the path exists (because net::sftp uses exceptions for that
        # and it makes code gross) and also raise an exception if the path is a
        # symlink.
        #
        # @param path [String] Remote path to check.
        # @return [Boolean]
        def safe_stat(path)
          stat = sftp_session.lstat!(path)
          raise "#{path} is a symlink, possible security threat, bailing out" if stat.symlink?
          true
        rescue Net::SFTP::StatusException
          false
        end

        # Upload the checksum script if needed.
        #
        # @return [void]
        def copy_checksums_script!
          # Fast path because upload itself is called multiple times.
          return if @checksums_copied
          # Only try to transfer the script if it isn't present. a stat takes about
          # 1/3rd the time of the transfer, so worst case here is still okay.
          sftp_session.upload!(CHECKSUMS_PATH, CHECKSUMS_REMOTE_PATH) unless safe_stat(CHECKSUMS_REMOTE_PATH)
          @checksums_copied = true
        end

        def files_to_upload(checksums, local, recursive)
          glob_path = if recursive
            File.join(local, '**', '*')
          else
            local
          end
          pending = []
          Dir.glob(glob_path, File::FNM_PATHNAME | File::FNM_DOTMATCH).each do |path|
            next unless File.file?(path)
            rel_path = path[local.length..-1]
            remote_hash = checksums.delete(rel_path)
            pending << rel_path unless remote_hash && remote_hash == Digest::SHA1.file(path).hexdigest
          end
          pending
        end

        def upload_file(checksums, local, remote, rel_path)
          parts = rel_path.split('/')
          parts.pop # Drop the filename since we are only checking dirs
          parts_to_check = []
          until parts.empty?
            parts_to_check << parts.shift
            path_to_check = parts_to_check.join('/')
            unless checksums[path_to_check]
              logger.debug("[SFTP] Creating directory #{remote}#{path_to_check}")
              add_xfer(sftp_session.mkdir("#{remote}#{path_to_check}"))
              checksums[path_to_check] = true
            end
          end
          logger.debug("[SFTP] Uploading #{local}#{rel_path} to #{remote}#{rel_path}")
          add_xfer(sftp_session.upload("#{local}#{rel_path}", "#{remote}#{rel_path}"))
        end

        def purge_files(checksums, remote)
          checksums.each do |key, value|
            # Check if the file was uploaded in #upload_file.
            if value != true
              logger.debug("[SFTP] Removing #{remote}#{key}")
              add_xfer(sftp_session.remove("#{remote}#{key}"))
            end
          end
        end

        def sftp_xfers
          @sftp_xfers ||= []
        end

        def add_xfer(xfer)
          sftp_xfers << xfer
          sftp_loop
        end

        def sftp_loop(n_xfers=MAX_TRANSFERS)
          sftp_session.loop do
            sftp_xfers.delete_if {|x| !(x.is_a?(Net::SFTP::Request) ? x.pending? : x.active?) } # Purge any completed operations, which has two different APIs for some reason
            sftp_xfers.length > n_xfers # Run until we have fewer than max
          end
        end


      end

    end
  end
end
