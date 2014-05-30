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

require 'kitchen-sync/base'

require 'net/sftp'

class KitchenSync
  class SFTP < Base
    CHECKSUMS_PATH = File.expand_path('../checksums.rb', __FILE__)
    CHECKSUMS_HASH = Digest::SHA1.file(CHECKSUMS_PATH)
    CHECKSUMS_REMOTE_PATH = "/tmp/checksums-#{CHECKSUMS_HASH}.rb" # This won't work on Windows targets
    MAX_TRANSFERS = 32

    def initialize(*args)
      super
      @sftp = @session.sftp
      @xfers = []
    end

    def upload(local, remote, recursive=true)
      remote = File.join(remote, File.basename(local))
      # Fast path check, if the remote path doesn't exist at all we just run a direct transfer
      unless safe_stat(remote)
        @logger.debug("[sync:sftp] Fast path upload from #{local} to #{remote}")
        @sftp.upload!(local, remote, requests: MAX_TRANSFERS)
        return
      end
      copy_checksums_script
      # Get our checksums
      checksum_cmd = "/opt/chef/embedded/bin/ruby #{CHECKSUMS_REMOTE_PATH} #{remote}"
      @logger.info("[sync:sftp] Running #{checksum_cmd}")
      checksums = JSON.parse(@session.exec!(checksum_cmd))
      files_to_upload(checksums, local, recursive).each do |rel_path|
        upload_file(checksums, local, remote, rel_path)
      end
      purge_files(checksums, remote)
      sftp_loop(0) # Wait until all xfers are complete
    end

    private

    # Return if the path exists (because net::sftp uses exceptions for that and
    # it makes code gross) and also raise an exception if the path is a symlink.
    def safe_stat(path)
      stat = @sftp.lstat!(path)
      raise "#{path} is a symlink, possible security threat, bailing out" if stat.symlink?
      true
    rescue Net::SFTP::StatusException
      false
    end

    def copy_checksums_script
      return if @checksums_copied
      # Only try to transfer the script if it isn't present. a stat takes about
      # 1/3rd the time of the transfer, so worst case here is still okay.
      @sftp.upload!(CHECKSUMS_PATH, CHECKSUMS_REMOTE_PATH) unless safe_stat(CHECKSUMS_REMOTE_PATH)
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
          @logger.debug("[sync:sftp] Creating directory #{remote}#{path_to_check}")
          add_xfer(@sftp.mkdir("#{remote}#{path_to_check}"))
          checksums[path_to_check] = true
        end
      end
      @logger.debug("[sync:sftp] Uploading #{local}#{rel_path} to #{remote}#{rel_path}")
      add_xfer(@sftp.upload("#{local}#{rel_path}", "#{remote}#{rel_path}"))
    end

    def purge_files(checksums, remote)
      checksums.each do |key, value|
        if value != true
          @logger.debug("[sync:sftp] Removing #{remote}#{key}")
          add_xfer(@sftp.remove("#{remote}#{key}"))
        end
      end
    end

    def add_xfer(xfer)
      @xfers << xfer
      sftp_loop
    end

    def sftp_loop(n_xfers=MAX_TRANSFERS)
      @sftp.loop do
        @xfers.delete_if {|x| !(x.is_a?(Net::SFTP::Request) ? x.pending? : x.active?) } # Purge any completed operations, which has two different APIs for some reason
        @xfers.length > n_xfers # Run until we have fewer than max
      end
    end

  end
end
