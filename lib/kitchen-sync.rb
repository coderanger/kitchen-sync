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

require 'kitchen-sync/core_ext'
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

  def shutdown
    @impl.shutdown
  end
end
