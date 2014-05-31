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
require 'kitchen-sync/rsync'
require 'kitchen-sync/scp'
require 'kitchen-sync/sftp'
require 'kitchen-sync/version'


class KitchenSync
  IMPLEMENTATIONS = {
    'rsync' => Rsync,
    'scp' => SCP,
    'sftp' => SFTP,
  }

  def initialize(logger, session, options)
    @logger = logger
    @session = session
    @options = options
    @impl = load_implementation
  end

  def load_implementation(default_mode='sftp')
    mode = (ENV['KITCHEN_SYNC_MODE'] || default_mode).downcase
    @logger.debug("[sync] Using transfer mode #{mode}")
    impl_class = IMPLEMENTATIONS[mode]
    raise "Sync implementation for #{mode} not found" unless impl_class
    # Create the instance, any error during init means we use SCP instead
    begin
      impl_class.new(@logger, @session, @options)
    rescue Exception
      if impl_class != SCP
        @logger.debug("[sync] Falling back to SCP")
        impl_class = SCP
        retry
      else
        raise
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
