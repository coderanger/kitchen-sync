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

require 'json'
require 'digest/sha1'

glob_path = base = ARGV.first
glob_path = File.join(glob_path, '**', '*') if File.directory?(glob_path)
d = Digest::SHA1.new
STDOUT.write(
  Dir.glob(glob_path, File::FNM_PATHNAME | File::FNM_DOTMATCH).inject({}) do |memo, path|
    rel_path = path[base.length..-1]
    if File.file?(path) && File.readable?(path)
      d.reset
      memo[rel_path] = d.file(path).hexdigest
    elsif File.directory?(path)
      memo[rel_path] = true
    end
    memo
  end.to_json
)
