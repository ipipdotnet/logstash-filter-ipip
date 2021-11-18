# encoding: utf-8
require "logstash/filters/base"

require 'ipaddr'
require "json"
require "lru_redux"

class Reader
  LOOKUP_CACHE = LruRedux::ThreadSafeCache.new(1000)

  def initialize(name, cache_size)

    if name.nil? || !File.exists?(name)
      raise "You must specify 'database => ...' in your ipip filter (I looked for '#{name}')"
    end
    if !File.readable? name
      raise "ip database is not readable."
    end

    @data = File.binread name

    meta_len = @data[0 ... 4].unpack('N')[0]
    meta_buf = @data[4 ... 4+meta_len]

    @meta = JSON.parse(meta_buf)

    if @data.length != (4 + meta_len + @meta['total_size'])
        raise "ip database file size error."
    end

    @node_count = @meta['node_count']
    @b_off = 4 + meta_len

    LOOKUP_CACHE.max_size = cache_size
  end

  def get_data_body(s, e)
    @data[@b_off+s .. @b_off+e]
  end

  def read_node(node, idx)
    off = node * 8 + idx * 4
    self.get_data_body(off, off+3).unpack('N')[0]
  end

  def find_node(ipv)
    addr = ipv.hton
    node = ipv.ipv4? ? 96 : 0

    idx = 0
    key = addr[0...16]
    val = LOOKUP_CACHE[key]
    if !val.nil?
      node = val
      idx = 16
    end

    if node < @node_count
      while idx < 128 do
        bin = addr[idx >> 3].unpack("C")[0]
        flag = (1 & (bin >> 7 - (idx % 8)))
        node = self.read_node(node, flag)
        idx += 1
        if idx == 16
          LOOKUP_CACHE[key] = node
        end
        if node > @node_count
          break
        end
      end
    end

    node
  end

  def find(ipx,lang)
    if ipx.nil?
        return nil
    end

    begin
        ipv = IPAddr.new ipx
    rescue => e
      return e.message
    end

    node = self.find_node ipv
    resolved = node - @node_count + @node_count * 8
    size = self.get_data_body(resolved, resolved+1).unpack('n')[0]

    temp = self.get_data_body(resolved+2, resolved+1+size)
    loc = temp.encode("UTF-8", "UTF-8").split("\t", @meta['fields'].length * @meta['languages'].length)

    off = @meta['languages'][lang]

    loc = loc[off ... @meta['fields'].length+off]
    
    info = {
      ip: ipx,
      db_build: @meta['build'],
    }

    @meta['fields'].each_with_index do | val, idx |
        info[val] = loc[idx]
    end
    
    return info
  end
end

class LogStash::Filters::Ipip < LogStash::Filters::Base
  READER_CACHE = LruRedux::ThreadSafeCache.new(1)

  config_name "ipip"

  config :source, :validate => :string, :required => true
  config :database, :validate => :path, :required => true
  config :target, :validate => :string, :default => "ipip"
  config :language, :validate => :string, :default => "CN"
  config :cache_size, :validate => :number, :default => 10000
  config :tag_on_failure, :validate => :array, :default => ["_ipip_lookup_failure"]

  public
  def register
    if @source == ""
        fail(LogStash::ConfigurationError, "please set non-empty `source` option")
    end

    READER_CACHE[1] = Reader.new(@database, @cache_size)
  end

  public
  def filter(event)
    ipx = event.get(@source)
    loc = READER_CACHE[1].find(ipx, @language)

    # if not return a hash means error happens, set failure tags
    if not loc.is_a?(::Hash)
      return tag_unsuccessful_lookup(event)
    end

    # if hash not contains ip symbol key, set failure tags
    if not loc.key?(:ip)
      return tag_unsuccessful_lookup(event)
    end

    event.set(@target, loc)
    filter_matched(event)
  end

  def tag_unsuccessful_lookup(event)
    @tag_on_failure.each{|tag| event.tag(tag)}
  end

end # class LogStash::Filters::Ipip
