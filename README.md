# logstash-filter-ipip

Logstash IP Geo info lookup filter plugin for `IPDB` format database which released by IPIP.net

Tested on logstash ver `7.13.2`

## how to configure

``` logstash
filter {
    ipip {
        source => "message"
        database => "/path/to/mydata4vipweek2.ipdb"
        target => "geoip" # default is ipip
        language => "CN"
        cache_size => 5000 # default is 10000
        tag_on_failure => ["_YOUR_LOOKUP_FAIL_TAG"] # default is ["_ipip_lookup_failure"]
    }
}
```

## how to use

Logstash support `--path.plugins` flag to directly load a plugin source code, more detail please vist [working-with-plugins](https://www.elastic.co/guide/en/logstash/current/working-with-plugins.html)

## note

The `cache_size` setting is global. All filter instances of this filter share the same cache. The last declared value in config file will win.
