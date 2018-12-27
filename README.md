# logstash-filter-ipip
IPIP.net  IPDB database file For  logstash filter plugin

# logstash.conf
<pre>
input {
    stdin {
    }
}

filter {
    ipip {
            source => "message"
            database => "/path/to/mydata4vipweek2.ipdb"
           target => "geoip"
        language => "CN"
    }
}

output {
    stdout {
        codec => rubydebug
    }
}
</pre>