# Logstash RFC2407 Plugin

[![Travis Build Status](https://travis-ci.org/logstash-plugins/logstash-filter-example.svg)](https://travis-ci.org/logstash-plugins/logstash-filter-example)

This plugin is meant for decoding RFC2047 headers

## Example

* with the message given:

```
message => "2013-01-20T13:14:01+0000: Example mail header field: =?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?==?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?=;"
```

* and the plugin configuration:

```
      filter {
        grok {
          match => { "message" => "%{TIMESTAMP_ISO8601:timestamp}: %{DATA}: %{DATA:header_field1};( %{GREEDYDATA:header_field2})?"}
        }
        mime {
          field => [ "header_field1", "header_field2" ]
        }
      }
```

* the outcome will be a document:

```
{
 @timestamp: "2013-01-20T13:14:01+0000",
 header_field1: "If you can read this you understand the example."
}
```

