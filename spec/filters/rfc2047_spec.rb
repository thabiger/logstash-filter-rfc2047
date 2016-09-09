# encoding: utf-8

require 'spec_helper'
require "logstash/patterns/core"

# solution based on https://github.com/logstash-plugins/logstash-filter-grok/blob/master/spec/filters/grok_spec.rb
module LogStash::Environment
  # running the grok code outside a logstash package means
  # LOGSTASH_HOME will not be defined, so let's set it here
  # before requiring the grok filter

  # the path that is set is the plugin root path
  unless self.const_defined?(:LOGSTASH_HOME)
    LOGSTASH_HOME = File.expand_path("../../../", __FILE__)
  end

  # also :pattern_path method must exist so we define it too
  unless self.method_defined?(:pattern_path)
    def pattern_path(path)
      ::File.join(LOGSTASH_HOME, "spec", "patterns", path)
    end
  end
end
require "logstash/filters/grok"
require "logstash/filters/rfc2047"

describe "LogStash::Filters::Mime" do
  describe "Encode RFC2047" do

    let(:config) do <<-CONFIG
      filter {
        grok {
          match => { "message" => "%{TIMESTAMP}: %{DATA}: %{GREEDYDATA:header_field}"}
        }
        rfc2047 {
          field => "header_field"
        }
      }
      CONFIG
    end
    
    message = "2013-01-20T13:14:01+0000: Example mail header field: =?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?==?ISO-8859-2?B?dSB1bmRlcnN0YW5kIHRoZSBleGFtcGxlLg==?="
    
    describe "Decode valid message" do
      sample ({
                'message' => message,
                'type' => 'type'
      }) do
        insist { subject["header_field"] } == "If you can read this you understand the example."
      end
    end

    describe "Invalid message should pass through unchanged" do
      message = "=?iso-2022-jp?Q?whatever"
      sample ({
                'message' => message,
                'type' => 'type'
      }) do
        insist { subject["message"] } == "=?iso-2022-jp?Q?whatever"
      end
    end

  end
end
