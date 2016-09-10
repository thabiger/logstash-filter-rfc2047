# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'rfc2047'

class LogStash::Filters::RFC2047 < LogStash::Filters::Base

 config_name "rfc2047"

 config :field, :validate => :array

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)

    @field.each do |f| 
      msg = event[f]
      if ((msg =~ /=\?((?:ISO|UTF)-[0-9]{1,4}(?:-[0-9])?)\?/i) && (msg.encoding.to_s=="UTF-8"))
         event[f] = Rfc2047.decode(msg.encode("utf-8"), $1)
         # correct debugging log statement for reference
         # using the event.get API
         @logger.debug? && @logger.debug("Message is now: #{event["message"]})")
      end
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end 
