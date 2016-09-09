Gem::Specification.new do |s|
  s.name = 'logstash-filter-rfc2047'
  s.version         = '0.1.0'
  s.licenses = ['Apache License (2.0)']
  s.summary = "This plugin decodes the RFC2047 format headers."
  s.description     = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["Tomasz Habiger"]
  s.email = 'tomasz.habiger@gmail.com'
  s.homepage = ""
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 1.0"
  s.add_runtime_dependency "rfc2047", "~> 0.3"
  s.add_development_dependency 'logstash-devutils', '~> 0'
  s.add_development_dependency 'logstash-filter-grok', '~> 3.2'
  s.add_development_dependency 'logstash-patterns-core', '~> 4.0'
end