# Ruby API for the OpenDNS Security Graph

## Usage

In your Ruby script, you can use it like this:

```ruby
require 'sgraph'

sg = SGraph.new('/path/to/your/umbrella-cert.pem', '/path/to/your/umbrella-key.pem')

# get IP information
data = sg.get_ip('208.64.121.161')
# use data

# get domain information
data = sg.get_domain('www.test.com')
# use data

# see if a list of domains is infected
data = sg.get_infected(['www.test.com', 'bibikun.ru'])

# get traffic information over time for a domain
start = Time.local(2013, "Dec", 13)
stop = Time.now
data = sg.get_traffic('wikileaks.org', start, stop)

# etc.
```

## Installation

### Install siphash-ruby
Unfortunately, [emboss/siphash-ruby](https://github.com/emboss/siphash-ruby) seems to be the only decent SipHash gem, and it is not on RubyForge, so manual installation is necessary.

```sh
git clone https://github.com/emboss/siphash-ruby.git
cd siphash-ruby
gem build siphash-ruby.gemspec
gem install {generated_name}.gem
```

### Install sgraph
```sh
git clone git@github.office.opendns.com:skyler/ruby-sgraph.git
cd ruby-sgraph
bundle install
gem build sgraph.gemspec
gem install {generated_name}.gem
```
