# Ruby API for the OpenDNS Security Graph

## Usage

In your Ruby script, you can use it like this:

```ruby
require 'investigate'

inv = Investigate.new('xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')

# get domain categorization and status
inv.categorization('amazon.com')

# categorization and status on a list of domains with labels
domains = ['www.amazon.com', 'www.opendns.com', 'bibikun.ru']
inv.categorization(domains, true)

# cooccurrences
inv.cooccurrences('test.com')

# related domains
inv.related("test.com")

# security features
inv.security("test.com")

# domain tags
inv.domain_tags('bibikun.ru')

# domain RR history
inv.rr_history('bibikun.ru')

# IP RR history
inv.rr_history('50.23.225.49')

# latest domains for an IP
inv.latest_domains('46.161.41.43')
```

## Installation
You can do:
```sh
gem install investigate
```

or install manually with:
```sh
git clone git@github.com:dead10ck/ruby-investigate.git
cd ruby-investigate
bundle install
gem build investigate.gemspec
gem install {generated_name}.gem
```
