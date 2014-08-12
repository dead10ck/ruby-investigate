require 'json'
require 'openssl'
require 'rest-client'
require 'uri'
require 'siphash'

# Ruby API for the OpenDNS Security Graph
class Investigate
  VERSION = '0.0.1'
  SGRAPH_URL = 'https://investigate.api.opendns.com'

  # Builds a new SGraph object.
  # cert and key should be the string path to your certificate and key PEM files,
  # respectively.
  def initialize(cert, key)
    @cert_file = OpenSSL::X509::Certificate.new(File.read(cert))
    @key_file = OpenSSL::PKey::RSA.new(File.read(key))
    @ssl_opts = {
      :ssl_client_cert  =>  @cert_file,
      :ssl_client_key   =>  @key_file,
      :verify_ssl       =>  OpenSSL::SSL::VERIFY_PEER
    }
  end

  # Builds a new RestClient::Resource object for HTTP calls
  def request_resource(url)
    RestClient::Resource.new(url, @ssl_opts)
  end

  # Generic GET call to 'https://sgraph.umbrella.com{sub_url}'.
  # Parses the response into a JSON object
  def get(sub_url)
    r = request_resource(SGRAPH_URL + sub_url)
    resp = r.get
    JSON.parse(resp)
  end

  
  # Generic POST call to 'https://sgraph.umbrella.com{sub_url}'.
  # Parses the response into a JSON object
  def post(sub_url, body)
    r = request_resource(SGRAPH_URL + sub_url)
    resp = r.post(body)
    JSON.parse(resp)
  end

  # Make a GET call to '/dnsdb/ip/a/{ip}.json'.
  # Return the JSON object in the response
  def get_ip(ip)
    get("/dnsdb/ip/a/" + ip + ".json")
  end

  # Make a GET call to '/dnsdb/name/a/{domain}.json'.
  # Return the JSON object in the response
  def get_domain(domain)
    get("/dnsdb/name/a/" + domain + ".json")
  end

  # Make a GET call to '/links/name/{domain}.json'.
  # Return the JSON object in the response
  def get_related_domains(domain)
    get("/links/name/" + domain + ".json")
  end

  # Make a GET call to '/label/rface-gbt/name/{domain}.json'.
  # Return the JSON object in the response
  def get_score(domain)
    get("/label/rface-gbt/name/" + domain + ".json")
  end

  # Make a GET call to '/recommendations/name/{domain}.json'.
  # Return the JSON obje
  def get_cooccurrences(domain)
    get("/recommendations/name/" + domain + ".json")
  end

  # Make a GET call to '/security/name/{domain}.json'.
  # Return the JSON object
  def get_security(domain)
    get("/security/name/" + domain + ".json")
  end

  # Make a GET call to '/whois/name/{domain}.json'.
  # Return the JSON obje
  def get_whois(domain)
    get("/whois/name/" + domain + ".json")
  end

  # Make a GET call to '/infected/names/{SipHash of domains list}.json'.
  # with a body containing the given domains.
  # Return the JSON object in the response
  def get_infected(domains=[])
    domains_json = JSON.generate(domains)
    sub_url = "/infected/names/" + SipHash::digest(SGRAPH_SIPHASH_KEY, domains_json.to_s).to_s(16) + ".json"
    post(sub_url, domains_json)
  end

  # Get traffic information over time for a particular domain.
  # start_time and stop_time should be Time objects
  def get_traffic(domain, start_time=Time.now, stop_time=Time.now)
    start_time_uri_str = start_time.strftime("%Y/%m/%d/%H")
    stop_time_uri_str = stop_time.strftime("%Y/%m/%d/%H")
    sub_url = "/appserver/?v=1&function=domain2-system&domains=#{domain}&locations=" +
      "&start=#{start_time_uri_str}&stop=#{stop_time_uri_str}"
    get(sub_url)
  end
end
