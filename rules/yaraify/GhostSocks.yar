rule GhostSocks
{
  meta:
        description = "Golang-based SOCKS5 backconnect proxy malware, detailing its integration with LummaC2 and its command-and-control infrastructure"
        author = "dogsafetyforeverone"
        date = "2025-02-22"
        version = "1.0"
        reference = "GhostSocks Detection"
        yarahub_reference_md5 = "6febfbb3533872cae2d81c76d7edc467"
        yarahub_uuid = "3e57fb2c-833b-438f-bb6e-55f8bee82c7f"
        yarahub_license = "CC BY-NC-ND 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
  strings:
        $body = "Forbidden: Invalid API Key"
        $status_code_403 = "HTTP/1.1 403"
        $headers_hash = "86362ac6d972b1b55f1f434811d014316196f0e193878d8270dae939efb25908"
        $port_30001 = "30001"   // Assuming the port might appear in textual logs or captures
    condition:
        all of ($body, $status_code_403, $headers_hash, $port_30001)
}
