Integer Overflow in tfDnsExpLabelLength Leading to Heap Overflow and RCE

CVE: CVE-2020-11901 (Variant 1)
CVSS: 9
Protocol(s): DNS over UDP (and likely DNS over TCP)
Port(s): 53

Vulnerability description:

In the Treck stack, DNS names are calculated via the function tfDnsExpLabelLength. A bug exists in this function where the computation is performed using an unsigned short, making it possible to overflow the computed value with a specially constructed DNS response packet. Since tfDnsExpLabelLength computes the full length of a DNS name after it is decompressed, it is possible to induce an overflow using a DNS packet far smaller than 2^16^ bytes. In some code paths, tfGetRawBuffer is called shortly after tfDnsExpLabelLength, allocating a buffer on the heap where the DNS name will be stored using the size computed by tfDnsExpLabelLength, thus leading to a heap overflow and potential RCE.

While newer versions of the Treck stack will stop copying the DNS name into the buffer as soon as a character that isn't alphanumeric or a hyphen is reached, older versions do not have this restriction and further use predictable transaction IDs for DNS queries, making this vulnerability easier to exploit.

Limitations or special considerations for detection:

Ideally, detection logic for this vulnerability would involve independently computing the uncompressed length of all DNS names contained within incoming DNS responses. Unfortunately, this may be computationally expensive for a device to perform for every incoming DNS response, especially since each one may contain many DNS names. Instead, we must rely on a combination of heuristics.

Furthermore, it is currently unclear whether exercising this vulnerability is possible when using EDNS(0) or DNS over TCP. We recommend assuming it is possible for the purposes of implementing detection logic. During our testing, an inconsistency in how Suricata handled DNS over TCP was discovered -- in some cases it was correctly identified as DNS traffic and in other cases, it was not. Consequently, two rules have been created to determine the size of DNS over TCP traffic. The second rule uses the TCP primitive instead of the DNS primitive; however, the second rule will only be evaluated if not flagged by the first rule.

Because the Suricata rule in dns_invalid_size.rules uses the DNS responses' EDNS UDP length, which may be controlled by the attacker, a second upper limit of 4096 bytes is enforced.

Recommended detection criteria:

    The device must be capable of processing DNS traffic and matching responses to their corresponding requests.

    The device must be capable of identifying individual DNS names within individual DNS packets.

    The device should flag any DNS responses whose size exceeds what is "expected". The expected size depends on the type of DNS packet sent:

        For DNS over TCP, the size should not exceed the value specified in the first two bytes of the TCP payload.

        For DNS over UDP with EDNS(0), the size should not exceed the value negotiated in the request, which is specified in the CLASS field of the OPT RR, if present.

        For DNS over UDP without EDNS(0), the size should not exceed 512 bytes.

        These are all checked in dns_invalid_size.rules, which invokes either dns_size.lua or dns_tcp_size.lua for the logic.

    The device should flag DNS responses containing DNS names exceeding 255 bytes (prior to decompression).
        This is checked in dns_invalid_name.rules, which invokes dns_invalid_name.lua for the logic.

    The device should flag DNS responses containing DNS names comprised of characters besides a-z, A-Z, 0-9, "-", "_", and "*".
        This is also checked in dns_invalid_name.rules, which invokes dns_invalid_name.lua for the logic.

    The device should flag DNS responses containing a large number of DNS compression pointers, particularly pointers one after the other. The specific tolerance will depend on the network.

        The device should count all labels starting with the bits 0b10, 0b01, or 0b11 against this pointer total, as vulnerable versions of the Treck stack (incorrectly) classify all labels where the first two bits aren't 0b00 as compression pointers. In the Lua script, we treat any value above 63 (0x3F) as a pointer for this reason, as any value in that range will have at least one of these bits set.

        The specific thresholds were set to 40 total pointers in a single DNS packet or 4 consecutive pointers for our implementation of this rule. These values were chosen since they did not seem to trigger any false positives in a very large test PCAP but should be altered as needed to suit typical traffic for the network the rule will be deployed on. The test for consecutive pointers is especially useful since each domain name should only ever have one pointer (at the very end), meaning we should never be seeing many pointers in a row in normal traffic.

        This is implemented in dns_heap_overflow_variant_1.lua, which is invoked by dns_heap_overflow.rules.

    Implementation of the detection logic above has been split up amongst several Suricata rule files since only the pointer counting logic is specific to this vulnerability. Detection of exploits leveraging this vulnerability are enhanced with the addition of the DNS layer size check, domain name compressed length check, and domain name character check implemented in the other rules, but these are considered to be "helper" signatures and flagging one of these does not necessarily indicate an exploitation attempt for this specific vulnerability.

False positive conditions (signatures detecting non-malicious traffic):

Networks expecting non-malicious traffic containing DNS names using non-alphanumeric characters or an abnormally large number of DNS compression pointers may generate false positives. Unfortunately, checking for pointers in only the domain name fields is insufficient, as a malicious packet could use a compression pointer that points to an arbitrary offset within said packet, so our rule instead checks every byte of the DNS layer. Consequently, Treck's overly liberal classification of DNS compression pointers means that our rule will often misclassify unrelated bytes in the DNS payload as pointers.

In our testing, we ran into false positives with domain names containing spaces or things like "https://". Per the RFCs, characters such as ":" and "/" should not be present in domain names but may show up from time to time in real, non-malicious traffic. The list of acceptable characters should be expanded as needed for the targeted network to avoid excessive false positives. That being said, keeping the list of acceptable characters as small as possible will make it more difficult to sneak in shellcode to leverage one of the Ripple20 DNS vulnerabilities.

False positives on the DNS size rules may occur when DNS over TCP is used if Suricata does not properly classify the packet as a DNS packet -- something that has occurred multiple times during our testing. This would cause the second size check to occur, which assumes that all traffic over port 53 is DNS traffic and processes the payload accordingly. As a result, any non-DNS traffic on TCP port 53 may cause false positives in this specific case. It is recommended the port number in the rule be adjusted for any network where a different protocol is expected over port 53.

Fragmentation of DNS traffic over TCP may also introduce false positives. If the streams are not properly reconstructed at the time the rules execute on the DNS payload, byte offsets utilized in the attached Lua scripts could analyze incorrect data. Fragmentation in DNS response packets is not common on a standard network unless MTU values have been set particularly low. Each rule should be evaluated independently prior to use in production based on specific network requirements and conditions.

False negative conditions (signatures failing to detect vulnerability/exploitation):

False negatives are more likely as this detection logic relies on heuristics due to computation of the uncompressed DNS name length being too computationally expensive. Carefully constructed malicious packets may be able to circumvent the suggested pointer limitations and still trigger the vulnerability.

Signature(s):

dns_invalid_size.rules:

alert dns any any ‑> any any (msg:"DNS packet too large"; flow:to_client; flowbits:set,flagged; lua:dns_size.lua; sid:2020119014; rev:1;)

alert tcp any 53 -> any any (msg:"DNS over TCP packet too large"; flow:to_client,no_frag; flowbits:isnotset,flagged; lua:dns_tcp_size.lua; sid:2020119015; rev:1;)

dns_invalid_name.rules:

alert dns any any -> any any (flow:to_client; msg:"DNS response contains invalid domain name"; lua:dns_invalid_name.lua; sid:2020119013; rev:1;)

dns_heap_overflow.rules:

# Variant 1

alert dns any any -> any any (flow:to_client; msg:"Potential DNS heap overflow exploit (CVE-2020-11901)"; lua:dns_heap_overflow_variant_1.lua; sid:2020119011; rev:1;)