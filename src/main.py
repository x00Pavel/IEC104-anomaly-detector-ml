from iec104Model.src.parse_pcap import parse

# Extract:
#   Length of APDU  - Length of Application Protocol Data Unit (apdulen)
#   sequence of COA - Common Address of Application Service Data Unit (addr)
#   sequence of COT - Cause of Transmition (causetx)
#   sequence of IOA - Information Obejct Address (ioa)
#   type            - type of the APDU (type)
#   typeId          - type of information object (typeid)
# Questions:
#   - should I split into flows and take some data from there, such as time of
#     the flow until termination?
#   - how to detect direction of the package (from master or to master)?
#   - can in out TCP packet be two ASDU with different element ID?
#   - should packets with two ASDU be aggregated into one?


# p = packets[15]
# apdu = p["iec60870_104"]
# asdu = p["iec60870_asdu"]
# print(apdu.field_names)
# print(asdu.field_names)
# print(p["iec60870_104"])

if __name__ == "__main__":
    parse()
