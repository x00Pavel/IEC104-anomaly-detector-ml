from iec104Model.src.parse_pcap import parse
import sys

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

if __name__ == "__main__":
    # check if CSV file exists
    # if not -> create from given file
    # fit the model
    # write test prediction
    # run 
    if len(sys.argv) > 1:
        parse(sys.argv[1])
    else:
        parse()
