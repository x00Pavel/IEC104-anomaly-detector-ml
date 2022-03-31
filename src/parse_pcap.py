import sys
import pyshark
import csv
from traceback import print_exc
from iec104Model.src import PCAP, CSV

def parse(num=1):
    pcap_file = PCAP[str(num)]
    print(f"Reading from {pcap_file}")
    packets = pyshark.FileCapture(pcap_file)
    
    parsed_data = [("asdu_len", "io_type", "type_id", "interval", "relative_time_stamp")]
    
    previous = 0
    first_time_stamp = packets[0].sniff_time
    relative_time = 0
    interval = 0
    for p in packets:
        if "iec60870_104" not in [l.layer_name for l in p.layers]:
            continue
        
        # Count time from the previous IEC 104 packet
        if previous != 0:
            interval = float((p.sniff_time - previous).total_seconds())
            relative_time = (p.sniff_time - first_time_stamp).total_seconds()

        previous = p.sniff_time
        # Extract only one 'representative' for the current package
        asdu_layer = p.get_multiple_layers("iec60870_asdu")
        if len(asdu_layer) == 0:
            continue
        asdu_layer = asdu_layer[0]

        iec_header_layer = p.get_multiple_layers("iec60870_104")
        # Aggregate values if more then one header is present in the packet
        iec_header = iec_header_layer[0]
        try:
            iec_header.apdulen = int(iec_header.apdulen)
        except AttributeError:
            # Not all APDU has valid apdulen attribute. Those packets in
            # Wireshark displayed as a byte sequence, so this packet can
            # be parsed
            print("Error in converting the value in packet")
            print_exc()
            print(p)
            continue

        if len(iec_header_layer) != 1:
            for entry in iec_header_layer[1:]:
                iec_header.apdulen += int(entry.apdulen)

        try:
            if asdu_layer:
                parsed_data.append((iec_header.apdulen, asdu_layer.ioa, asdu_layer.typeid, interval, relative_time))
        except:
            # Ignoring error if data can't be appended for some reasons.
            print("Error in parsing the packet")
            print_exc()
            print(p)

    with open(CSV[str(num)], "w") as f:
        writer = csv.writer(f)
        writer.writerows(parsed_data)

    print(f"CSV file is stored into {CSV[str(num)]}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        parse(sys.argv[1])
    else:
        parse()
