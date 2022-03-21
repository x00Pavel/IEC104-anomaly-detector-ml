import pyshark
from iec104Model import DATA_DIR
from os.path import join, basename
import csv
from traceback import print_exc


def parse(file="10122018-104Mega.pcapng"):
    file = basename(file)
    pcap_file = join(DATA_DIR, file)
    print(f"Reading from {pcap_file}")
    packets = pyshark.FileCapture(pcap_file)

    parsed_data = [("asdu_len", "seq_coa", "seq_cot",
                    "io_type", "interval")]

    previous = 0
    for p in packets:
        if "iec60870_104" not in [l.layer_name for l in p.layers]:
            continue
        # Count time from the previous IEC 104 packet
        if previous != 0:
            interval = float((p.sniff_time - previous).total_seconds())
        else:
            interval = 0  # Initial value for the first packet
        previous = p.sniff_time

        # Extract only one 'representative' for the current package
        asdu_layer = p.get_multiple_layers("iec60870_asdu")
        asdu_layer = None if len(asdu_layer) == 0 else asdu_layer[0]

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
                parsed_data.append((iec_header.apdulen, asdu_layer.addr,
                                    asdu_layer.causetx, asdu_layer.ioa,
                                    asdu_layer.typeid, interval))
            else:
                parsed_data.append((iec_header.apdulen, -1, -1,
                                    -1, -1, interval))
        except:
            # Ignoring error if data can't be appended for some reasons.
            print("Error in parsing the packet")
            print_exc()
            print(p)

    with open(join(DATA_DIR, f"{file}.csv"), "w") as f:
        writer = csv.writer(f)
        writer.writerows(parsed_data)

    print(f"CSV file is stored into {join(DATA_DIR, f'{file}.csv')}")