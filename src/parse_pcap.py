import pyshark
from iec104Model import DATA_DIR
from os.path import join
import csv


def parse():
    pcap_file = join(DATA_DIR, "10122018-104Mega.pcapng")
    packets = pyshark.FileCapture(pcap_file)

    parsed_data = [("asdu_len", "seq_coa", "seq_cot", "seq_ioa", "type",
                    "io_type", "interval")]

    previous = 0
    for p in packets:
        if "iec60870_104" not in [l.layer_name for l in p.layers]:
            continue

        if previous != 0:
            interval = float((p.sniff_time - previous).total_seconds())
        else:
            interval = 0
        previous = p.sniff_time

        iec_header_layers = p.get_multiple_layers("iec60870_104")
        asdu_layers = p.get_multiple_layers("iec60870_asdu")
        if len(asdu_layers) == 0:
            asdu_layers = [None for _ in iec_header_layers]

        for header, asdu in zip(iec_header_layers, asdu_layers):
            try:
                if asdu is not None:
                    parsed_data.append((header.apdulen, asdu.addr, asdu.causetx,
                                        asdu.ioa, header.type, asdu.typeid,
                                        interval))
                else:
                    parsed_data.append((header.apdulen, -1, -1,
                                        -1, header.type, -1, interval))
            except Exception:
                print("Error in parsing the packet")
                print(p)

    with open(join(DATA_DIR, "parsed.csv"), "w") as f:
        writer = csv.writer(f)
        writer.writerows(parsed_data)