import subprocess
import os
import sys
import csv

trial_path = "C:\\Users\\asus\\Documents\\nids-pcap-dataset\\trial_unsw_nb_reassembled\\result"
reassembled_pcap_path = "C:\\Users\\asus\\Documents\\tugas-akhir\\resources\\nids-pcap-dataset\\reassembled_pcap"
pcap_path = "C:\\Users\\asus\\Documents\\tugas-akhir\\resources\\nids-pcap-dataset\\unsw_nb_full_pcap"
prob_pcap_path = "C:\\Users\\asus\\Documents\\tugas-akhir\\resources\\dummy_dataset"

def get_file_list(dir, header_saved):
    header_tshark_cmd = 'tshark -r {} -T fields -Y http -E header=y -E separator=, -E quote=d -E occurrence=f -e _ws.col.Source -e _ws.col.Destination -e _ws.col.sport -e _ws.col.dport -e _ws.col.Protocol  -e _ws.col.start_time -e _ws.col.Info >> {}.csv'
    newest_tshark_cmd = 'tshark -r {} -T fields -Y http -E header=n -E separator=, -E quote=d -E occurrence=f -e _ws.col.Source -e _ws.col.Destination -e _ws.col.sport -e _ws.col.dport -e _ws.col.Protocol  -e _ws.col.start_time -e _ws.col.Info >> {}.csv'

    for root, dirs, files in os.walk(dir, header_saved):
        for file in files:
            if file.endswith(".pcap"):
                print("parsing file: " + file + "........")
                if header_saved == False:
                    subprocess.check_output(header_tshark_cmd.format(os.path.join(root, file), os.path.join("C:\\Users\\asus\\Documents\\nids-pcap-dataset","unsw_dataset")), shell=True, universal_newlines=True)
                    header_saved = True
                else:
                    subprocess.check_output(newest_tshark_cmd.format(os.path.join(root, file), os.path.join("C:\\Users\\asus\\Documents\\nids-pcap-dataset","unsw_dataset")), shell=True, universal_newlines=True)

if __name__ == "__main__" :
    header_saved = False
    get_file_list(trial_path, header_saved)