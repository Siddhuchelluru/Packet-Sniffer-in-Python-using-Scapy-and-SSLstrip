#!/usr/bin/env python

import argparse
import sslstrip
from scapy.all import *

def parse_arguments():
  parser = argparse.ArgumentParser()
  parser.add_argument("-i", "--interface", help="Network interface to sniff on", required=True)
  parser.add_argument("-f", "--filter", help="BPF filter to apply")
  parser.add_argument("-o", "--output", help="Output file to save packets to (PCAP format)")
  parser.add_argument("-t", "--tap", help="Network tap device to use")
  return parser.parse_args()

def run_sslstrip(interface):
  # start SSLstrip
  print("Starting SSLstrip on interface {}".format(interface))
  sslstrip.main(["sslstrip", "-l", "10000", "-w", "sslstrip.log"])

def sniffer(interface, bpf_filter, output_file, tap_device):
  # create the sniffer
  if tap_device:
    # use a network tap to capture all traffic on the segment
    sniffer = AsyncSniffer(iface=tap_device, filter=bpf_filter, prn=lambda x: x.summary())
  else:
    # capture only traffic to or from the host
    sniffer = AsyncSniffer(iface=interface, filter=bpf_filter, prn=lambda x: x.summary())

  # start sniffing
  print("Starting sniffer on interface {}".format(interface))
  if output_file:
    print("Writing packets to {}".format(output_file))
  sniffer.start()

  # wait for Ctrl-C
  try:
    while True:
      time.sleep(1)
  except KeyboardInterrupt:
    print("Stopping sniffer")

  # stop sniffing and write packets to file if specified
  sniffer.stop()
  if output_file:
    wrpcap(output_file, sniffer.results)

if __name__ == "__main__":
  args = parse_arguments()
  if args.tap:
    run_sslstrip(args.interface)
  sniffer(args.interface, args.filter, args.output, args.tap)
