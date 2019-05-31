#!/usr/bin/env python3.5
#
# Copyright (c) 2019, Philipp Winter
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import sys
import socket
import threading

import tabulate

import stem
import stem.descriptor.reader
import stem.descriptor.remote

from stem.descriptor import parse_file


def log(*args, **kwargs):
    """Generic log function that prints to stderr."""

    print("[+]", *args, file=sys.stderr, **kwargs)


def tcp_port_reachable(addr, port, timeout=5):
    """
    Return 'True' if we could establish a TCP connection with the given
    addr:port tuple and 'False' otherwise.

    Use the optional third argument to determine the timeout for the connect()
    call.
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((addr, port))
        s.shutdown(socket.SHUT_RDWR)
        return True
    except:
        return False


def get_obfs4_bridges(filename):
    """
    Extract obfs4 extra-info descriptors and return dictionary.

    The dictionary maps an obfs4 bridge's fingerprint to its extra-info
    descriptor.
    """

    fpr2obfs4desc = {}

    # We are parsing our descriptor files as type "extra-info 1.0" because
    # unredacted bridge extra-info descriptors are normal extra-info
    # descriptors.

    with open(filename, "rb") as desc_file:
        for desc in parse_file(desc_file, descriptor_type="extra-info 1.0"):
            if "obfs4" in desc.transport:
                fpr2obfs4desc[desc.fingerprint] = desc

    # Use "cached-extrainfo.new" to augment "cached-extrainfo".

    with open(filename + ".new", "rb") as desc_file:
        for desc in parse_file(desc_file, descriptor_type="extra-info 1.0"):
            if "obfs4" in desc.transport:
                fpr2obfs4desc[desc.fingerprint] = desc

    return fpr2obfs4desc


def get_contact_info(filename):
    """
    Extract bridge contact information and return dictionary.

    The dictionary maps a bridge's fingerprint to its contact information.
    """

    fpr2contact = {}

    with open(filename, "rb") as desc_file:
        for desc in parse_file(desc_file,
                               descriptor_type="server-descriptor 1.0"):
            if desc.contact:
                fpr2contact[desc.fingerprint] = desc.contact

    return fpr2contact


def scan_bridges(bridges):
    """TCP-scan the given bridges in parallel."""

    # We encode our scan results as a dictionary that maps an obfs4 bridge's
    # fingerprint to a boolean value that tells us if we could establish a TCP
    # connection to the obfs4 bridge's port.

    fpr2result = {}
    lock = threading.Lock()

    def wrapper(func, args, fingerprint, res):
        extrainfo_desc = args[0]
        addr, port, _ = extrainfo_desc.transport["obfs4"]
        result = func(addr, port)
        with lock:
            fpr2result[fingerprint] = result

    threads = []
    for fingerprint, extrainfo_desc in bridges.items():
        t = threading.Thread(target=wrapper, args=(tcp_port_reachable,
                                                   (extrainfo_desc,),
                                                   fingerprint,
                                                   fpr2result))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return fpr2result


def main(bridgeauth_dir):

    num_bridges = 0
    num_running = 0

    # Parse our extra-info document to learn what bridges run obfs4.  The
    # returned data structure maps a bridge's fingerprint to its extra-info
    # descriptor.

    fpr2obfs4desc = get_obfs4_bridges("{}/cached-extrainfo".format(
                                      bridgeauth_dir))
    obfs4_fprs = set(fpr2obfs4desc.keys())
    running_obfs4_bridges = {}

    # Parse our network status document.

    handler = stem.descriptor.DocumentHandler.ENTRIES
    with open("{}/networkstatus-bridges".format(bridgeauth_dir),
              "rb") as consensus_file:
        for bridge in parse_file(consensus_file,
                                 descriptor_type=("network-status-consensus-3 "
                                                  "1.0"),
                                 document_handler=handler):
            num_bridges += 1

            # Ignore bridges that don't have the 'Running' flag.

            if stem.Flag.RUNNING not in bridge.flags:
                continue
            num_running += 1

            # Filter obfs4 bridges that have the 'Running' flag.

            if bridge.fingerprint in obfs4_fprs:
                extrainfo_desc = fpr2obfs4desc[bridge.fingerprint]
                running_obfs4_bridges[bridge.fingerprint] = extrainfo_desc

    log("{:,} bridges in network status; {:,} ({:.1f}%) have 'Running' "
        "flag.".format(num_bridges,
                       num_running,
                       num_running / num_bridges * 100))

    log("{:,} ({:.1f}%) of {:,} bridges with 'Running' flag support "
        "obfs4.".format(len(running_obfs4_bridges),
                        len(running_obfs4_bridges) / num_running * 100,
                        num_running))

    fpr2result = scan_bridges(running_obfs4_bridges)

    num_unreachable = len([r for _, r in fpr2result.items() if not r])
    log("{:,} ({:.1f}%) of {:,} running obfs4 bridges fail to establish TCP "
        "connection.".format(num_unreachable,
                             (num_unreachable /
                              len(running_obfs4_bridges) *
                              100),
                             len(running_obfs4_bridges)))

    # If a bridge's obfs4 port is not reachable, we need to get in touch with
    # its operator.  We extract contact information from the
    # 'bridge-descriptors' file.

    fpr2contact = get_contact_info("{}/bridge-descriptors".format(
                                   bridgeauth_dir))

    unreachable_fprs = [fpr for fpr, r in fpr2result.items() if not r]
    unreachable_contacts = len([fpr for fpr in fpr2contact.keys()
                                if fpr in unreachable_fprs])
    log("{:,} ({:.1f}%) of {:,} unreachable obfs4 bridges have contact "
        "info.".format(unreachable_contacts,
                       unreachable_contacts / num_unreachable * 100,
                       num_unreachable))

    # Print analysis results, formatted as table, to stdout.

    results = [["Fingerprint", "Address:port", "Contact"]]
    for fpr, reachable in fpr2result.items():
        if not reachable:
            extrainfo_desc = running_obfs4_bridges[fpr]
            addr, port, _ = extrainfo_desc.transport["obfs4"]
            contact = fpr2contact.get(fpr, "N/A")
            results.append([fpr, "{}:{}".format(addr, port), contact])
    print(tabulate.tabulate(results, headers="firstrow"))

    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {} BRIDGEAUTH_DIR".format(sys.argv[0]), file=sys.stderr)
        print("\nBRIDGEAUTH_DIR should point to the directory that the bridge "
              "authority (currently Serge) rsyncs to BridgeDB's host.  The "
              "directory contains the files 'bridge-descriptors', "
              "'cached-extrainfo', 'cached-extrainfo.new', and "
              "'networkstatus-bridges'.", file=sys.stderr)
        sys.exit(1)
    bridgeauth_dir = sys.argv[1]

    sys.exit(main(bridgeauth_dir))
