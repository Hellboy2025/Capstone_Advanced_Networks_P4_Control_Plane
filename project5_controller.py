#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep

import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.convert import decodeIPv4, decodeNum, decodeMac
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2
DST_ID1 = 10
DST_ID2 = 20
request_type=0x8

def writeICMPRules(p4info_helper, sw, sw_dict):
    #print('gets here atleast') # testing output 

    for match,action in sw_dict.items(): 
        IP, Mask = match.split('/')#I only need the IP for the match
       

        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.icmp_match",
            match_fields={
                "hdr.icmp.icmp_type": request_type,
                "hdr.ipv4.dstAddr": IP,  
            },
            action_name="MyIngress.icmp_reply",
            action_params={
            })

        sw.WriteTableEntry(table_entry)
        print(f"Installed ICMP forward rule on {sw.name} for ip: {IP}" )

# TODO 7 define a new function, writeIPv4lpmRules(p4info_helper,sw,sw_dict):
def writeIPv4lpmRules(p4info_helper, sw, sw_dict):
    #print('gets here atleast') # testing output 

    for match,action in sw_dict.items(): 
        IP, Mask = match.split('/')
        Mask = int(Mask)
        MAC = action[0]
        PORT = action[1]

        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (IP, Mask) # tuple 
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": MAC,
                "port": PORT
            })

        sw.WriteTableEntry(table_entry) # write table entry on switch 
        print(f"Installed IPv4 forward rule on {sw.name} to {(IP,Mask)}")

def writeTunnelRules(p4info_helper, ingress_sw, egress_sw, tunnel_id,
                     dst_eth_addr, dst_ip_addr):
    """
    Installs three rules:
    1) An tunnel ingress rule on the ingress switch in the ipv4_lpm table that
       encapsulates traffic into a tunnel with the specified ID
    2) A transit rule on the ingress switch that forwards traffic based on
       the specified ID
    3) An tunnel egress rule on the egress switch that decapsulates traffic
       with the specified ID and sends it to the host

    :param p4info_helper: the P4Info helper
    :param ingress_sw: the ingress switch connection
    :param egress_sw: the egress switch connection
    :param tunnel_id: the specified tunnel ID
    :param dst_eth_addr: the destination IP to match in the ingress rule
    :param dst_ip_addr: the destination Ethernet address to write in the
                        egress rule
    """
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.myTunnel_ingress",
        action_params={
            "dst_id": tunnel_id,
        })
    ingress_sw.WriteTableEntry(table_entry)
    print(f"Installed ingress tunnel rule on {ingress_sw.name} to {dst_ip_addr,32}" )

    # 2) Tunnel Transit Rule
    # The rule will need to be added to the myTunnel_exact table and match on
    # the tunnel ID (hdr.myTunnel.dst_id). Traffic will need to be forwarded
    # using the myTunnel_forward action on the port connected to the next switch.
    #
    # For our simple topology, switch 1 and switch 2 are connected using a
    # link attached to port 2 on both switches. We have defined a variable at
    # the top of the file, SWITCH_TO_SWITCH_PORT, that you can use as the output
    # port for this action.
    #
    # We will only need a transit rule on the ingress switch because we are
    # using a simple topology. In general, you'll need on transit rule for
    # each switch in the path (except the last switch, which has the egress rule),
    # and you will need to select the port dynamically for each switch based on
    # your topology.

    # TODO 1 build the transit rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",
        match_fields={
            "hdr.myTunnel.dst_id": tunnel_id
        },
        action_name="MyIngress.myTunnel_forward",
        action_params={
            "port": SWITCH_TO_SWITCH_PORT
        })

    # TODO 2 install the transit rule on the ingress switch
    ingress_sw.WriteTableEntry(table_entry)
    print(f"Installed tunnel transit rule on {ingress_sw.name} to tunnel ID: {tunnel_id}" )

    # 3) Tunnel Egress Rule
    # For our simple topology, the host will always be located on the
    # SWITCH_TO_HOST_PORT (port 1).
    # In general, you will need to keep track of which port the host is
    # connected to.
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",
        match_fields={
            "hdr.myTunnel.dst_id": tunnel_id
        },
        action_name="MyIngress.myTunnel_egress",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": SWITCH_TO_HOST_PORT
        })
    egress_sw.WriteTableEntry(table_entry)
    print(f"Installed egress tunnel rule on {egress_sw.name} for tunnel ID: {tunnel_id}")


def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print('%s: ' % table_name, end=' ')
            for m in entry.match:
                entry_name = p4info_helper.get_match_field_name(table_name, m.field_id)
                entry_value = p4info_helper.get_match_field_value(m)
                if entry_name == "hdr.ipv4.dstAddr":
                    print(entry_name, end=' ')
                    ip = entry_value[0]
                    mask = entry_value[1]
                    ip = decodeIPv4(ip)
                    entry_value = (ip, mask)
                    print('%r' % (entry_value,), end=' ')
                elif entry_name == 'hdr.myTunnel.dst_id':
                    print(entry_name, end=' ')
                    num = decodeNum(entry_value)
                    print('%r' % num, end=' ')
                else:
                    print(entry_name, end=' ')
                    print('%r' % (entry_value,), end=' ')
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print('->', action_name, end=' ')
            for p in action.params:
                param_name = p4info_helper.get_action_param_name(action_name, p.param_id)       
                if param_name == "dstAddr":
                    l = []
                    for b in p.value:
                        dig = str(hex(b)).split("0x")[1]
                        if len(dig) < 2:
                            dig = "0" + dig
                        l.append(dig)
                    mac = ':'.join(l)
                    print(param_name, end='=')
                    print('%r' % mac, end=', ')
                elif param_name == "port" or param_name == "dst_id":
                    print(param_name, end='=')
                    num = decodeNum(p.value)
                    print('%r' % num, end=', ')
                else:  
                    print(param_name, end='=')
                    print('%r' % p.value, end=', ')
            print()

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print("%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            ))

def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt'
            )
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt'
            )
       # TODO 3 create a switch connection object for s3
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt'
            )
        
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        # TODO 4 astablish this controller as master for s3
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        # TODO 5 set the forwarding pipeline for s3
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")

        # Write the rules that tunnel traffic from h1 to h2
        writeTunnelRules(p4info_helper, ingress_sw=s1, egress_sw=s2, tunnel_id=DST_ID2,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        # Write the rules that tunnel traffic from h2 to h1
        writeTunnelRules(p4info_helper, ingress_sw=s2, egress_sw=s1, tunnel_id=DST_ID1,
                         dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1")
        
        
        # TODO 6 create rules for s2 and s3 using s1_ipv4_rules as a guide.
        
        # Dictionaries holding the next hop ethernet addr and output port based
        # on destination IP at each switch. (IP is key, dest eth and port are
        # vals) Note that switches 1 and 2 are tunneling to IPs 10.0.1.1 and
        # 10.0.2.2, which is why we ignore them. These are passed to
        # writeIPv4lpmRules to be installed on the respective switches.
        s1_ipv4_rules = dict([('10.0.1.1/32', ('08:00:00:00:01:11', 1)), 
                              ('10.0.3.0/24', ('08:00:00:00:03:00', 3)),
                              ('10.0.2.0/24', ('08:00:00:00:02:00', 2))]) 

        s2_ipv4_rules = dict([('10.0.2.2/32', ('08:00:00:00:02:22', 1)),
                              ('10.0.3.0/24', ('08:00:00:00:03:00', 3)), 
                              ('10.0.1.0/24', ('08:00:00:00:01:00', 2))])

        s3_ipv4_rules = dict([('10.0.3.3/32', ('08:00:00:00:03:33', 1)),
                              ('10.0.2.0/24', ('08:00:00:00:01:00', 3)),
                              ('10.0.1.0/24', ('08:00:00:00:02:00', 2))])
        # TODO 8 
        writeIPv4lpmRules(p4info_helper, s1, s1_ipv4_rules) # write rules on s1 
        writeIPv4lpmRules(p4info_helper, s2, s2_ipv4_rules) # write rules on s2 
        writeIPv4lpmRules(p4info_helper, s3, s3_ipv4_rules) # write rules on s3

        s1_ICMP_rules = dict([('10.0.1.10/32', ('08:00:00:00:01:00', 1)), 
                              ]) 

        s2_ICMP_rules = dict([('10.0.2.20/32', ('08:00:00:00:02:00', 1)),
                            ])

        s3_ICMP_rules = dict([('10.0.3.30/32', ('08:00:00:00:03:00', 1))])

        writeICMPRules(p4info_helper, s1, s1_ICMP_rules) # write rules on s1 
        writeICMPRules(p4info_helper, s2, s2_ICMP_rules) # write rules on s2 
        writeICMPRules(p4info_helper, s3, s3_ICMP_rules) 

        
        while True:
            sleep(15)
            print('\n----- Reading tunnel counters -----')
            printCounter(p4info_helper, s1, "MyIngress.ingressTunnelCounter", DST_ID2)
            printCounter(p4info_helper, s2, "MyIngress.egressTunnelCounter", DST_ID2)
            printCounter(p4info_helper, s2, "MyIngress.ingressTunnelCounter", DST_ID1)
            printCounter(p4info_helper, s1, "MyIngress.egressTunnelCounter", DST_ID1)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/project5.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/project5.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
