#!/usr/bin/env python3
"""
EnumPy Automatized – Intelligent network scanner with automatic host discovery and port enumeration.
"""

import argparse
import logging
import re
import socket
import warnings
from ipaddress import ip_network

warnings.filterwarnings("ignore", category=SyntaxWarning, module="scapy.*")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.all import ARP, Ether, ICMP, IP, TCP, UDP, srp, sr, sr1, conf, Raw
conf.verb = 0

# Common port lists for TCP and UDP scanning
COMMON_TCP_PORTS = [
    1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389
]

COMMON_UDP_PORTS = [
    2,3,7,9,13,17,19,20,21,22,23,37,38,42,49,53,67,68,69,80,88,111,112,113,120,123,135,136,137,138,139,158,161,162,177,192,199,207,217,363,389,402,407,427,434,443,445,464,497,500,502,512,513,514,515,517,518,520,539,559,593,623,626,631,639,643,657,664,682,683,684,685,686,687,688,689,764,767,772,773,774,775,776,780,781,782,786,789,800,814,826,829,838,902,903,944,959,965,983,989,990,996,997,998,999,1000,1001,1007,1008,1012,1013,1014,1019,1020,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1053,1054,1055,1056,1057,1058,1059,1060,1064,1065,1066,1067,1068,1069,1070,1072,1080,1081,1087,1088,1090,1100,1101,1105,1124,1200,1214,1234,1346,1419,1433,1434,1455,1457,1484,1485,1524,1645,1646,1701,1718,1719,1761,1782,1804,1812,1813,1885,1886,1900,1901,1993,2000,2002,2048,2049,2051,2148,2160,2161,2222,2223,2343,2345,2362,2967,3052,3130,3283,3296,3343,3389,3401,3456,3457,3659,3664,3702,3703,4000,4008,4045,4444,4500,4666,4672,5000,5001,5002,5003,5010,5050,5060,5093,5351,5353,5355,5500,5555,5632,6000,6001,6002,6004,6050,6346,6347,6970,6971,7000,7938,8000,8001,8010,8181,8193,8900,9000,9001,9020,9103,9199,9200,9370,9876,9877,9950,10000,10080,11487,16086,16402,16420,16430,16433,16449,16498,16503,16545,16548,16573,16674,16680,16697,16700,16708,16711,16739,16766,16779,16786,16816,16829,16832,16838,16839,16862,16896,16912,16918,16919,16938,16939,16947,16948,16970,16972,16974,17006,17018,17077,17091,17101,17146,17184,17185,17205,17207,17219,17236,17237,17282,17302,17321,17331,17332,17338,17359,17417,17423,17424,17455,17459,17468,17487,17490,17494,17505,17533,17549,17573,17580,17585,17592,17605,17615,17616,17629,17638,17663,17673,17674,17683,17726,17754,17762,17787,17814,17823,17824,17836,17845,17888,17939,17946,17989,18004,18081,18113,18134,18156,18228,18234,18250,18255,18258,18319,18331,18360,18373,18449,18485,18543,18582,18605,18617,18666,18669,18676,18683,18807,18818,18821,18830,18832,18835,18869,18883,18888,18958,18980,18985,18987,18991,18994,18996,19017,19022,19039,19047,19075,19096,19120,19130,19140,19141,19154,19161,19165,19181,19193,19197,19222,19227,19273,19283,19294,19315,19322,19332,19374,19415,19482,19489,19500,19503,19504,19541,19600,19605,19616,19624,19625,19632,19639,19647,19650,19660,19662,19663,19682,19683,19687,19695,19707,19717,19718,19719,19722,19728,19789,19792,19933,19935,19936,19956,19995,19998,20003,20004,20019,20031,20082,20117,20120,20126,20129,20146,20154,20164,20206,20217,20249,20262,20279,20288,20309,20313,20326,20359,20360,20366,20380,20389,20409,20411,20423,20424,20425,20445,20449,20464,20465,20518,20522,20525,20540,20560,20665,20678,20679,20710,20717,20742,20752,20762,20791,20817,20842,20848,20851,20865,20872,20876,20884,20919,21000,21016,21060,21083,21104,21111,21131,21167,21186,21206,21207,21212,21247,21261,21282,21298,21303,21318,21320,21333,21344,21354,21358,21360,21364,21366,21383,21405,21454,21468,21476,21514,21524,21525,21556,21566,21568,21576,21609,21621,21625,21644,21649,21655,21663,21674,21698,21702,21710,21742,21780,21784,21800,21803,21834,21842,21847,21868,21898,21902,21923,21948,21967,22029,22043,22045,22053,22055,22105,22109,22123,22124,22341,22692,22695,22739,22799,22846,22914,22986,22996,23040,23176,23354,23531,23557,23608,23679,23781,23965,23980,24007,24279,24511,24594,24606,24644,24854,24910,25003,25157,25240,25280,25337,25375,25462,25541,25546,25709,25931,26407,26415,26720,26872,26966,27015,27195,27444,27473,27482,27715,27892,27899,28122,28369,28465,28493,28543,28547,28641,28840,28973,29078,29243,29256,29810,29823,29977,30263,30303,30365,30544,30656,30697,30704,30718,30975,31059,31073,31109,31189,31195,31335,31337,31365,31625,31681,31731,31891,32345,32385,32528,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32798,32815,32818,32931,33030,33249,33281,33354,33355,33459,33717,33744,33866,33872,34038,34079,34125,34358,34422,34433,34555,34570,34577,34578,34579,34580,34758,34796,34855,34861,34862,34892,35438,35702,35777,35794,36108,36206,36384,36458,36489,36669,36778,36893,36945,37144,37212,37393,37444,37602,37761,37783,37813,37843,38037,38063,38293,38412,38498,38615,39213,39217,39632,39683,39714,39723,39888,40019,40116,40441,40539,40622,40708,40711,40724,40732,40805,40847,40866,40915,41058,41081,41308,41370,41446,41524,41638,41702,41774,41896,41967,41971,42056,42172,42313,42431,42434,42508,42557,42577,42627,42639,43094,43195,43370,43514,43686,43824,43967,44101,44160,44179,44185,44190,44253,44334,44508,44923,44946,44968,45247,45380,45441,45685,45722,45818,45928,46093,46532,46836,47624,47765,47772,47808,47915,47981,48078,48189,48255,48455,48489,48761,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49162,49163,49165,49166,49167,49168,49169,49170,49171,49172,49173,49174,49175,49176,49177,49178,49179,49180,49181,49182,49184,49185,49186,49187,49188,49189,49190,49191,49192,49193,49194,49195,49196,49197,49198,49199,49200,49201,49202,49204,49205,49207,49208,49209,49210,49211,49212,49213,49214,49215,49216,49220,49222,49226,49259,49262,49306,49350,49360,49393,49396,49503,49640,49968,50099,50164,50497,50612,50708,50919,51255,51456,51554,51586,51690,51717,51905,51972,52144,52225,52503,53006,53037,53571,53589,53838,54094,54114,54281,54321,54711,54807,54925,55043,55544,55587,56141,57172,57409,57410,57813,57843,57958,57977,58002,58075,58178,58419,58631,58640,58797,59193,59207,59765,59846,60172,60381,60423,61024,61142,61319,61322,61370,61412,61481,61550,61685,61961,62154,62287,62575,62677,62699,62958,63420,63555,64080,64481,64513,64590,64727,65024
]

# Quick port lists (top 20 ports for fast scanning)
QUICK_TCP_PORTS = [21, 22, 23, 25, 443, 53, 80, 110, 135, 139, 143, 445, 993, 995, 111, 1723, 3306, 3389, 5900, 8080]
QUICK_UDP_PORTS = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 49152]

# Host Discovery Functions
def icmp_ping(targets):
    """Send ICMP echo requests to discover live hosts."""
    ans, _ = sr(IP(dst=targets) / ICMP(), timeout=2, verbose=False)
    return [rcv.src for _, rcv in ans]

def arp_ping(targets):
    """Send ARP requests on local network to discover hosts."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=" ".join(targets))
    ans, _ = srp(pkt, timeout=2, verbose=False)
    return [rcv.psrc for _, rcv in ans]

def tcp_ping(targets, port=80):
    """Send TCP SYN packets to discover hosts via SYN-ACK response."""
    ans, _ = sr(IP(dst=targets) / TCP(dport=port, flags="S"), timeout=2, verbose=False)
    return [rcv.src for _, rcv in ans if rcv.haslayer(TCP)]

def udp_ping(targets, ports=[53, 161, 1900, 40123]):
    """
    Send UDP packets to multiple ports to increase detection rate.
    Relies on ICMP port unreachable responses from closed ports.
    """
    packets = [IP(dst=t)/UDP(dport=p) for t in targets for p in ports]
    ans, _ = sr(packets, timeout=2, verbose=False)
    return list({rcv.src for _, rcv in ans if rcv.haslayer(ICMP) and rcv[ICMP].type == 3 and rcv[ICMP].code == 3})

# Port Scanning Functions
def syn_scan(host, ports):
    """Perform SYN scan and return open ports (SYN-ACK response)."""
    ans, _ = sr(IP(dst=host) / TCP(dport=ports, flags="S"), timeout=2, verbose=False)
    return [int(r["TCP"].sport) for _, r in ans if r.haslayer(TCP) and r["TCP"].flags == 0x12]

def tcp_connect_scan(host, ports):
    """Perform full TCP connect scan using native sockets."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
        except (socket.timeout, socket.error):
            continue
    return sorted(open_ports)

def ack_scan(host, ports):
    """
    Detect firewall filtering by sending ACK packets.
    Returns (unfiltered, filtered, open) port lists.
    """
    unfiltered = []
    filtered = []
    open_ports = []

    ans, unans = sr(IP(dst=host) / TCP(dport=ports, flags="A"), timeout=2, verbose=False)

    for _, r in ans:
        if r.haslayer(TCP):
            flags = r["TCP"].flags
            port = int(r["TCP"].sport)
            if flags == 0x12:  # SYN-ACK
                open_ports.append(port)
            elif flags == 0x04:  # RST
                unfiltered.append(port)

    for pkt in unans:
        filtered.append(int(pkt["TCP"].dport))

    return sorted(set(unfiltered)), sorted(set(filtered)), sorted(set(open_ports))

def udp_scan(host, ports):
    """
    Scan UDP ports using generic payload.
    Returns (open, closed, open|filtered) ports.
    """
    GENERIC_PAYLOAD = b"X"

    open_ports = []
    closed_ports = []
    open_or_filtered = []

    packets = [
        IP(dst=host)/UDP(dport=port)/Raw(load=GENERIC_PAYLOAD)
        for port in ports
    ]
    ans, unans = sr(packets, timeout=3, verbose=False)

    for sent, received in ans:
        port = sent[UDP].dport
        if received.haslayer(ICMP):
            if received[ICMP].type == 3 and received[ICMP].code == 3:
                closed_ports.append(port)
        else:
            open_ports.append(port)

    for pkt in unans:
        open_or_filtered.append(pkt[UDP].dport)

    return sorted(set(open_ports)), sorted(set(closed_ports)), sorted(set(open_or_filtered))

# Banner Grabbing Functions
def grab_banner(host, port, timeout=4.0):
    """
    Retrieve service banner from TCP port.
    Handles HTTP services specially with proper headers.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in {80, 443, 8080, 8000, 8443}:
                req = (b"GET / HTTP/1.0\r\nHost: " + host.encode() +
                       b"\r\n\r\n")
                sock.send(req)
                hdr = sock.recv(1024).decode(errors="ignore")
                if not hdr:
                    return "(no banner)"

                lines = hdr.splitlines()
                status = lines[0] if lines else ""
                server = re.search(r"Server:\s*([^\r\n]+)", hdr, re.I)
                powered = re.search(r"X-Powered-By:\s*([^\r\n]+)", hdr, re.I)

                parts = [status]
                if server:
                    parts.append(f"Server: {server.group(1).strip()}")
                if powered:
                    parts.append(f"Powered: {powered.group(1).strip()}")

                return " | ".join(parts)
            data = sock.recv(1024)
            if not data:
                return "(no banner)"
            line = data.splitlines()[0].decode(errors="ignore").strip()
            return line
    except Exception:
        return "(no banner)"

def grab_udp_banner(host, port, timeout=3.0):
    """Retrieve UDP service banner with minimal probe."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"X", (host, port))
            data, _ = s.recvfrom(2048)
            if data:
                response = data.decode('utf-8', errors='ignore').strip()
                if response:
                    first_line = response.splitlines()[0][:100]
                    return first_line
                else:
                    return f"UDP reply ({len(data)} B)"
            else:
                return f"UDP reply ({len(data)} B)"
    except socket.timeout:
        return "(udp: no response)"
    except Exception:
        return "(udp: error)"

def os_fingerprint(host, open_ports, banners=None):
    """
    Determine OS using banner analysis and network characteristics.
    Prioritizes HTTP banners, then TTL and common port patterns.
    """
    # Check HTTP banners first for reliable OS identification
    if banners:
        for banner in banners.values():
            if "HTTP" in banner:
                if "Microsoft-IIS" in banner or "ASP.NET" in banner:
                    return "Windows (HTTP: Microsoft-IIS/ASP.NET)"
                if "(Ubuntu)" in banner:
                    return "Linux (Ubuntu) (HTTP banner)"
                if "(Debian)" in banner:
                    return "Linux (Debian) (HTTP banner)"
                if "nginx" in banner or "Apache" in banner:
                    return "Likely Linux (HTTP server) (HTTP banner)"

    # Get TTL from network response
    for port in [80, 443, 22, 21, *open_ports[:2]]:
        pkt = sr1(IP(dst=host)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        if pkt:
            ttl = pkt[IP].ttl
            break
    else:
        pkt = sr1(IP(dst=host)/ICMP(), timeout=1, verbose=0)
        ttl = pkt[IP].ttl if pkt else None

    if ttl is None:
        return "Detection failed"

    # Analyze TTL and common ports
    has_windows = any(p in open_ports for p in [135, 139, 445, 3389])
    has_linux = 22 in open_ports

    if has_windows:
        if ttl > 64 and ttl <= 128:
            return f"Windows (SMB/RDP ports + TTL>64 = Common Windows Configuration)"
        else:
            return f"Very likely Windows (SMB/RDP ports but modified TTL)"

    if ttl <= 64:
        if has_linux:
            return f"Likely Linux server (SSH port + TTL<=64 = Linux default)"
        else:
            return f"Likely Linux (TTL<=64 = Linux Default TTL)"
    elif ttl <= 128:
        return f"Likely Windows (TTL>64 = Windows Default TTL)"
    else:
        return f"Network device (TTL>128 = router/switch default)"

# Utility Functions
def parse_targets(raw):
    """Parse target specification into individual IP addresses."""
    result = []
    for part in raw.split(","):
        part = part.strip()
        try:
            if "/" in part:
                net = ip_network(part, strict=False)
                result.extend(str(ip) for ip in net.hosts())
            else:
                result.append(part)
        except Exception:
            print(f"[WARN] Invalid target '{part}' – skipped.")
    return result

def parse_port_arg(arg, common_list, all_ports=list(range(1, 65536)), quick_list=None):
    """
    Parse port specification string into port list and description.
    Handles 'all', 'quick', 'common', and custom ranges.
    """
    arg = arg.lower()
    if arg == "all":
        return all_ports, "all ports"
    elif arg == "quick":
        if quick_list:
            return quick_list, f"quick scan ({len(quick_list)} common ports)"
        else:
            return common_list, f"top {len(common_list)} common ports"
    elif arg == "" or arg == "common":
        return common_list, f"top {len(common_list)} common ports"
    else:
        ports = set()
        for chunk in arg.split(","):
            chunk = chunk.strip()
            if "-" in chunk:
                try:
                    start, end = map(int, chunk.split("-", 1))
                    if start > end:
                        print(f"[WARN] Invalid range '{chunk}' – skipped.")
                        continue
                    ports.update(range(start, end + 1))
                except ValueError:
                    print(f"[WARN] Invalid port range '{chunk}' – skipped.")
                    continue
            else:
                try:
                    ports.add(int(chunk))
                except ValueError:
                    print(f"[WARN] Invalid port '{chunk}' – skipped.")
                    continue
        return sorted(ports), f"{len(ports)} specified port(s)"

# Automatic Host Discovery
def auto_discovery(targets):
    """Discover live hosts using multiple scanning techniques."""
    methods = [
        ("ICMP", icmp_ping),
        ("ARP", arp_ping),
        ("TCP", lambda t: tcp_ping(t, 80)),
        ("UDP", udp_ping),
    ]

    host_methods = {}
    discovered_hosts = set()

    for name, func in methods:
        print(f"Trying {name} ping...")
        new_hosts = func(targets)
        for host in new_hosts:
            if host not in host_methods:
                host_methods[host] = []
            if name not in host_methods[host]:
                host_methods[host].append(name)
            discovered_hosts.add(host)
        if new_hosts:
            print(f"  Found {len(new_hosts)} hosts via {name}")
        else:
            print(f"  No hosts found via {name}")

    return sorted(discovered_hosts), host_methods

# Simplified Port Scanning
def auto_port_scan(host, tcp_ports=None, udp_ports=None):
    """
    Perform comprehensive port scanning with firewall detection.
    Returns scan results and methods used.
    """
    results = {
        "tcp": [], 
        "udp": {"open": [], "closed": [], "open|filtered": []},
        "firewall": {"unfiltered": [], "filtered": [], "open": [], "status": "unknown"}
    }
    tcp_method = None
    udp_method = None

    # Firewall Detection - ACK Scan (must run first)
    if tcp_ports:
        print(f"Detecting firewall on {host}...")
        unfiltered, filtered, open_ports = ack_scan(host, tcp_ports)

        if filtered and not unfiltered:
            firewall_status = "firewall present (all ports filtered)"
        elif filtered and unfiltered:
            firewall_status = "partial firewall (some ports filtered)"
        elif not filtered and unfiltered:
            firewall_status = "no firewall detected"
        else:
            firewall_status = "unknown firewall status"

        results["firewall"] = {
            "unfiltered": sorted(unfiltered),
            "filtered": sorted(filtered),
            "open": sorted(open_ports),
            "status": firewall_status
        }
        print(f"  Firewall status: {firewall_status}")
        if filtered:
            print(f"  {len(filtered)} filtered port(s) detected")

    # TCP Scan - First try SYN scan (faster and stealthier)
    if tcp_ports:
        print(f"Scanning TCP ports on {host}...")
        open_tcp = syn_scan(host, tcp_ports)

        # If SYN scan found nothing, try TCP Connect as fallback
        if not open_tcp and tcp_ports:
            open_tcp = tcp_connect_scan(host, tcp_ports)
            tcp_method = "Connect" if open_tcp else None
        else:
            tcp_method = "SYN" if open_tcp else None

        results["tcp"] = sorted(open_tcp)

    # UDP Scan - Corrected to capture all results
    if udp_ports:
        print(f"Scanning UDP ports on {host}...")
        open_udp, closed_udp, open_filtered_udp = udp_scan(host, udp_ports)
        if open_udp or closed_udp or open_filtered_udp:
            udp_method = "UDP"
            results["udp"] = {
                "open": sorted(open_udp),
                "closed": sorted(closed_udp),
                "open|filtered": sorted(open_filtered_udp)
            }

    return results, tcp_method, udp_method

# Main
def main():
    parser = argparse.ArgumentParser(
        usage="%(prog)s TARGETS [SCAN_OPTIONS...]",
        description="EnumPy – Intelligent scanner with auto host discovery, port scan, banners and OS.",
        epilog="""
Port scan options:
  - 'tcp'          → scan top 1000 common TCP ports (alias for 'tcp:common')
  - 'tcp:common'   → scan top 1000 common TCP ports
  - 'tcp:all'      → scan all TCP ports (1-65535)
  - 'tcp:quick'    → scan 20 most common TCP ports
  - 'tcp:80,443'   → scan specific TCP ports
  - 'udp'          → scan top 1000 common UDP ports (alias for 'udp:common')
  - 'udp:common'   → scan top 1000 common UDP ports
  - 'udp:all'      → scan all UDP ports
  - 'udp:quick'    → scan 20 most common UDP ports
  - 'udp:53,161'   → scan specific UDP ports
  - No scan option → only discover hosts and fingerprint OS
  You can combine: tcp udp:53,161""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("targets", help="Target(s): IP or CIDR network")
    parser.add_argument("scan_options", nargs="*", help="Scan options: tcp, udp, tcp:all, udp:quick, etc. See examples above.")

    args = parser.parse_args()

    # Parse target specification into individual IPs
    targets = parse_targets(args.targets)

    # Parse scan options: process each option to determine TCP/UDP ports to scan
    tcp_ports = None
    udp_ports = None
    scan_descriptions = []

    for opt in args.scan_options:
        opt = opt.strip()
        if ":" in opt:
            proto, port_arg = opt.split(":", 1)
        else:
            proto, port_arg = opt, "common"  # Default: tcp → tcp:common, udp → udp:common

        proto = proto.lower()
        port_arg = port_arg.strip()

        if proto == "tcp":
            ports, desc = parse_port_arg(
                port_arg,
                common_list=COMMON_TCP_PORTS,
                quick_list=QUICK_TCP_PORTS
            )
            tcp_ports = ports
            scan_descriptions.append(f"TCP ({desc})")
        elif proto == "udp":
            ports, desc = parse_port_arg(
                port_arg,
                common_list=COMMON_UDP_PORTS,
                quick_list=QUICK_UDP_PORTS
            )
            udp_ports = ports
            scan_descriptions.append(f"UDP ({desc})")
        else:
            parser.error(f"Unknown protocol in '{opt}'. Use 'tcp' or 'udp'.")

    # Host Discovery Phase
    print("-> Starting automated host discovery...")
    alive_hosts, host_methods = auto_discovery(targets)

    # Display discovered hosts
    if alive_hosts:
        print("-> Hosts discovered:")
        for h in alive_hosts:
            methods_used = ", ".join(host_methods[h])
            print(f"  {h} ({methods_used})")
    else:
        print("-> No hosts discovered")

    # Decide scan mode based on provided options
    if not tcp_ports and not udp_ports:
        print("\n-> No port scan requested. Performing OS fingerprinting only...")
        for host in alive_hosts:
            print(f"\n-> Host: {host}")
            guess = os_fingerprint(host, [])  # No open ports known
            print(f"  OS: {guess}")
        return  # Exit after OS scan

    # Port Scanning Phase
    scan_desc = ", ".join(scan_descriptions)
    print(f"\n-> Starting automated port scan ({scan_desc})...")
    for host in alive_hosts:
        port_results, tcp_method, udp_method = auto_port_scan(host, tcp_ports, udp_ports)

        print(f"\n-> Host: {host}")

        # Display firewall information first for context
        if port_results["firewall"]["status"] != "unknown":
            print(f"  Firewall: {port_results['firewall']['status']}")
            if port_results["firewall"]["filtered"]:
                print(f"  Filtered ports: {port_results['firewall']['filtered'][:6]}")

        # Display TCP results
        if port_results["tcp"]:
            print(f"  TCP ports discovered via {tcp_method}: {port_results['tcp']}")

        # Display UDP results
        if udp_method:
            if port_results["udp"]["open"]:
                print(f"  UDP ports open: {port_results['udp']['open']}")
            if port_results["udp"]["closed"]:
                print(f"  UDP ports closed: {port_results['udp']['closed']}")
            if port_results["udp"]["open|filtered"]:
                print(f"  UDP ports open|filtered: {port_results['udp']['open|filtered']}")

        # Banner grabbing for discovered ports
        all_ports = sorted(set(port_results["tcp"] + port_results["udp"]["open"]))
        banners = {}

        if all_ports:
            print("  Banners:")
            for p in all_ports:
                if p in port_results["udp"]["open"]:
                    banner = grab_udp_banner(host, p)
                else:
                    banner = grab_banner(host, p)
                print(f"    {p}: {banner}")
                banners[p] = banner
        else:
            print("  No ports discovered")

        # OS Fingerprinting
        guess = os_fingerprint(host, port_results["tcp"], banners=banners)
        print(f"  OS: {guess}\n")

if __name__ == "__main__":
    main()
