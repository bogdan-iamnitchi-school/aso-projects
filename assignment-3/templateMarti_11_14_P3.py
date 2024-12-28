"""
Livarbile:
    - Un script care parsează PCAP-uri sau trafic live și detectează următoarele
      atacuri făcute de Mirai: syn, ack, udp, udpplain, greip.
    - Un document după formatul: https://moodle.cs.utcluj.ro/mod/page/view.php?id=46745
      Trebuie să includă toate capitolele. Dacă folosiți acest script, trebuie explicat sumar și
      parțile deja existente.
    - Screenschoturi cu rularea pentru fiecare atac pe captura corespunzătoare lui.
      Capturile se găsesc pe Teams în canalul ASO 2024-2025 și subchannelul Marti_11_14.
      Captura attacks.pcapng conține toate atacurile dar o să dureze mult prea mult procesarea pe ea.

Folosire:
    - Creați un virtualenv pentru acest proiect: virtualenv venv
    - Activați virutalenv-ul creat: source venv/bin/activate
    - Installați pachetul pyshark (https://github.com/KimiNewt/pyshark/): pip install pyshark
    - Rulați scriptul: python templateMarti_11_14_P3.py path/to/capture.pcap

TODO:
    - Completează metodele de check_pachet la clasele derivate din BruteForceAttack.
    - SynAttack este deja implementat și se poate folosi ca model pentru restul metodelor.
    - Odată completat se să decomenteze din funcția main din lista de monitoare.
    - NICETOHAVE: Să nu se dea mai multe detecții pentru același trafic. De exemplu să nu se dea alertă de atac
      UDP și GREIP simultan. Acest lucru se poate obține prin limitele la care se dă alertă, ordinea monitoarele
      la procesarea pachetelor și oprirea procesări de celelalte procesatoare dacă un pachet a fost tratat de
      deja de unul.

Debug hints:
    - Se poate da print(pachet) pentru a vedea conținutul pachetului.
      Asta nu o să meargă dacă este setat la captură use_json=True.
"""

import json
import sys
import subprocess
import argparse

import pyshark


DISPLAY_FILTER = "(tcp || udp || icmp)"


class TCPFlags:
    URG = 32
    ACK = 16
    PSH = 8
    RST = 4
    SYN = 2
    FIN = 1


class BruteForceAttack:
    def check_packet(self, packet):
        raise NotImplementedError()


"""    
Traficul TCP normal începe cu stabilirea unei conexiunea prin facere unui handsake:
    User  ----- SYN ---->  Server
    User  <-- SYN, ACK --  Server
    User  ----- ACK ---->  Server

Când serverul primește un pachet de SYN alocă resurse pentru conexiunea respectivă,
iar dacă le poate aloca cu succes atunci o să răspundă înapoi userului cu acknowledge la SYN.
Resursele consistă în memorie, procesoare, threaduri.
"""


class SynAttack(BruteForceAttack):
    """
    Un atacator poate exploata TCP handshakeul prin anuntarea intentiei de a stabili o conexiune la server.
    Dar când acesta vrea să confirme că dorește să stabilească conexinea, atacatorul dă reset la conexiune.
    Astfel serverul a pierdut timp de procesare, și temporar a alocat resursele pentru client.
    Dar dacă avem un număr uriaș de clienți atunci serverul poate ajunge ca până primește reset de la clinet,
    să nu mai aibă resursele necesarea pentru a stabili conexiuni, astfel utilizatori normali nu vor mai
    putea folosi serviciul.
    """

    def __init__(self):
        # Putem să detectăm dacă un utilizator trimite un număr foarte mare de pachete SYN intr-un interval scurt
        self.bruteforce_timestamps = {}
        self.bruteforce_attack_count = 50  # packets
        self.bruteforce_attack_interval = 2  # seconds
        self.bruteforce_attackers = {}

        # Putem considera mult mai repede că un utilizator este un atacator dacă face mai multe conexiuni la care le
        # dă reset, chiar dacă serverul le acceptă.
        self.connection_timestamp = {}
        self.connection_attack_count = 20
        self.connection_attack_interval = 2
        self.connection_attackers = {}

    def count_bruteforce_attack(self, packet):
        # Atacatorul poate folosi toate porturile sa atace un server deschis la un anumit port.
        key = (packet.ip.src, packet.ip.dst, packet.tcp.dstport)

        start_window = float(packet.sniff_timestamp) - self.bruteforce_attack_interval

        self.bruteforce_timestamps[key] = [t for t in self.bruteforce_timestamps.get(key, []) if t > start_window]
        self.bruteforce_timestamps[key].append(float(packet.sniff_timestamp))

        if len(self.bruteforce_timestamps[key]) >= self.bruteforce_attack_count:
            if key not in self.bruteforce_attackers:
                print(f"\nSYN bruteforce attack from {packet.ip.src} to {packet.ip.dst}:{packet.tcp.dstport}")
            self.bruteforce_attackers[key] = packet.sniff_timestamp
        else:
            if key in self.bruteforce_attackers:
                del self.bruteforce_attackers[key]

    def count_connection_syn_attack(self, packet):
        key = (packet.ip.src, packet.ip.dst, packet.tcp.dstport)

        if key not in self.connection_timestamp:
            self.connection_timestamp[key] = {}

        start_window = float(packet.sniff_timestamp) - self.bruteforce_attack_interval

        self.connection_timestamp[key][packet.tcp.srcport] = [
            info for info in self.connection_timestamp[key].get(packet.tcp.srcport, []) if info["time"] > start_window
        ]

        self.connection_timestamp[key][packet.tcp.srcport].append({
            "time": float(packet.sniff_timestamp),
            "synack": False,  # Serverul a aceptat conexiunea.
            "rst": False  # Clientul a confirmat conexiunea.
        })

        count_acked_connections = sum(
            len([info for info in self.connection_timestamp[key][srcport] if info["rst"] and info["time"] > start_window])
            for srcport in self.connection_timestamp[key]
        )
        if count_acked_connections >= self.connection_attack_count:
            if key not in self.connection_attackers:
                print(f"\nSYN connection attack from {packet.ip.src} to {packet.ip.dst}:{packet.tcp.dstport}")
            self.connection_attackers[key] = packet.sniff_timestamp
        else:
            if key in self.connection_attackers:
                del self.connection_attackers[key]

    def count_connection_synack_attack(self, packet):
        key = (packet.ip.dst, packet.ip.src, packet.tcp.srcport)

        if key not in self.connection_timestamp:
            return

        if packet.tcp.dstport not in self.connection_timestamp[key]:
            return

        for info in self.connection_timestamp[key][packet.tcp.dstport]:
            if not info["synack"]:
                info["synack"] = True
                return

    def count_connection_rst_attack(self, packet):
        key = (packet.ip.src, packet.ip.dst, packet.tcp.dstport)

        if key not in self.connection_timestamp:
            return

        if packet.tcp.srcport not in self.connection_timestamp[key]:
            return

        for info in self.connection_timestamp[key][packet.tcp.srcport]:
            if info["synack"] and not info["rst"]:
                info["rst"] = True
                return

    def check_packet(self, packet):
        if "IPV6" in packet:
            return False
        
        if "TCP" not in packet:
            return

        tcp_flags = int(packet.tcp.flags.raw_value, base=16)

        if tcp_flags == TCPFlags.SYN:
            self.count_bruteforce_attack(packet)
            self.count_connection_syn_attack(packet)

        elif tcp_flags == (TCPFlags.SYN | TCPFlags.ACK):
            self.count_connection_synack_attack(packet)

        elif tcp_flags == TCPFlags.RST:
            self.count_connection_rst_attack(packet)


class AckAttack:
    """
    Un atacator care dorește să atace un server ce folosește TCP, poate să trimită pachete
    cu flagul ACK cu date random, la care serverul trebuie să răspundă cu reset, deoarce nu
    s-a stabilit inițial o conexiune.
    """
    def __init__(self):
        self.ack_timestamps = {}
        self.ack_attack_count = 50
        self.ack_attack_interval = 2
        self.ack_attackers = {}

    def count_bruteforce_attack(self, packet):
        key = (packet.ip.src, packet.ip.dst, packet.tcp.dstport)
        start_window = float(packet.sniff_timestamp) - self.ack_attack_interval

        self.ack_timestamps[key] = [
            t for t in self.ack_timestamps.get(key, []) if t > start_window
        ]
        self.ack_timestamps[key].append(float(packet.sniff_timestamp))

        if len(self.ack_timestamps[key]) >= self.ack_attack_count:
            if key not in self.ack_attackers:
                print(f"\nACK attack from {packet.ip.src} to {packet.ip.dst}:{packet.tcp.dstport}")
            self.ack_attackers[key] = packet.sniff_timestamp
            return True
        else:
            if key in self.ack_attackers:
                del self.ack_attackers[key]
        return False

    # HINT: La fel ca la SynAttack când numărăm conexiunile, salvăm ACK-urile și dacă li se răspunde cu RST
    # pentru un număr sufient de mare se poate considera un atac.
    def check_packet(self, packet):
        if "IPV6" in packet:
            return False

        if "TCP" not in packet:
            return

        tcp_flags = int(packet.tcp.flags.raw_value, base=16)
        if tcp_flags == TCPFlags.ACK:
            return self.count_bruteforce_attack(packet)
        return False


"""
Protocolul UDP nu se bazează pe o conexiune prealabilă. Dacă un client are ceva de transmis, trimite direct,
și traficul poate ajunge sau nu la server. Serverul de asemnea nu trebuie să confirme dacă a primit ceva.

Totuși când se primesc ceva date, serverul o să le proceseze, astfel se poate ajunge la epuizarea resurselor
dacă există un număr mare de clienți care trimit date simultan.
"""


class UdpAttack:
    """
    Atacatorul trimite de pe toate porturile pachete UDP de o lungime fixă cu date random de pe toate porturile
    catre server. Faptul că se folosesc prea multe porturi de la client spre același port este un factor notabil
    pentru identificarea acestui atatc.
    """
    def __init__(self):
        self.udp_ports = {}
        self.udp_attack_count = 50
        self.udp_attack_interval = 2
        self.udp_packet_size = {}
        self.udp_attackers = {}

    def count_bruteforce_attack(self, packet):
        key = (packet.ip.src, packet.ip.dst, packet.udp.dstport, packet.udp.length)

        start_window = float(packet.sniff_timestamp) - self.udp_attack_interval

        self.udp_ports[key] = [
            t for t in self.udp_ports.get(key, []) if t > start_window
        ]
        self.udp_ports[key].append(float(packet.sniff_timestamp))

        if (len(self.udp_ports[key]) >= self.udp_attack_count):
            if key not in self.udp_attackers:
                print(f"\nUDP attack from {packet.ip.src} to {packet.ip.dst}:{packet.udp.dstport}")
            self.udp_attackers[key] = packet.sniff_timestamp
            return True
        else:
            if key in self.udp_attackers:
                del self.udp_attackers[key]
        return False

    # HINT: La fel ca la SynAttack când numărăm conexiunile, salvăm fiecare port și dacă se folosesc prea multe
    # porturi, atunci se poate considera un atac. Pentru condiții suplimentare, Mirai o să trimită toate pachetele
    # cu aceași mărime. Astfel pentru un port putem salva și mărimea pachetului UDP și să o comprăm să fie egală.
    # Mărimea se poate obține cu: int(packet.udp.length).
    # Atenție: Mărimea nu o să fie mereu 512/520, atacatorul putând să o aleagă.
    def check_packet(self, packet):
        if "IPV6" in packet:
            return False
        
        if "UDP" not in packet:
            return False

        return self.count_bruteforce_attack(packet)


class UdpPlainAttack:
    """
    O subclasa a atacului UDP in care atacatorul trimite de pe acelasi port, pachete UDP de o lungime fixă cu date
    random. Este optimizat pentru un numar mai mare de pachete pe secundă.
    Nu putem să identificăm cu ușurință acest atatc intr-un setup real, deoarce dacă o aplicație de a noastră folosește
    protocolul UDP, traficul acestui atac poate să fie similar cu cel normal.
    """
    def __init__(self):
        self.udp_plain_timestamps = {}
        self.udp_plain_attack_count = 50
        self.udp_plain_attack_interval = 2
        self.udp_plain_packet_size = {}
        self.udp_plain_attackers = {}

    def count_bruteforce_attack(self, packet):
        key = (packet.ip.src, packet.ip.dst, packet.udp.dstport, packet.udp.srcport, packet.udp.length)

        start_window = float(packet.sniff_timestamp) - self.udp_plain_attack_interval

        self.udp_plain_timestamps[key] = [
            t for t in self.udp_plain_timestamps.get(key, []) if t > start_window
        ]
        self.udp_plain_timestamps[key].append(float(packet.sniff_timestamp))

        if (len(self.udp_plain_timestamps[key]) >= self.udp_plain_attack_count):
            if key not in self.udp_plain_attackers:
                print(f"\nUDP Plain attack from {packet.ip.src} to {packet.ip.dst}:{packet.udp.dstport}")
            self.udp_plain_attackers[key] = packet.sniff_timestamp
            return True
        else:
            if key in self.udp_plain_attackers:
                del self.udp_plain_attackers[key]
        return False

    # HINT: La fel ca la UdpAttack, numai că o fie un singur port sursă, aceași mărime a headerului UDP, și o setare
    # hardcodată în Mirai, are setat flagul de "Don't fragment" în headerul IP.
    def check_packet(self, packet):
        if "IPV6" in packet:
            return False

        if "UDP" not in packet:
            return False

        # Dacă nu conține flagul "Don't fragment"
        if hex(packet.ip.flags.hex_value) != "0x2":
            return False

        return self.count_bruteforce_attack(packet)

import json


class GreIpAttack:
    """
    Generic Routing Encapsulation (https://www.cloudflare.com/learning/network-layer/what-is-gre-tunneling/) este un
    protocol de incapsulare a unui pachet IP pentru a travesra o rețea virtuală point to point.

    Acesta poate fi folosit pentru un atac brute force prin trimiterea unor adrese random sau unreacheable, pe care
    serverul o să încerce să determine dacă sunt accesbile. Dacă sunt accesbile o să încerce să redirecteze pachetul
    spre destinație. Altfel o să răspundă împoi un pachet ICMP cu Destination unrecheable.

    In ambele cazuri se folosesc resurse, care la un numar mare de utilizatori, pot să fie epuizate.
    """

    # HINT: Ne uitam după următoarele informați:
    #   - ip.src, ip.dst, ip.dstport constante
    #   - orice port sursa
    #   - aceasi marime a headerului UDP
    #   - aceasi adresa sursa in al doilea header ip.

    def __init__(self):
        # Putem să detectăm dacă un utilizator trimite un număr foarte mare de pachete SYN intr-un interval scurt
        self.bruteforce_timestamps = {}
        self.bruteforce_attack_count = 50  # packets
        self.bruteforce_attack_interval = 2  # seconds
        self.bruteforce_attackers = {}

    def count_bruteforce_attack(self, packet, ip_layer2):
        # Atacatorul poate folosi toate porturile sa atace un server deschis la un anumit port.
        key = (packet.ip.src, packet.udp.dstport, packet.ip.dst, ip_layer2.src)
        start_window = float(packet.sniff_timestamp) - self.bruteforce_attack_interval

        self.bruteforce_timestamps[key] = [
            (t, ip) for t, ip in self.bruteforce_timestamps.get(key, []) if t > start_window
        ]
        self.bruteforce_timestamps[key].append((float(packet.sniff_timestamp), ip_layer2.dst))

        uniq_ips = set([ip for t, ip in self.bruteforce_timestamps[key]])

        if len(uniq_ips) >= self.bruteforce_attack_count:
            if key not in self.bruteforce_attackers:
                print(
                    f"\nGRE bruteforce attack from {packet.ip.src}:{packet.udp.srcport} to {packet.ip.dst}:{packet.udp.dstport}")
            self.bruteforce_attackers[key] = packet.sniff_timestamp
            return True
        else:
            if key in self.bruteforce_attackers:
                del self.bruteforce_attackers[key]
        return False

    def check_packet(self, packet):
        if "GRE" not in packet or "UDP" not in packet:
            return False

        ip_header2 = packet.layers[3]

        # Ne asigurăm că avem un header IP.
        if not ip_header2.has_field("proto") or ip_header2.proto.showname_value.split()[0] != "UDP":
            return False

        return self.count_bruteforce_attack(packet, ip_header2)


total_packets_count = None


def print_progress_bar(index, label=""):
    if total_packets_count:
        n_bar = 75  # Progress bar width
        progress = index / total_packets_count
        sys.stdout.write('\r')
        sys.stdout.write(f"[{'=' * int(n_bar * progress):{n_bar}s}] {int(100 * progress)}%  {label}")
        sys.stdout.flush()


def print_progress_dot(index):
    if index % 2000 == 0:
        print(".", end="", flush=True)


def count_packets(file_path):
    try:
        cmd = ["capinfos", "-c", "-M", file_path]
        output = subprocess.check_output(cmd)
        """ Example output:
        File name:           file/path
        Number of packets:   INT_SIZE
        """
        output = output.decode("utf-8")
        lines = output.splitlines()

        number = int(lines[-1].rsplit(" ", maxsplit=1)[-1])
        print(f"Number of packets in capture is {number}.")

        global total_packets_count
        total_packets_count = number
    except:
        print("Failed to get the number of packets from the capture.")
        pass


def parse_args():
    parser = argparse.ArgumentParser(description="Determine the presence of Mirai attacks.")
    parser.add_argument(
        "capture_path",
        type=str,
        help="Path to the captured .pcapng file"
    )
    parser.add_argument(
        "-s", "--show_progress_bar",
        action="store_true",
        help="Display a progress bar during processing"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print(f"Parsing {args.capture_path} for attacks")
    cap = pyshark.FileCapture(
        args.capture_path,
        display_filter=DISPLAY_FILTER,  # Include only relevant packets.
        # use_json=True,  # Improve parsing speed.
        include_raw=False,  # Improve parsing speed but strip some raw values.
        custom_parameters={"-j": "frame ip udp tcp"}  # Filter only the desired protocols to also improve speed.
    )

    if args.show_progress_bar:
        count_packets(args.capture_path)

    attack_monitors = [
        SynAttack(),
        AckAttack(),
        GreIpAttack(),
        UdpPlainAttack(),
        UdpAttack(),
    ]

    index = 0
    for packet in cap:
        is_processed = False
        if args.show_progress_bar:
            print_progress_bar(index)
        else:
            print_progress_dot(index)
        for monitor in attack_monitors:
            if not is_processed:
                is_processed = monitor.check_packet(packet) or is_processed
        index += 1


if __name__ == '__main__':
    main()
