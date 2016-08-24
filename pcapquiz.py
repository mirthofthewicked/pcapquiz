from scapy.all import *
import argparse
from colors import *
#from IPy import IP

# At some point, add what the correct value is (DONE!!) and why *(LOL)*

def quiz(filename, hr):
    pcaps=rdpcap(filename)

    IPv4TableHelp ="""
        |   0   |   1   |   2   |   3   |
      0 |VER|IHL|  TOS  |  Total length |
      4 |    IP Ident   |XDM |  Offset  |
      8 |  TTL  | Proto |    Checksum   |
      12|        SOURCE ADDRESS         |
      16|     DESTINATION ADDRESS       |
      20|            OPTIONS            |
    """

    TCPTableHelp = """
        |   0   |   1   |   2   |   3   |
      0 |  Source Port  |  Dest.  Port  |
      4 |        Sequence Number        |
      8 |     Acknowledgement Number    |
      12| HL | R | Flag |  Window size  |
      16|   Checksum    | Urgent Pointer|
      20|    OPTIONS (up to 40 bytes)   |
    """

    UDPTableHelp = """
        |   0   |   1   |   2   |   3   |
      0 |  Source Port  |  Dest.  Port  |
      4 |     Length    |    Checksum   |
    """

    DNSTableHelp = """
        |   0   |   1   |   2   |   3   |
      0 |    Query ID   |     Flags     |
      4 |  Query Count  |  Answer Count |
      8 |Authority Rec.#| Addtl. Rec. # |
      12|          Questions..          |
        |           Answers..           |
        |      Authority Records..      |
        |     Additional Records..      |
    """ 

    ICMPTableHelp = """
        |   0   |   1   |   2   |   3   |
      0 | Type  |  Code |    Checksum   |
      4 |    ICMP ID    | ICMP Sequence |
    """

    score=0
    # Questions to add to pool:
    #
    # Ethernet
    # What is the MTU set in the following output?
    # TCP
    # What is the value of the ECN flag?
    for p in pcaps:

    # IP related questions
        if IP in p:
            # Question 1   
            if hr == True:
                print 'Score: ' + str(score)
                print magenta("\n" + IPv4TableHelp + "\n")
            print hexdump(p[IP])
            while True: #Checks for a valid number
                try:
                    answer = int(raw_input("\nGiven the IP datagram, what is the decimal length?\n=>"))
                except KeyboardInterrupt:
                    print yellow('\n' + 'Final Score ' + str(score))
                    exit()
                except:
                    print 'Please enter a valid number.'
                    continue
                else:
                    break
            if int(answer) == p[IP].len:
                print green("CORRECT!")
                score=+1
            else:
                print red("INCORRECT! The correct answer is: ") + yellow(str(p[IP].len))

            # Question 2
            if hr == True:
                print 'Score: ' + str(score)
                print magenta("\n" + IPv4TableHelp + "\n")
            print hexdump(p[IP])
            while True:
                try:
                    answer = raw_input("\nWhich protocol is in use?\n=>")
                except KeyboardInterrupt:
                    print yellow('\n' + 'Final Score ' + str(score))
                    exit()
                else:
                    break
            if (TCP in p and answer == "TCP") or (UDP in p and answer == "UDP") or (ICMP in p and answer == "ICMP") or (DNS in p and answer == "DNS"):
                print green("CORRECT!")
                score=+1
            else:
                print red("INCORRECT!")

            # Question 3
            if hr == True:
                print 'Score: ' + str(score)
                print magenta("\n" + IPv4TableHelp + "\n")
            print hexdump(p[IP])
            while True:
                try:
                    answer = raw_input("\nWhat is the destination IP?\n=>")
                except KeyboardInterrupt:
                    print '\n' + 'Final Score ' + str(score)
                    exit()
                else:
                    break
            if str(answer) == str(p[IP].dst):
                print green("CORRECT!")
                score=+1
            else:
                print red("INCORRECT! The correct answer is: ") + yellow(str(p[IP].dst))

        # TCP related questions
        if TCP in p:
            # Question 1
            # Given the TCP output below, which flags are set?
            flags = {
                'F': 'FIN',
                'S': 'SYN',
                'R': 'RST',
                'P': 'PSH',
                'A': 'ACK',
                'U': 'URG',
                'E': 'ECE',
                'C': 'CWR'}
            
            if hr == True:
                print 'Score: ' + str(score)
                print magenta("\n" + TCPTableHelp + "\n")
                print magenta("      Flags:  FSRPAUEC\n")
            print hexdump(p[TCP])
            while True: #Checks for a valid number
                try:
                    answer = str(raw_input("\nGiven the TCP datagram, which flags are set? (expecting just letters in order)\n=>"))
                except KeyboardInterrupt:
                    print '\n' + 'Final Score ' + str(score)
                    exit()
                except:
                    print 'Please enter a valid number.'
                    continue
                else:
                    break

            if answer == p[TCP].sprintf('%TCP.flags%'):
                print green("CORRECT!")
                score=+1
            else:
                print red("INCORRECT! The correct answer is: ") + yellow(str(p[TCP].sprintf('%TCP.flags%') + red(" which is " + str([flags[x] for x in p[TCP].sprintf('%TCP.flags%')]))))

            if hr == True:
                print 'Score: ' + str(score)
                print magenta("\n" + TCPTableHelp + "\n")
            print hexdump(p[TCP])
            while True: #Checks for a valid number
                try:
                    answer = int(raw_input("\nWhat is the TCP header length?\n=>"))
                except KeyboardInterrupt:
                    print '\n' + 'Final Score ' + str(score)
                    exit()
                except:
                    print 'Please enter a valid number.'
                    continue
                else:
                    break
            if int(answer) == p[TCP].dataofs:
                print green("CORRECT!")
                score=+1
            else:
                print red("INCORRECT!")

    # More questions to add...
    # Are IP options enabled?
    # Are TCP options enabled?
    # How much TCP data is in the following output (in bytes)?
            if hr == True:
                print 'Score: ' + str(score)
                print magenta("\n" + TCPTableHelp + "\n")
            print hexdump(p[TCP])
            while True:
                try:
                    answer = int(raw_input("\nWhat is the TCP destination port?\n=>"))
                except KeyboardInterrupt:
                    print '\n' + 'Final Score ' + str(score)
                    exit()
                else:
                    break
            if int(answer) == p[TCP].dport:
                print green("CORRECT!")
                score=+1
            else:
                print red("INCORRECT! The correct answer is: ") + yellow(str(p[TCP].dport))

        # UDP related questions
        if UDP in p:
            if hr == True:
                print 'Score: ' + str(score)
                print magenta("\n" + UDPTableHelp + "\n")
            print hexdump(p[UDP])
            while True:
                try:
                    answer = int(raw_input("\nWhat is the UDP destination port?\n=>"))
                except KeyboardInterrupt:
                    print '\n' + 'Final Score ' + str(score)
                    exit()
                else:
                    break
            if answer == p[UDP].dport:
                print green("CORRECT!")
                score=+1
            else:
                print red("INCORRECT! The correct answer is: ") + yellow(str(p[UDP].dport))

# ICMP
    # What is the value of the ICMP identifier and ICMP secquence number?
    # Given the IPv4 ICMP packet, what is the ICMP type?
    # DNS



def main():
    parser_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
            description = 'Packet Analysis Study Quiz (TODO: better description)',
            formatter_class=parser_formatter)

    parser.add_argument('--filename', required=True, action='store',
            dest='filename', help='pcap file used to quiz')
    #parser.add_argument('-n', required=False, action='store_false',
            #default=??, help='defines number of questions you get asked')

    # Getting tired, fugged something up here...changing to default True
    parser.add_argument('--hr', required=False, action='store',
            dest='hr', default=True, help='Displays Header Reference for question')
    #Sometime add show Types (for like ICMP Echo Reply or whatever)
    #Sometime add an option to choose IP, TCP, UDP, ICMP, DNS questions only
    #Sometime add an option to use built in sample pcaps instead of supplying your own

    args = parser.parse_args()

    quiz(args.filename, args.hr)

if __name__ == '__main__':
    main()

