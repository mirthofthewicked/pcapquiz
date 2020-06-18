from scapy.all import *
import argparse
from colors import *
#from IPy import IP


def requestIntegerInput(prompt):
    while True: #Checks for a valid number
        try:
            answer = int(raw_input("\n%s\n=>" % prompt))
            return answer
        except KeyboardInterrupt:
            raise
        except EOFError:
            raise
        except:
            print '\nPlease enter a valid number.'
            continue
        else:
            break

def reportscore(score, qcount):
    print "\nScore: %d" % score
    print "Question Number: %d" % qcount
    print "Current Score: %d%%. " % ((score*100)/qcount)


# At some point, add what the correct value is (DONE!!) and why *(LOL)*

def quiz(filename, hr):
    pcaps=rdpcap(filename)

    ethernetTableHelp = """
        |   0   |   1   |   2   |   3   |
      0 |   Destination MAC OUI | Dest  |
      4 | MAC UAA       |   Source MAC  |
      8 | OUI   |   Source MAC UAA      |
      12|    LEN/SNAP   |
    """

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

    score=0         # Total Score
    qcount=1        # Question Count
    dscore = {      # Dictionary Score
    'Datagram Length': 0,
    'Protocol': 0,
    'Destination IP': 0,
    'TCP Flags': 0,
    'TCP Header': 0,
    'TCP Destination': 0,
    'UDP Destination': 0
	}     

    # Questions to add to pool:
    #
    # Ethernet
    # What is the MTU set in the following output?
    # TCP
    # What is the value of the ECN flag?
    try:
        for p in pcaps:

        # IP related questions
            if IP in p:
                # Question 1   
                if hr == True:
                    reportscore(score, qcount)
                    print magenta("\n" + IPv4TableHelp + "\n")

                print hexdump(p[IP])
                answer = requestIntegerInput("Given the IP datagram, what is the decimal length?")
                qcount+=1
                if answer == p[IP].len:
                    print green("CORRECT!")
                    score+=1
                    dscore['Datagram Length'] += 1
                else:
                    print red("INCORRECT! The correct answer is: ") + yellow("%d" % p[IP].len)
                    dscore['Datagram Length'] -= 1

                # Question 2
                if hr == True:
                    reportscore(score, qcount)
                    print magenta("\n" + IPv4TableHelp + "\n")
                print hexdump(p[IP])
                answer = raw_input("\nWhich protocol is in use?\n=>").upper()
                qcount+=1
                # I should probably pull these from a lookup table or something
                if (p[IP].proto == 6 and answer == "TCP") or (p[IP].proto == 17 and answer == "UDP") or (p[IP].proto == 1 and answer == "ICMP") or (DNS in p and answer == "DNS") or (p[IP].proto == 4 and answer == "IP"):
                #if p[IP].proto == 4 and answer == "IP":
                    print green("CORRECT!")
                    score+=1
                    dscore['Protocol'] += 1
                else:
                    # I should probably pull these from a lookup table or something
                    print red("INCORRECT! The correct answer is: %s" % ("TCP" if p[IP].proto == 6 else ("UDP" if p[IP].proto == 17 else ("ICMP" if p[IP].proto == 1 else ("IP" if p[IP].proto == 4 else( "NO IDEA"))))))
                    dscore['Protocol'] -= 1

                # Question 3
                if hr == True:
                    reportscore(score, qcount)
                    print magenta("\n" + IPv4TableHelp + "\n")
                print hexdump(p[IP])
                answer = raw_input("\nWhat is the destination IP?\n=>")
                qcount+=1
                if answer == p[IP].dst:
                    print green("CORRECT!")
                    score+=1
                    dscore['Destination IP'] += 1
                else:
                    print red("INCORRECT! The correct answer is: %s" % yellow(p[IP].dst))
                    dscore['Destination IP'] -= 1

            # TCP related questions
            if TCP in p:
                tcpLayer = p[TCP]

                # Question 1
                # Given the TCP output below, which flags are set?
                flags = { 'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH', 'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'}
                
                if hr == True:
                    reportscore(score, qcount)
                    print magenta("\n" + TCPTableHelp + "\n")
                    print magenta("      Flags:  FSRPAUEC\n")

                print hexdump(tcpLayer)
                answer = raw_input("\nGiven the TCP datagram, which flags are set? (expecting just letters in order)\n=>").upper()
                qcount+=1
                if answer == tcpLayer.sprintf('%TCP.flags%').upper():
                    print green("CORRECT!")
                    score+=1
                    dscore['TCP Flags'] += 1
                else:
                    print red("INCORRECT! The correct answer is: ") + yellow(tcpLayer.sprintf('%TCP.flags%')) + red(" which is " + ", ".join([flags[x] for x in tcpLayer.sprintf('%TCP.flags%')]))
                    dscore['TCP Flags'] -= 1

                # Question 2
                # Given the tcp header supplied, compute the TCP header length.
                if hr == True:
                    reportscore(score, qcount)
                    print magenta("\n" + TCPTableHelp + "\n")

                print hexdump(tcpLayer)
                answer = requestIntegerInput("What is the TCP header length?")
                qcount+=1
                if answer == tcpLayer.dataofs * 4:
                    print green("CORRECT!")
                    score+=1
                    dscore['TCP Header'] += 1
                else:
                    print red("INCORRECT! The correct answer is %d." % tcpLayer.dataofs * 4)
                    dscore['TCP Header'] -= 1

                # Question 3
                if hr == True:
                    reportscore(score, qcount)
                    print magenta("\n" + TCPTableHelp + "\n")

                print hexdump(tcpLayer)
                answer = requestIntegerInput("What is the TCP Destination port?")
                qcount+=1
                if answer == tcpLayer.dport:
                    print green("CORRECT!")
                    score+=1
                    dscore['TCP Destination'] += 1
                else:
                    print red("INCORRECT! The correct answer is: ") + yellow(str(tcpLayer.dport))
                    dscore['TCP Destination'] -= 1

                # More questions to add...
                # Is this a TCP fragment? What offseT?
                # Are IP options enabled?
                # Are TCP options enabled?
                # How much TCP data is in the following output (in bytes)?

            # UDP related questions
            if UDP in p:
                if hr == True:
                    reportscore(score, qcount)
                    print magenta("\n" + UDPTableHelp + "\n")

                print hexdump(p[UDP])
                answer = requestIntegerInput("What is the UDP destination port?") 
                qcount+=1
                if answer == p[UDP].dport:
                    print green("CORRECT!")
                    score+=1
                    dscore['UDP Destination'] += 1
                else:
                    print red("INCORRECT! The correct answer is: ") + yellow("%d" % p[UDP].dport)
                    dscore['UDP Destination'] -= 1

    except KeyboardInterrupt:
        qcount -= 1
        print yellow("\nFinal Score: %d. " % score)
        print yellow("Total Questions: %d. " % qcount)
        print yellow("Overall Score: %d%%. " % ((score*100)/qcount))
        print green("\n\nScore Breakdown:")         # Sorted by what subjects to work on
        sorted_questions = sorted(dscore, key=dscore.__getitem__)
        for q in sorted_questions:
            print("{} : {}".format(q, dscore[q]))
        exit()

    except EOFError:
        qcount -= 1
        print yellow("\nFinal Score: %d. " % score)
        print yellow("Total Questions: %d. " % qcount)
        print yellow("Overall Score: %d%%. " % ((score*100)/qcount))
        print green("\n\nScore Breakdown:")         # Sorted by what subjects to work on
        sorted_questions = sorted(dscore, key=dscore.__getitem__)
        for q in sorted_questions:
            print ("{} : {}".format(q, dscore[q]))
        exit()


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
