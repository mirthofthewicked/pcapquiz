from scapy.all import *
import argparse

# At some point, add what the correct value is and why

def quiz(filename, hr):
    pcaps=rdpcap(filename)
    
    # Add ICMP and DNS
    IPv4TableHelp ="""
        |   0   |   1   |   2   |   3   |
      0 |VER|IHL|  TOS  |  Total length |
      4 |    IP Ident   |XDM |  Offset  |
      8 |  TTL  | Proto |    Checksum   |
      12|        SOURCE ADDRESS         |
      16|     DESTINATION ADDRESS       |
      20|            OPTIONS            |"""

    TCPTableHelp = """
        |   0   |   1   |   2   |   3   |
      0 |  Source Port  |  Dest.  Port  |
      4 |        Sequence Number        |
      8 |     Acknowledgement Number    |
      12| HL | R | Flag |  Window size  |
      16|   Checksum    | Urgent Pointer|
      20|    OPTIONS (up to 40 bytes)   |"""

    UDPTableHelp = """
        |   0   |   1   |   2   |   3   |
      0 |  Source Port  |  Dest.  Port  |
      4 |     Length    |    Checksum   |"""

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
              print '\033[95m' + "\n" + IPv4TableHelp + "\n" + '\033[0m'
          print hexdump(p[IP])
          while True: #Checks for a valid number
              try:
                  answer = int(raw_input("\nGiven the IP datagram, what is the decimal length?\n=>"))
              except:
                      print("Please enter a valid number.")
                      continue
              else:      
                      break
          if int(answer) == p[IP].len:
              print '\033[92m' + "CORRECT!" + '\033[0m'
              score=+1
          else:
              print '\033[91m' + "INCORRECT!" + '\033[0m'
         
          # Question 2
          if hr == True:
              print 'Score: ' + str(score)
              print '\033[95m' + "\n" + IPv4TableHelp + "\n" + '\033[0m'
          print hexdump(p[IP])
          answer = raw_input("\nWhich protocol is in use?\n=>")
          if (TCP in p and answer == "TCP") or (UDP in p and answer == "UDP") or (ICMP in p and answer == "ICMP") or (DNS in p and answer == "DNS"):
              print '\033[92m' + "CORRECT!" + '\033[0m'
              score=+1
          else:
              print '\033[91m' + "INCORRECT!" + '\033[0m'

          # Question 3
          if hr == True:
              print 'Score: ' + str(score)
              print '\033[95m' + "\n" + IPv4TableHelp + "\n" + '\033[0m'
          print hexdump(p[IP])
          answer = raw_input("\nWhat is the destination IP?\n=>")
          if answer == p[IP].dst:
              print '\033[92m' + "CORRECT!" + '\033[0m'
              score=+1
          else:
              print '\033[91m' + "INCORRECT!" + '\033[0m'

        # TCP related questions
       if TCP in p:
            # Question 1
            # Given the TCP output below, which flags are set?
            # This will get ugly:
            #   flags = {
            #     'F': 'FIN',
            #     'S': 'SYN',
            #     'R': 'RST',
            #     'P': 'PSH',
            #     'A': 'ACK',
            #     'U': 'URG',
            #     'E': 'ECE',
            #     'C': 'CWR',}
            #
          
          if hr == True:
              print 'Score: ' + str(score)
              print '\033[95m' + "\n" + TCPTableHelp + "\n" + '\033[0m'
          print hexdump(p[TCP])
          while True: #Checks for a valid number
              try:
                  answer = int(raw_input("\nWhat is the TCP header length?\n=>"))
              except:
                      print("Please enter a valid number.")
                      continue
              else:      
                      break
          if int(answer) == p[TCP].dataofs:
              print '\033[92m' + "CORRECT!" + '\033[0m'
              score=+1
          else:
              print '\033[91m' + "INCORRECT!" + '\033[0m'

    # More questions to add...
    # What is the TCP header length?
    # How much TCP data is in the following output (in bytes)?
    # What is the destination port?
    # UDP
    # What is the destination port?
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

    args = parser.parse_args()

    quiz(args.filename, args.hr)
    #packetcount = len(pcaps)

if __name__ == '__main__':
    main()
