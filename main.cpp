/*
 * Program: Simple NetFlow collector
 * Author: Martin Pech, 2022
 * https://mpech.net/developer
 */

#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <fstream>
#include <string>
#include <string.h>
#include <list>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <netdb.h>


/*
 * Error codes:
 * 0 - normal exit, program is finished
 * 10 - not existing option
 * 11 - invalid parameter value
 * 12 - other problem with reading options or parameters
 * 20 - invalid input data
 * 30 - invalid packet type
 * 41 - cannot resolve dns name
 * 42 - cannot create socket
 * 43 - cannot connect to the server
 * 44 - invalid port format
 * 50 - send() failed - packet not sent
 * 51 - send() failed - packet sent partially
 */

/*
 * Definition of tcp flags
 */
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

/*
 * Netflow V5 format (header + body)
 */
typedef struct netFlowV5header{
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsec;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;
}netFlowV5header;

typedef struct netFlowV5format{
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;
    uint32_t dOctets;
    uint32_t First;
    uint32_t Last;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t pad1;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint16_t pad2;
}netFlowV5format;

/*
 * Global variables
 */
uint32_t sysUptimeSet;
uint32_t firstPacketReceived = 0;
uint32_t currentPacketTime = 0;
uint32_t flowSeq = 0;
uint32_t timestamp;
uint32_t tm_sec;
uint32_t tm_nsec;

uint8_t tcpFlags = 0;
ether_header *eptr;
std::map<size_t, std::map<std::string, std::string>> allPackets;

/*
 * Variables that contain input parameters
 */
char* fileName;
std::string collectorPort = "127.0.0.1:2055";
int activeTime = 60;
int interval = 10;
uint32_t flowCache = 1024;

/*
 * Code handling tokens
 */
bool tokenFile = false;
bool tokenCollectorPort = false;

/*
 * Function used for error outputs on stderr
 * Set debugToggler to "true" to allow these messages
 */
bool debugToggler = false;
void debug(std::string errMessage){
    if(debugToggler){
        std::cerr << "\nError:" + errMessage;
    }
}

/*
 * Function used for informative messages
 * Set msgToggler to "true" to allow these messages
 */
bool msgToggler = false;
void msg(std::string message){
    if(msgToggler){
        std::cerr << "Message:" + message << "\n";
    }
}

/*
 * Function checks if given array is full of digits
 */
bool checkFormat(char* char_array){
    for(int i = 0; i < static_cast<int>(strlen(char_array)); i++){
        if(!std::isdigit(char_array[i])){
            return false;
        }
    }
    return true;
}

/*
 * function check given hostname and separates IP address and port number
 */
std::vector<std::string> checkHostname(std::string hostname){
    size_t pos = 0;
    std::vector<std::string>token;
    std::string delimiter = ":";

    while((pos = hostname.find(delimiter)) != std::string::npos){
        token.push_back(hostname.substr(0, pos));
        hostname.erase(0, pos + delimiter.length());
    }
    token.push_back(hostname);

    return token;
}

/*
 * Function responsible for exporting Netflow packets
 */
bool collectorExport(std::map<std::string, std::string>packet){
    flowSeq++;

    //If exported flow had only 1 packet inside
    if(packet.find("packetAmount") == packet.end()){
        packet.insert({"packetAmount", "1"});
    }

    netFlowV5format netflowV5;
    netFlowV5header netflowHeader;

    in_addr test;

    //Netflow packet
    inet_aton(packet.find("srcIP")->second.c_str(), &test);
    netflowV5.srcaddr = (test.s_addr);

    inet_aton(packet.find("dstIP")->second.c_str(), &test);
    netflowV5.dstaddr = (test.s_addr);

    netflowV5.srcport = htons(atoi(packet.find("srcPort")->second.c_str()));
    netflowV5.dstport = htons(atoi(packet.find("dstPort")->second.c_str()));

    netflowV5.prot = (atoi(packet.find("UsedProtocol")->second.c_str()));
    netflowV5.tos = (atoi(packet.find("ToS")->second.c_str()));

    netflowV5.dPkts = htonl(atoi(packet.find("packetAmount")->second.c_str()));

    netflowV5.First = htonl(atoi(packet.find("FirstTimestamp")->second.c_str()));
    netflowV5.Last = htonl(atoi(packet.find("LastTimestamp")->second.c_str()));

    netflowV5.dOctets = htonl(stoi(packet.find("dOctets")->second));

    netflowV5.tcp_flags = stoi(packet.find("tcpFlags")->second);


    netflowV5.dst_as = 0; netflowV5.dst_mask = 0; netflowV5.input = 0; netflowV5.nexthop = 0;
    netflowV5.output = 0; netflowV5.pad1 = 0; netflowV5.pad2 = 0; netflowV5.src_as = 0; netflowV5.src_mask = 0;

    // Netflow Header
    netflowHeader.version = htons(5);
    netflowHeader.count = htons(1);

    netflowHeader.SysUptime = htonl(sysUptimeSet);
    netflowHeader.unix_secs = htonl(tm_sec);
    netflowHeader.unix_nsec = htonl(tm_nsec);
    netflowHeader.flow_sequence = htonl(flowSeq);
    netflowHeader.engine_type = 0;
    netflowHeader.engine_id = 0;
    netflowHeader.sampling_interval = 0;

    std::string ip = "127.0.0.1";
    uint16_t port = 2055;
    if(tokenCollectorPort == true){
        if(gethostbyname(collectorPort.c_str()) == NULL){
            auto functionReturned = checkHostname(collectorPort);
            if(functionReturned.size() == 1){
                ip = functionReturned[0];
            }
            else{
                ip = functionReturned[0];
                try{
                    port = stoi(functionReturned[1]);
                }
                catch(...){
                   debug("Invalid port format");
                   exit(44);
                }
            }
        }
        else{
            ip = collectorPort;
        }
    }

    struct hostent *servent;
    struct sockaddr_in server;

    memset(&server,0,sizeof(server));
    server.sin_family = AF_INET;
    servent = gethostbyname(ip.c_str());
    if(servent == NULL){
        debug("Cannot resolve DNS name");
        exit(41);
    }

    memcpy(&server.sin_addr, servent->h_addr, servent->h_length);
    server.sin_port = htons(port);

    auto sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock== -1){
        debug("Cannot create socket");
        exit(42);
    }

    if(connect(sock, (struct sockaddr *)&server, sizeof(server)) == -1){
        debug("Cannot connect to the server");
        exit(43);
    }
    char buffer[1024];
    memcpy(buffer, &netflowHeader, sizeof(netFlowV5header));
    memcpy(buffer+sizeof(netFlowV5header), &netflowV5, sizeof(netFlowV5format));


    auto i = send(sock, buffer, 72, 0);
    if(i == -1){
        debug("Fail while sending packets");
        exit(50);
    }
    if(i != 72){
        debug("Packet was sent partially");
        exit(51);
    }

    close(sock);
    return true;
}

/*
 * Main program function
 */
int main(int argc, char *argv[]) {
    /*
     * defining Functions
     */

    void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
    bool collectorExport(std::map<std::string, std::string>);

    /*
     * Default behaviour -> ./... -c hell -c hello
     */
    int opt;
    while((opt = getopt(argc, argv, "f:c:a:i:m:")) != -1){
        try{
            switch(opt){
                case 'f':
                    fileName = optarg;
                    tokenFile = true;
                    break;
                case 'c':
                    collectorPort = optarg;
                    tokenCollectorPort = true;
                    break;
                case 'a':
                    if(checkFormat(optarg)){
                        activeTime = atoi(optarg);
                    }
                    else{
                        debug("Invalid value for parameter -a");
                        exit(11);
                    }
                    break;
                case 'i':
                    if(checkFormat(optarg)){
                        interval = atoi(optarg);
                    }
                    else{
                        debug("Invalid value for parameter -i");
                        exit(11);
                    }
                    break;
                case 'm':
                    if(checkFormat(optarg)){
                        debug("Invalid value for parameter -a");
                    }
                    else{
                        debug("Invalid value for parameter -a");
                        exit(11);
                    }
                    flowCache = atoi(optarg);
                    break;
                default:
                    debug("Invalid use of options");
                    exit(10);
            }
        }
        catch (...){
            debug("Error has occurred while reading parameters");
            exit(12);
        }
    }

    /*
     * Checking input file (if is requested)
     */
    std::ofstream fileChecker;

    /*
     * Checking collector port input
     */
    std::string port;
    if(tokenCollectorPort == true){
        port = collectorPort;
    }
    else{
        port = "127.0.0.1:2055";
    }

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *fileHandler;

    if(tokenFile){
        fileHandler = pcap_open_offline(fileName, errbuff);
    }
    else{
        fileHandler = pcap_open_offline("-", errbuff);
    }
    if(fileHandler == NULL){
        debug("PCAP is unable to read this file. Read PCAP error message below:\n");
        debug(errbuff);
        exit(20);
    }

    pcap_loop(fileHandler, -1, process_packet, NULL);
    pcap_close(fileHandler);
    msg("Pcap closed successfully, exiting program...");

    std::map<uint32_t, std::map<std::string, std::string>>unsortedOutput;
    for (auto itr = allPackets.begin(); itr != allPackets.end(); ++itr){
        collectorExport(itr->second);
    }

    exit(0);
}

/*
 * Packet processing function
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){

    std::string packetType = " ";
    std::string srcIP = " ";
    std::string dstIP = " ";
    u_short srcPort = 0;
    u_short dstPort = 0;
    u_int ToS = 0;
    u_int usedProtocol = 0;
    tcpFlags = 0;
    uint16_t dOctets = 0;
    bool tokenNoPort = false;

    eptr = (ether_header*)buffer;

    //Unique = src, dst IP; src, dst PORT; PROTOCOL, TOS

    if(ntohs(eptr->ether_type) == ETHERTYPE_IP){
        sockaddr_in source,dest;

        auto *iph = (iphdr*)(buffer + 14);
        int ipHeaderLen = iph->ihl * 4;

        dOctets = ntohs(iph->tot_len);

        source.sin_addr.s_addr = iph->saddr;
        dest.sin_addr.s_addr = iph->daddr;

        switch(iph->protocol){
            case 1: {//ICMP protocol
                usedProtocol = 1;
                srcIP = inet_ntoa(source.sin_addr);
                dstIP = inet_ntoa(dest.sin_addr);
                ToS = (unsigned int)iph->tos;
                tokenNoPort = true;
                break;
            }

            case 6: {//TCP protocol
                auto *tcpheader = (tcphdr *) (buffer + ipHeaderLen + 14);

                usedProtocol = 6;
                // IP adress
                packetType = "TCP"; msg("TCP");
                srcIP = inet_ntoa(source.sin_addr);
                dstIP = inet_ntoa(dest.sin_addr);

                // port
                srcPort = ntohs(tcpheader->th_sport);
                dstPort = ntohs(tcpheader->th_dport);

                // ToS
                ToS = (unsigned int)iph->tos;
                tcpFlags = tcpheader->th_flags;

                break;
            }

            case 17: {//UDP protocol
                auto *udpheader = (udphdr *) (buffer + ipHeaderLen + 14);

                usedProtocol = 17;
                // IP adress
                srcIP = inet_ntoa(source.sin_addr);
                dstIP = inet_ntoa(dest.sin_addr);

                //port
                srcPort = ntohs(udpheader->uh_sport);
                dstPort = ntohs(udpheader->uh_dport);

                // ToS
                ToS = (unsigned int)iph->tos;
                break;
            }
        }


    }
    else if(ntohs(eptr->ether_type) == IPPROTO_ICMP){
        msg("ICMP Packet");
    }
    else{
        debug("This packet type is unsupported!");
    }

    //Current packet
    std::map<std::string, std::string> packet;

    //Map format: ToS, dstIP, dstPort, srcIP, srcPort, usedProtocol
    try {
        packet.insert({"srcIP", srcIP});
        packet.insert({"dstIP", dstIP});

        if ((srcPort == 0 && tokenNoPort == true) && (dstPort == 0 && tokenNoPort == true)) {
            packet.insert({"srcPort", std::to_string(0)});
            packet.insert({"dstPort", std::to_string(0)});
        } else {
            packet.insert({"srcPort", std::to_string(srcPort)});
            packet.insert({"dstPort", std::to_string(dstPort)});
        }
        packet.insert({"ToS", std::to_string(ToS)});
        packet.insert({"UsedProtocol", std::to_string(usedProtocol)});
    }catch(...){
        debug("Invalid packet format");
        exit(30);
    }

    //Concatenation of strings, which need to be converted to hash
    std::string toBeHashID;

    for (auto itr = packet.begin(); itr != packet.end(); ++itr){
        toBeHashID = toBeHashID + itr->second;
    }

    std::hash<std::string> hashID;
    size_t finalHash = (hashID(toBeHashID));

    //Adding Timestamp into packet structure

    tm_sec = header->ts.tv_sec;
    tm_nsec = header->ts.tv_usec*1000;

    timestamp = tm_sec*1000 + header->ts.tv_usec/1000;

    if(firstPacketReceived == 0){
        firstPacketReceived = timestamp;
    }

    sysUptimeSet = timestamp - firstPacketReceived;

    packet.insert({"FirstTimestamp", std::to_string(sysUptimeSet)});
    packet.insert({"LastTimestamp", std::to_string(sysUptimeSet)});

    packet.insert({"dOctets", std::to_string(dOctets)});

    //**********************************************************************************************************
    //Active & inactive timer

    std::vector<size_t>packetsToBeRemoved;
    for (auto itr = allPackets.begin(); itr != allPackets.end(); ++itr){

        //New packet time - old first time > -a
        //New packet time - old last time > -i
        auto newPacketTime = stod(packet.find("LastTimestamp")->second);

        auto oldPacketFirst = stod(itr->second.find("FirstTimestamp")->second);

        auto oldPacketLast = stod(itr->second.find("LastTimestamp")->second);

        if(newPacketTime - oldPacketFirst > activeTime*1000 || newPacketTime - oldPacketLast > interval*1000){
            bool exportStatus = collectorExport(itr->second);
            if(exportStatus == true){
                packetsToBeRemoved.push_back(itr->first);
            }
        }
        else{
        }
    }

    for(size_t i : packetsToBeRemoved){
        allPackets.erase(i);
    }

    //**********************************************************************************************************
    //Incrementing float statistics

    //This packet is already stored
    if(allPackets.find(finalHash) != allPackets.end()){

        msg("Packet found in structure");
        auto existingPacket = allPackets.find(finalHash);

        if(existingPacket == allPackets.end()){
            //Currently unused
        }
        else{
            //This is the existing packet, we need to edit
            std::map<std::string, std::string>modifiedPacket = existingPacket->second;

            //Packets in the flow
            if(modifiedPacket.find("packetAmount") == modifiedPacket.end()){
                //key not found
                modifiedPacket.insert({"packetAmount", "2"});
            }
            else{
                //key found
                auto toIncrement = modifiedPacket.find("packetAmount")->second;
                auto toIncrementNumber = std::stoi(toIncrement)+1;
                toIncrement = std::to_string(toIncrementNumber);
                modifiedPacket.find("packetAmount")->second = toIncrement;
            }

            modifiedPacket.find("LastTimestamp")->second = packet.find("LastTimestamp")->second;
            uint8_t currentFlags = stoi(modifiedPacket.find("tcpFlags")->second);
            currentFlags = currentFlags | tcpFlags;

            modifiedPacket.find("tcpFlags")->second = std::to_string(currentFlags);
            uint16_t currentOctets = stoi(modifiedPacket.find("dOctets")->second);
            currentOctets += dOctets;
            modifiedPacket.find("dOctets")->second = std::to_string(currentOctets);
            allPackets[finalHash] = modifiedPacket;

            if (tcpFlags & TH_RST || tcpFlags & TH_FIN) {
                collectorExport(allPackets.find(finalHash)->second);
                allPackets.erase(finalHash);
            }

        }
    }

    //**********************************************************************************************************
    //Creating new flow + flow cache check
    else{
        msg("Packet not found in structure");

        //Inserting current packet into all packet structure, because it was not found as existing one
        if(allPackets.size() >= flowCache && allPackets.size() > 0){
            int minimum = 0;
            size_t minimalHash = 0;
            for (auto itr = allPackets.begin(); itr != allPackets.end(); ++itr){
                if(minimum == 0){
                    minimum = stod(itr->second.find("FirstTimestamp")->second);
                    minimalHash = itr->first;
                }
                if(stod(itr->second.find("FirstTimestamp")->second) < minimum){
                    minimum = stod(itr->second.find("FirstTimestamp")->second);
                    minimalHash = itr->first;
                }
            }
            debug("NewPacket \n\n");

            collectorExport(allPackets.find(minimalHash)->second);
            allPackets.erase(minimalHash);
        }
        allPackets.insert(std::make_pair(finalHash, packet));
        if(tcpFlags != 0){
            allPackets.find(finalHash)->second.insert({"tcpFlags", std::to_string(tcpFlags)});
            if (tcpFlags & TH_RST || tcpFlags & TH_FIN){
                collectorExport(allPackets.find(finalHash)->second);
                allPackets.erase(finalHash);
            }
        }
        else{
            allPackets.find(finalHash)->second.insert({"tcpFlags", std::to_string(0)});
        }
    }
}


