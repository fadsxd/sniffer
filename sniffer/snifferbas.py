import socket, struct, sys
import ipaddress
import binascii


# Configuracion del socket objet
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((socket.gethostbyname(socket.gethostname()),0))
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

while True:
    
    #print (s.recvfrom(65565))

    data = s.recvfrom(65565)

    data = data[0]
    
    #ethernet
    eth_length = 14
    eth_header = data[:eth_length]
    eth = struct.unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print ("Ethernet Header")
    print("QUISPE YUJRA MIKI JERZY  C.I. 8305874")
    print("  |-Destination MAC \t:",binascii.hexlify(eth[0])) 
    print("  |-Source MAC \t\t:",binascii.hexlify(eth[1]))
    print("  |-Protocol \t\t:", str(eth_protocol))
    print("")
    

    unpackedData = struct.unpack('!BBHHHBBH4s4s', data[0:20])

    #print ("Datos interpretados:", unpackedData)
    print("IP Header")
    print("QUISPE YUJRA MIKI JERZY  C.I. 8305874")
    version_IHL = unpackedData[0]
# Recupera version IP
    version = version_IHL  >>  4
    print("  |-Version IP\t\t:"+ str(version))
    
# Determina longitud de cabecera IP
    IHL = version_IHL  &  0xF
    iph_length = IHL * 4
    print ("  |-IHL:\t\t:"+ str(IHL)+"DWORDS or "+ str(iph_length) +" Bytes")
    
#Type of Service
    TOS = unpackedData[1]  
    print ("  |-Type of Service \t:", str(TOS))

#total longitud
    totalLength = unpackedData[2]
    print ("  |-IP Total Length:\t:" + str(totalLength) +"Bytes (Size of packet)")

#Recuperar ID 
    ID = unpackedData[3]  
    print ("  |-ID\t\t:" + str(hex(ID)) + " (" + str(ID) + ")")

#Time to live
    TTL = unpackedData[5]
    print ("  |-Time to live\t:"+str(TTL))
#protocolo
#tcp = 6 
#icmp = 1
#udp = 17
 
    protocolo = unpackedData[6]
    print ("  |-Protocol:\t\t:", str(protocolo))
    
    
#Checksum    
    checksum = unpackedData[7]
    print ("  |-Checksum\t\t:"+str(checksum))
#Source Adrres
   
    origen = socket.inet_ntoa(unpackedData[8])
    print("  |-SourceAddr\t\t:"+origen)

#Destination Adrres
    
    destino = socket.inet_ntoa(unpackedData[9])
    print("  |-DestinationAddr\t:"+destino)

    print(" ")
    if str(protocolo)=='6': 
        
        print("TCP Header")
        print("QUISPE YUJRA MIKI JERZY  C.I. 8305874")
        tcp_header = data[IHL:IHL+20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    
        source_port = tcph[0]   # uint16_t
        dest_port = tcph[1]     # uint16_t
        sequence = tcph[2]      # uint32_t
        acknowledgement = tcph[3]   # uint32_t
        doff_reserved = tcph[4]     # uint8_t
        tcph_length = doff_reserved >> 4

        tcph_flags = tcph[5]            #uint8_t
        def getFlagsTCP(data):
            Flag_URG = {0:"  |-Urgent flag \t: 0",1: "  |-Urgent flag \t: 1"}
            Flag_ACK = {0:"  |-Acknowledgment flag : 0",1: "  |-Acknowledgment flag : 1"}
            Flag_PSH = {0:"  |-Push flag \t\t: 0",1: "  |-Push flag \t\t: 1"}
            Flag_RST = {0:"  |-Reset flag \t\t: 0",1: "  |-Reset flag \t\t: 1"}
            Flag_SYN = {0:"  |-Synchronize flag \t: 0",1: "  |-Synchronize flag \t: 1"}
            Flag_FIN = {0:"  |-Finish flag \t: 0",1: "  |-Finish flag \t: 1"}
      
            URG = data & 0x020
            URG >>= 5
            ACK = data & 0x010
            ACK >>= 4
            PSH = data & 0x008
            PSH >>= 3
            RST = data & 0x004
            RST >>= 2
            SYN = data & 0x002
            SYN >>= 1
            FIN = data & 0x001
            FIN >>= 0
            new_line = "\n"
            Flags = Flag_URG[URG] + new_line + Flag_ACK[ACK] + new_line + Flag_PSH[PSH] + new_line + Flag_RST[RST] + new_line + Flag_SYN[SYN] + new_line + Flag_FIN[FIN]
            return Flags
 
        tcph_window_size = tcph[6]      #uint16_t
        tcph_checksum = tcph[7]         #uint16_t
        tcph_urgent_pointer = tcph[8]   #uint16_t
    
        print(" ")
            
        print("  |-Source Port\t\t:",source_port)
        print("  |-Destination Port\t:",dest_port)
        print("  |-Sequence Number\t:",sequence)
        print("  |-Acknowledge Number\t:",acknowledgement)
        print("  |-Header Length\t:",tcph_length,'DWORDS or ',str(tcph_length*32//8) ,'bytes')

        print (getFlagsTCP(tcph_flags))


        print("  |-Window Size\t\t:",tcph_window_size)
        print("  |-Checksum\t\t:",tcph_checksum)
        print("  |-Urgent Pointer\t:",tcph_urgent_pointer)
        print("")
        
    
    elif str(protocolo) == '1':
        print ("ICMP Header")
        print("QUISPE YUJRA MIKI JERZY  C.I. 8305874")
        u = iph_length + eth_length
        icmp_header = data[u:u+4]

			#now unpack them :)
        icmph = struct.unpack('!BBH' , icmp_header)
			
        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]
			
        print ('  |-Type \t\t:' + str(icmp_type))
        print ('  |-Code \t\t:' + str(code))
        print ('  |-Checksum \t\t:' + str(checksum))
        print(" ")
    elif str(protocolo) == '17':
        print("UDP Header")
        print("QUISPE YUJRA MIKI JERZY  C.I. 8305874")
        uu = iph_length + eth_length
		
        udp_header = data[uu:uu+8]
        
        udph = struct.unpack('!HHHH' , udp_header)
        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]
        print ('  |-Source Port \t:' + str(source_port))
        print ('  |-Destination Port \t:' + str(dest_port))
        print ('  |-Length \t\t: ' + str(length))
        print ('  |-Checksum \t\t: ' + str(checksum))
        
        print(" ")
        print(" ")










