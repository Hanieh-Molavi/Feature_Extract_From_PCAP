
from struct import *
from scapy.all import rdpcap, TCP, IP
from scapy.all import *
import numpy as np
import pandas as pd

pcap_file = rdpcap("FileName.pcap")
c = 0
packet_num = []
packet_Raw = []
packet_len = []
packet_DWF = []
packet_Delta = []
Ether_Dist = []
Ether_Src = []
Ether_Type = []
Ip_Version = []
Ip_Ihl = []
Ip_Tos = []
Ip_Len = []
Ip_Id = []
Ip_Frag = []
Ip_Flags =[]
Ip_Ttl = []
Ip_Options = []
Ip_Dst = []
Ip_Src = []
Ip_Chksum= []
IP_Protos = []
Flag_Syn =[]
Flag_Urg =[]
Flag_Fin = []
Flag_Ack = []
Flag_Psh = []
Flag_Rst = []
Tcp_Seq = []
Tcp_ChkSum = []
Tcp_Sport = []
Tcp_Dport = []
Tcp_Payload = []
Tcp_OffSet = []
RTT=[]
CWND =[]
pl_seq_nums = []
IPV6 =[]

for oneP in pcap_file:
    #print("\n ===> packet:", oneP,"<=== \n")

    if oneP.haslayer("IP") or oneP.haslayer(IP):
        c += 1
        print("\n**** packet : ",c," ****\n")
        packet_num.append(c)

        #print("\npacket len:" ,len(oneP))
        packet_len.append(len(oneP))

        #print("duration window flow:",pcap_file[-1].time - oneP[0].time)
        packet_DWF.append(pcap_file[-1].time - oneP[0].time)

        if oneP.time != None and oneP[0].sent_time != None:
            RTT.append(oneP.time - oneP[0].sent_time)
        else:
            RTT.append(0)
            
        CWND.append(oneP.window)

        #print("delta time:",oneP.time - oneP[0].time)
        packet_Delta.append(oneP.time - oneP[0].time)

        #print("\n** Ethernet **\n")

        #print("Ether dist:" ,oneP["Ether"].dst)
        Ether_Dist.append(oneP["Ether"].dst)

        #print("Ether src:" ,oneP["Ether"].src)
        Ether_Src.append(oneP["Ether"].src)

        #print("Ether type:" ,oneP["Ether"].type)
        Ether_Type.append(oneP["Ether"].type)

        #print("\n** Ip **\n")
        
        #print("Ip version:" ,oneP["IP"].version)
        Ip_Version.append(oneP["IP"].version)

        #print("Ip ihl:" ,oneP["IP"].ihl)
        Ip_Ihl.append(oneP["IP"].ihl)

        #print("Ip tos:" ,oneP["IP"].tos)
        Ip_Tos.append(oneP["IP"].tos)

        #print("Ip len:" ,oneP["IP"].len)
        Ip_Len.append(oneP["IP"].len)

        #print("Ip id:" ,oneP["IP"].id)
        Ip_Id.append(oneP["IP"].id)

        #print("Ip flags:" ,oneP["IP"].flags)
        Ip_Flags.append(oneP["IP"].flags)

        #print("Ip frag:" ,oneP["IP"].frag)
        Ip_Frag.append(oneP["IP"].frag)

        #print("Ip syn:" ,oneP["TCP"].flags.value & 0x02)
        Flag_Syn.append(oneP["TCP"].flags.value & 0x02)

        #print("Ip urg:" ,oneP["TCP"].flags.value & 0x20)
        Flag_Urg.append(oneP["TCP"].flags.value & 0x20)

        # print("Ip fin:" ,oneP["TCP"].flags.value & 0x01)
        Flag_Fin.append(oneP["TCP"].flags.value & 0x01)

        #print("Ip ack:" ,oneP["TCP"].flags.value & 0x10)
        Flag_Ack.append(oneP["TCP"].flags.value & 0x10)

        #print("Ip psh:" ,oneP["TCP"].flags.value & 0x08)
        Flag_Psh.append(oneP["TCP"].flags.value & 0x08)

        #print("Ip rst:" ,oneP["TCP"].flags.value & 0x04)
        Flag_Rst.append(oneP["TCP"].flags.value & 0x04)

        #print("Ip ttl:" ,oneP["IP"].ttl)
        Ip_Ttl.append(oneP["IP"].ttl)

        #print("Ip proto:" ,oneP["IP"].proto)
        IP_Protos.append(oneP["IP"].proto)

        # print("Ip chksum:" ,oneP["IP"].chksum)
        Ip_Chksum.append(oneP["IP"].chksum)

        #print("Ip options:" ,oneP["IP"].options)
        Ip_Options.append(oneP["IP"].options)

        #print("Ip src:" ,oneP["IP"].src)
        Ip_Src.append(oneP["IP"].src)

        #print("Ip dst:" ,oneP["IP"].dst)
        Ip_Dst.append(oneP["IP"].dst)


        #print("\n** Tcp **\n")

        #print("TCP sport:" ,oneP["TCP"].sport)
        Tcp_Sport.append(oneP["TCP"].sport)

        #print("TCP dport:" ,oneP["TCP"].dport)
        Tcp_Dport.append(oneP["TCP"].dport)

        #print("TCP seq:" ,oneP["TCP"].seq)
        Tcp_Seq.append(oneP["TCP"].seq)

        pl_seq_nums.append(oneP["TCP"].seq)

        #print("TCP chksum:" ,oneP["TCP"].chksum)
        Tcp_ChkSum.append(oneP["TCP"].chksum)

        #print("TCP payload:" ,oneP["TCP"].payload)
        Tcp_Payload.append(oneP["TCP"].payload)

        #print("TCP dataofs:" ,oneP["TCP"].dataofs)
        Tcp_OffSet.append(oneP["TCP"].dataofs)

        packet_Raw.append(oneP["IP"].len - oneP["IP"].ihl - oneP["TCP"].dataofs )

    else:
        IPV6.append(oneP)
        print("=> useless num:",c," => packet",oneP)
        continue
        

print("num",len(packet_num),"\nlen",len(packet_len),"\npacket_DWF",len(packet_DWF)
                        ,"\ndelta",len(packet_Delta),"\nEther Src",len(Ether_Src),"\nEther Dist",len(Ether_Dist) 
                        ,"\nEther Type",len(Ether_Type),"\nIp Version",len(Ip_Version),"\nIp ihl",len(Ip_Ihl)
                        ,"\nIp Tos",len(Ip_Tos),"\nIp Id",len(Ip_Id),"\nIp Flags",len(Ip_Flags),"\nIp Ttl",len(Ip_Ttl)
                        ,"\nIp Options",len(Ip_Options),"\nIp Dist",len(Ip_Dst),"\nIp Src",len(Ip_Src)
                        ,"\nIp CheckSum",len(Ip_Chksum),"\nIp protocol",len(IP_Protos),"\nSyn",len(Flag_Syn)
                        ,"\nUrg",len(Flag_Urg),"\nFin",len(Flag_Fin),"\nAck",len(Flag_Ack),"\nPsh",len(Flag_Psh)
                        ,"\nRst",len(Flag_Rst),"\nTcp seq",len(Tcp_Seq),"\nTcp checkSum",len(Tcp_ChkSum)
                        ,"\nTcp Sport",len(Tcp_Sport),"\nTcp Dport",len(Tcp_Dport),"\nTcp Payload",len(Tcp_Payload)
                        ,"\nTcp OffSet",len(Tcp_OffSet),"\nCWND",len(CWND),"\npl_seq_nums",len(pl_seq_nums),"\nRTT",len(RTT))

df = pd.DataFrame(data={"num":packet_num,"len":packet_len,"packet_DWF":packet_DWF
                        ,"delta":packet_Delta,"Ether Src":Ether_Src,"Ether Dist":Ether_Dist 
                        ,"Ether Type":Ether_Type,"Ip Version":Ip_Version,"Ip ihl":Ip_Ihl
                        ,"Ip Tos":Ip_Tos,"Ip Id":Ip_Id,"Ip Flags":Ip_Flags,"Ip Ttl":Ip_Ttl
                        ,"Ip Options":Ip_Options,"Ip Dist":Ip_Dst,"Ip Src":Ip_Src
                        ,"Ip CheckSum":Ip_Chksum,"Ip protocol":IP_Protos,"Syn":Flag_Syn
                        ,"Urg":Flag_Urg,"Fin":Flag_Fin,"Ack":Flag_Ack,"Psh":Flag_Psh
                        ,"Rst":Flag_Rst,"Tcp seq":Tcp_Seq,"Tcp checkSum":Tcp_ChkSum
                        ,"Tcp Sport":Tcp_Sport,"Tcp Dport":Tcp_Dport,"Tcp Payload":Tcp_Payload,"Tcp OffSet":Tcp_OffSet
                        ,"RTT":RTT,"CWND":CWND,"pl_seq_nums":pl_seq_nums})
df.to_csv("./47.csv", sep=',',index=False)


