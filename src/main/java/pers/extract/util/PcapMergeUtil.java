package pers.extract.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

public class PcapMergeUtil {
	
	public Map<Integer, Integer> merge(String file) throws PcapNativeException, NotOpenException {
		PcapHandle handle = Pcaps.openOffline(file);
//		PcapHandle handle = Pcaps.openOffline("src/main/resources/test0.pcap");
		Packet packet;
		TcpPacket tcpPacket;
		IpV4Packet ipPacket;
		List<Packet> list=new ArrayList<Packet>();
		int count=0;//计数
		int type=0;//分类计数
		Map<Integer,Integer> map=new HashMap<Integer,Integer>();
		
		while ((packet = handle.getNextPacket()) != null) {
			count ++;
			if(packet.get(TcpPacket.class)==null){
				continue;
			}else if(packet.get(TcpPacket.class).getPayload()==null){
				continue;
			}
			boolean add=true;
			for(int i=0;i<list.size();i++){
				if(isequal(packet, list.get(i))){
					add=false;
					map.put(count, i);
					break;
				}
			}
			if(add){
				list.add(packet);
				map.put(count, type++);
			}
		}
		handle.close();
		return map;
	}
	

	public int count(String path) throws PcapNativeException, NotOpenException {
		PcapHandle handle = Pcaps.openOffline(path);
		int i = 0;
		Packet packet;
		while ((packet = handle.getNextPacket()) != null) {
			i++;

		}
		return i;
	}

	public boolean isequal(Packet packet1, Packet packet2) {
		boolean flag = false;
		TcpPacket tcpPacket1;
		IpV4Packet ipPacket1;
		TcpPacket tcpPacket2;
		IpV4Packet ipPacket2;
		if (((ipPacket1 = packet1.get(IpV4Packet.class)) != null)
				&& ((ipPacket2 = packet2.get(IpV4Packet.class)) != null)) {
			flag = ipPacket1.getHeader().getSrcAddr().equals(ipPacket2.getHeader().getSrcAddr());
			flag = flag && ipPacket1.getHeader().getDstAddr().equals(ipPacket2.getHeader().getDstAddr());
			if (((tcpPacket1 = packet1.get(TcpPacket.class)) != null)
					&& ((tcpPacket2 = packet2.get(TcpPacket.class)) != null)) {
				flag = flag && tcpPacket1.getHeader().getSrcPort().equals(tcpPacket2.getHeader().getSrcPort());
				flag = flag && tcpPacket1.getHeader().getDstPort().equals(tcpPacket2.getHeader().getDstPort());
				flag = flag && tcpPacket1.getHeader().getAcknowledgmentNumberAsLong()==tcpPacket2.getHeader()
						.getAcknowledgmentNumberAsLong();
			}
		}

		return flag;
	}
	/**
	 * packet1是否在packet2之前发出
	 * @param packet1
	 * @param packet2
	 * @return
	 */
	public boolean isBigger(Packet packet1,Packet packet2){
		boolean bigger=false;
		TcpPacket tcpPacket1;
		TcpPacket tcpPacket2;
		
		if (((tcpPacket1 = packet1.get(TcpPacket.class)) != null)
				&& ((tcpPacket2 = packet2.get(TcpPacket.class)) != null)) {
			bigger=tcpPacket1.getHeader().getSequenceNumberAsLong()>tcpPacket2.getHeader().getSequenceNumberAsLong();
		}
		
		return bigger;
	}

}
