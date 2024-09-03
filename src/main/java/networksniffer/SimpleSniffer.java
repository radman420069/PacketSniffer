package networksniffer;

/**
 * Hello world!
 *
 */
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

public class SimpleSniffer {
    public static void main(String[] args) throws Exception {
        PcapNetworkInterface nif = Pcaps.findAllDevs().get(0); // Get the first network device
        try (PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
            for (int i = 0; i < 10; i++) {
                Packet packet = handle.getNextPacket();
                System.out.println(packet);
            }
        }
    }
}

