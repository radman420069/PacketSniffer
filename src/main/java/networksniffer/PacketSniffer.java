package networksniffer;

import java.util.List;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

public class PacketSniffer {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Please provide the duration (in seconds) for packet sniffing.");
            return;
        }

        // Parse the duration argument
        int durationInSeconds;
        try {
            durationInSeconds = Integer.parseInt(args[0]);
        } catch (NumberFormatException e) {
            System.out.println("Invalid duration provided. Please enter a valid integer.");
            return;
        }

        System.out.printf("Sniffing packets for %d seconds...\n", durationInSeconds);

        try {
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            if (allDevs.isEmpty()) {
                System.out.println("No network interfaces found.");
                return;
            }

            PcapNetworkInterface nif = allDevs.get(0);  // Select the first interface
            PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1000);

            long endTime = System.currentTimeMillis() + (durationInSeconds * 1000);

            while (System.currentTimeMillis() < endTime) {
                Packet packet = handle.getNextPacket();
                if (packet == null) {
                    System.out.println("No packet captured.");
                } else {
                    System.out.println("Captured packet: " + packet);
                }
            }

            System.out.println("Packet sniffing completed.");

            handle.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

