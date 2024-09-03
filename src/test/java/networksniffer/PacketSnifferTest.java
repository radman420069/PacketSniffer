package networksniffer;


import org.junit.jupiter.api.Test;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import static org.junit.jupiter.api.Assertions.*;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

public class PacketSnifferTest {

    @Test
    public void testPacketSnifferInitialization() {
        try {
            PcapNetworkInterface nif = Pcaps.findAllDevs().get(0); // Get the first network device
            assertNotNull(nif, "Network interface should not be null");

            try (PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
                assertNotNull(handle, "PcapHandle should not be null");
            }
        } catch (PcapNativeException e) {
            fail("Exception thrown during test: " + e.getMessage());
        }
    }

    @Test
    public void testPacketCapture() {
        try {
            PcapNetworkInterface nif = Pcaps.findAllDevs().get(0);
            try (PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
                Packet packet = handle.getNextPacket();
                assertNotNull(packet, "Captured packet should not be null");
            }
        } catch (NotOpenException | PcapNativeException e) {
            fail("Exception thrown during packet capture test: " + e.getMessage());
        }
    }
}