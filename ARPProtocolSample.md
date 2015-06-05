# Introduction #

使用ARP协议根据目标设备的IP地址来取得目标设备的MAC地址。用了已定义的ArpProtocol类型和
EthernetProtocol类型来实现了ArpApp类，然后可以用该ArpApp类来执行Arp功能。

# Details #

**ArpApp类的使用方法例：**
```
String dstIp = "192.168.11.1";
//生成Pcap套接字来实现链路层通信
IPcapSocket socket = IPcapSocketFactory.INSTANCE.createPcapSocket();
socket.setDevice(getInterface().name);
//生成Arp对象
ArpApp arp = new ArpApp(socket, LOCAL_MAC, LOCAL_IP);
//设置是否打印数据通信内容
arp.setDumpPacket(true);
//取得目标设备的MAC地址
String dstMac = arp.askMac(dstIp);
//打印
System.out.println("Mac for " + dstIp + " is " + dstMac + ".");
```

**上述代码的执行结果例:**

00:16:01:15:A4:99

**Arp Request报文的打印例：**
```
0:42  EtherProtocol.EtherProtocol 
0:6     dstAddress            FF:FF:FF:FF:FF:FF 
6:6     srcAddress            00:16:D4:17:25:C4 
12:2    etherType             2054 ARP
14:28   payload               
14:28     arp                 ArpProtocol.ArpProtocol
14:28 ArpProtocol.ArpProtocol 
14:2    hwType                6 IEEE 802 Networks
16:2    protocolType          2048 IPv4
18:1    hlen                  6 MAC
19:1    plen                  4 IPv4
20:2    operation             1 Arp Request
22:6    senderHwAddress       '0016D41725C4'O 
28:4    senderProtocolAddress 'C0A80B05'O 
32:6    targetHwAddress       '000000000000'O 
38:4    targetProtocolAddress 'C0A80B01'O 
42:0    fcs                   omit 
```

**Arp Response报文的打印例：**
```
0:46  EtherProtocol.EtherProtocol 
0:6     dstAddress            00:16:D4:17:25:C4 
6:6     srcAddress            00:16:01:15:A4:88 
12:2    etherType             2054 ARP
14:28   payload               
14:28     arp                 ArpProtocol.ArpProtocol
14:28 ArpProtocol.ArpProtocol 
14:2    hwType                1 Ethernet - 10Mb
16:2    protocolType          2048 IPv4
18:1    hlen                  6 MAC
19:1    plen                  4 IPv4
20:2    operation             2 Arp Response
22:6    senderHwAddress       '00160115A488'O 
28:4    senderProtocolAddress 'C0A80B01'O 
32:6    targetHwAddress       '0016D41725C4'O 
38:4    targetProtocolAddress 'C0A80B05'O 
42:4    fcs                   '00000000'O 
```

**ArpApp类的源代码：**
```
/**
 * Arp协议的实现。 使用ARP协议根据目标设备的IP地址来取得目标设备的MAC地址。
 */
public class ArpApp {
    private static IModule module = IModuleRegistry.INSTANCE
            .resolveModule("EtherProtocol");
    private static IFactory factory = module.getFactory();
    private static IValueSerializer ser = IValueSerializer.INSTANCE;
    private String srcMac;
    private String srcIp;
    private IPcapSocket socket;
    private int timeout = ICommonSocket.DEFAULT_TIMEOUT;
    private boolean dumpPacket;

    /**
     * 构造函数
     * @param socket Pcap套接字。
     * @param srcMac 源设备的MAC地址。
     * @param srcIp 源设备的IP地址。
     */
    public ArpApp(IPcapSocket socket, String srcMac, String srcIp) {
        this.socket = socket;
        this.srcMac = srcMac;
        this.srcIp = srcIp;
    }

    /**
     * 生成ARP请求报文。协议栈为Ehternet/Arp.
     * @param dstIp
     * @return
     */
    private IRecordSetValue createArpRequest(String dstIp) throws MetaException {
        // Ethernet
        IRecordSetValue etherPrtl = (IRecordSetValue) factory
                .createValue("EtherProtocol");
        etherPrtl.getField("dstAddress").setTextAs("ff:ff:ff:ff:ff:ff",
                IValueTextStyle.MAC_ADDRESS);
        etherPrtl.getField("srcAddress").setTextAs(srcMac, IValueTextStyle.MAC_ADDRESS);
        etherPrtl.getField("etherType").setText("0x0806");
        // Arp
        IRecordSetValue arpPrtl = (IRecordSetValue) etherPrtl.findField("payload/arp",
                true);
        arpPrtl.getField("operation").setText("1");
        arpPrtl.getField("senderHwAddress")
                .setTextAs(srcMac, IValueTextStyle.MAC_ADDRESS);
        arpPrtl.getField("senderProtocolAddress").setTextAs(srcIp,
                IValueTextStyle.IPV4_ADDRESS);
        arpPrtl.getField("targetHwAddress").setTextAs("00:00:00:00:00:00",
                IValueTextStyle.MAC_ADDRESS);
        arpPrtl.getField("targetProtocolAddress").setTextAs(dstIp,
                IValueTextStyle.IPV4_ADDRESS);
        return etherPrtl;
    }

    /**
     * 根据目标设备的IP地址来取得目标设备的MAC地址。
     * @param dstIp 目标设备的IP地址。
     * @return 目标设备的MAC地址文本描述。
     * @throws Exception
     */
    public String askMac(String dstIp) throws Exception {
        byte[] resData = new byte[1514];
        socket.setTimeout(timeout);
        // 打开套接字
        socket.open();
        try {
            // 设置Pcap套接字的过滤条件。（过滤条件的书写规则可以参考WinPcap的用户手册）
            socket.setFilter("ether dst " + srcMac + " and arp", true);
            // 生成ARP请求报文
            IRecordSetValue arpRequest = createArpRequest(dstIp);
            // 对报文数据包内的可计算字段进行自动计算（这里是Arp协议的Hlen和Plen字段）
            ser.calculate(arpRequest);
            if (dumpPacket) {
                IValueDumper.INSTANCE.dump(arpRequest);
            }
            // 编码
            byte data[] = ser.encode(arpRequest, false);
            // 发送编码数据
            socket.write(data);
            // 接收应答数据
            int len = socket.read(resData);
            // 解码（底层协议为Ethernet所以使用EtherProtocol作为推测类型）
            IRecordSetValue arpResponse = (IRecordSetValue) ProtocolUtils.decode(resData,
                    0, len, module.getType("EtherProtocol"));
            // 打印解码后的ARP应答报文对象
            if (dumpPacket) {
                IValueDumper.INSTANCE.dump(arpResponse);
            }
            // 从EthernetProtocol的Payload字段取得ARP协议字段
            IRecordSetValue arpPrtl = (IRecordSetValue) arpResponse
                    .findField("payload/arp");
            // 取得ARP协议的SenderHwAddress从而得到目标设备的MAC地址
            return arpPrtl.getField("senderHwAddress").getTextAs(
                    IValueTextStyle.MAC_ADDRESS);
        } finally {
            // 关闭套接字
            socket.close();
        }
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public String getSrcMac() {
        return srcMac;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public boolean isDumpPacket() {
        return dumpPacket;
    }

    public void setDumpPacket(boolean dumpPacket) {
        this.dumpPacket = dumpPacket;
    }

}
```