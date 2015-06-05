# Introduction #

模拟TCP协议连接的三向握手开始和终了。使用用EtherProtocol、IPv4Protocol和TcpProtocol类型来实现TcpConnectionSample类，然后执行该类来模拟TCP的连接。

# Details #

**TcpConnectionSample类的使用方法例：**
```
//网关IP地址
String gatewayIp = "192.168.11.1";
//目标IP地址
String dstIp = "64.233.189.147";
//生成Pcap套接字来实现链路层通信
IPcapSocket socket = IPcapSocketFactory.INSTANCE.createPcapSocket();
socket.setDevice(getInterface().name);
//生成Arp对象
ArpApp arp = new ArpApp(socket, LOCAL_MAC, LOCAL_IP);
//设置是否打印数据通信内容
arp.setDumpPacket(true);
//取得目标设备的MAC地址
String dstMac = arp.askMac(gatewayIp);
//生成Connection对象
TcpConnectionSample conn = new TcpConnectionSample(socket, LOCAL_MAC, dstMac, LOCAL_IP);
//设置是否打印数据通信内容
conn.setDumpPacket(true);
if (!conn.openConnection(dstIp, 12923, 80)) {
    assert false;
}
conn.closeConnection();
```

**TCP报文的打印例：**
```
0:58  EtherProtocol.EtherProtocol 
0:6     dstAddress           00:16:01:15:A4:88 
6:6     srcAddress           00:16:D4:17:25:C4 
12:2    etherType            2048 IPv4
14:44   payload              
14:44     ipv4               Ipv4Protocol.Ipv4Protocol
14:44 Ipv4Protocol.Ipv4Protocol 
14:20   header               
14:1      0000----           4 version 0xF0 
14:1      ----0000           5 headerLength 0x0F 
15:1      typeOfService      '00000000'B 
16:2      totalLength        44 
18:2      identification     1 
20:1      0---------------   0 reserved 0x8000 
20:1      -0--------------   false doNotFrag 0x4000 
20:1      --0-------------   false moreFrags 0x2000 
20:2      ---0000000000000   0 fragmentOffset 0x1FFF 
22:1      timeToLive         255 
23:1      protocol           6 TCP: Transmission Control Protocol
24:2      hcs                '0000'O 
26:4      sourceAddress      192.168.11.5 
30:4      destinationAddress 64.233.189.147 
34:0      options            omit 
34:24   payload              
34:24     tcp                TcpProtocol.TcpProtocol
34:24 TcpProtocol.TcpProtocol 
34:24   header               
34:2      sourcePort         12923 
36:2      destinationPort    80 WWW-HTTP
38:4      sequenceNumber     25372 
42:4      ackNumber          0 
46:1      0000------------   6 dataOffset 0xF000 
46:2      ----000000------   0 reserved 0x0FC0 
47:1      ----------0-----   false urgent 0x0020 
47:1      -----------0----   false ack 0x0010 
47:1      ------------0---   false push 0x0008 
47:1      -------------0--   false reset 0x0004 
47:1      --------------0-   true syn 0x0002 
47:1      ---------------0   false fin 0x0001 
48:2      windowSize         0 
50:2      checksum           '0000'O 
52:2      urgentPointer      0 
54:4      options            
54:4        [0]              
54:4          maxSs          
54:1            optionCode   2 Maximum Segment Lifetime
55:1            optionLength 4 
56:2            value        1460 
58:0      padding            ''O 
58:0    payload              omit 
58:0    fcs                  omit 
```

**TcpConnectionSample类的源代码：**
```
/**
 * 模拟TCP协议连接的三向握手开始和终了。
 * 
 * @author JiangMin
 * 
 */
public class TcpConnectionSample {
    protected static IModule module = IModuleRegistry.INSTANCE
            .resolveModule("EtherProtocol");
    protected static IFactory factory = module.getFactory();
    protected static IValueSerializer ser = IValueSerializer.INSTANCE;

    protected String srcMac;
    protected String dstMac;
    protected String srcIp;
    protected IPcapSocket socket;
    protected int timeout = ICommonSocket.DEFAULT_TIMEOUT;
    protected boolean dumpPacket;
    protected String dstIp;
    protected int srcPort;
    protected int dstPort;

    private long lastRemoteSeqNo;
    private long currentLocalSeqNo;

    /**
     * 生成用于发送的TCP数据包。协议栈为Ethernet/IPv4/TCP。
     * @return TcpProtocol类型的Record对象
     */
    protected IRecordSetValue createTcpPacket() throws MetaException {
        // Ethernet
        IRecordSetValue etherPrtl = (IRecordSetValue) factory
                .createValue("EtherProtocol");
        etherPrtl.getField("dstAddress").setTextAs(dstMac, IValueTextStyle.MAC_ADDRESS);
        etherPrtl.getField("srcAddress").setTextAs(srcMac, IValueTextStyle.MAC_ADDRESS);
        etherPrtl.getField("etherType").setText("0x0800");
        // Ipv4
        IRecordSetValue ipv4Prtl = (IRecordSetValue) etherPrtl.findField("payload/ipv4",
                true);
        IRecordSetValue header = (IRecordSetValue) ipv4Prtl.getField("header");
        header.getField("identification").setText("1");
        header.getField("timeToLive").setText("255");
        header.getField("protocol").setText("6");
        header.getField("sourceAddress").setTextAs(srcIp, IValueTextStyle.IPV4_ADDRESS);
        header.getField("destinationAddress").setTextAs(dstIp,
                IValueTextStyle.IPV4_ADDRESS);
        // Tcp
        IRecordSetValue tcpPrtl = (IRecordSetValue) ipv4Prtl.findField("payload/tcp",
                true);
        ((IIntegerValue) tcpPrtl.findField("header/sourcePort")).setInteger(srcPort);
        ((IIntegerValue) tcpPrtl.findField("header/destinationPort")).setInteger(dstPort);
        return etherPrtl;
    }

    /**
     * 构造函数
     * @param socket PCAP套接字
     * @param srcMac 源设备的MAC地址
     * @param dstMac 目标设备的MAC地址
     * @param srcIp 源设备的IP地址
     */
    public TcpConnectionSample(IPcapSocket socket, String srcMac, String dstMac,
            String srcIp) {
        this.socket = socket;
        this.srcMac = srcMac;
        this.dstMac = dstMac;
        this.srcIp = srcIp;
    }

    /**
     * 使用三向握手的连接建立,非三向的握手将返回失败。
     * @param dstIp
     * @param localPort
     * @param remotePort
     * @return
     * @throws Exception
     */
    public boolean openConnection(String dstIp, int localPort, int remotePort)
            throws Exception {
        srcPort = localPort;
        dstPort = remotePort;
        this.dstIp = dstIp;
        socket.setTimeout(timeout);
        // 打开套接字
        socket.open();
        // 设置Pcap套接字的过滤条件。（过滤条件的书写规则可以参考WinPcap的用户手册）
        socket.setFilter("ip dst " + srcIp + " and ip src " + dstIp
                + " and tcp dst port " + srcPort + " and tcp src port " + dstPort, true);
        // 生成随机的TCP序号
        currentLocalSeqNo = (int) (Math.random() * 0xFFFF);

        // send syn
        IRecordSetValue etherPrtl = createTcpPacket();
        IRecordSetValue tcpPrtl = (IRecordSetValue) etherPrtl
                .findField("payload/ipv4/payload/tcp");
        ((IIntegerValue) tcpPrtl.findField("header/sequenceNumber"))
                .setLong(currentLocalSeqNo);
        ((IBooleanValue) tcpPrtl.findField("header/syn")).setBoolean(true);
        // Maximum Segment Size Option
        tcpPrtl.findField("header/options[0]/maxSs/value", true).setText("1460");
        encodeAndWrite(etherPrtl);

        // receive syn + ack
        etherPrtl = readAndDecode();
        tcpPrtl = (IRecordSetValue) etherPrtl.findField("payload/ipv4/payload/tcp");
        boolean reset = ((IBooleanValue) tcpPrtl.findField("header/reset")).getBoolean();
        lastRemoteSeqNo = ((IIntegerValue) tcpPrtl.findField("header/sequenceNumber"))
                .getLong();
        boolean syn = ((IBooleanValue) tcpPrtl.findField("header/syn")).getBoolean();
        if (reset || !syn) {
            return false;
        }

        // send ack
        etherPrtl = createTcpPacket();
        tcpPrtl = (IRecordSetValue) etherPrtl.findField("payload/ipv4/payload/tcp");
        ((IIntegerValue) tcpPrtl.findField("header/sequenceNumber"))
                .setLong(currentLocalSeqNo);
        ((IIntegerValue) tcpPrtl.findField("header/ackNumber"))
                .setLong(lastRemoteSeqNo + 1);
        ((IBooleanValue) tcpPrtl.findField("header/ack")).setBoolean(true);
        ((IIntegerValue) tcpPrtl.findField("header/windowSize")).setInteger(65535);
        encodeAndWrite(etherPrtl);

        return true;
    }

    private IRecordSetValue readAndDecode() throws Exception {
        IRecordSetValue etherPrtl;
        byte[] resData = new byte[1514];
        int len = socket.read(resData);
        // 解码（底层协议为Ethernet所以使用EtherProtocol作为推测类型）
        etherPrtl = (IRecordSetValue) ProtocolUtils.decode(resData, 0, len, module
                .getType("EtherProtocol"));
        // 打印报文内容
        if (dumpPacket) {
            IValueDumper.INSTANCE.dump(etherPrtl);
        }
        return etherPrtl;
    }

    private void encodeAndWrite(IRecordSetValue etherPrtl) throws EncodeException,
            IOException {
        // 对报文数据包内的可计算字段进行自动计算（这里是IP协议的HeaderLength和TotalLength和
        // TCP协议的dataOffset等字段）
        ser.calculate(etherPrtl);
        // 打印报文内容
        if (dumpPacket) {
            IValueDumper.INSTANCE.dump(etherPrtl);
        }
        // 编码
        byte data[] = ser.encode(etherPrtl, false);
        // 发送编码数据
        socket.write(data);
    }

    /**
     * 使用三向握手的连接终止, 如果是半关闭将直接终止。
     * @return
     * @throws Exception
     */
    public void closeConnection() throws Exception {
        // send RST
        IRecordSetValue etherPrtl = createTcpPacket();
        IRecordSetValue tcpPrtl = (IRecordSetValue) etherPrtl
                .findField("payload/ipv4/payload/tcp");
        ((IIntegerValue) tcpPrtl.findField("header/sequenceNumber"))
                .setLong(++currentLocalSeqNo);
        ((IIntegerValue) tcpPrtl.findField("header/ackNumber"))
                .setLong(lastRemoteSeqNo + 1);
        ((IBooleanValue) tcpPrtl.findField("header/fin")).setBoolean(true);
        encodeAndWrite(etherPrtl);

        // receive RST+ACK
        etherPrtl = readAndDecode();
        tcpPrtl = (IRecordSetValue) etherPrtl.findField("payload/ipv4/payload/tcp");
        boolean fin = ((IBooleanValue) tcpPrtl.findField("header/fin")).getBoolean();
        lastRemoteSeqNo = ((IIntegerValue) tcpPrtl.findField("header/sequenceNumber"))
                .getLong();

        if (fin) {
            // send ACK
            etherPrtl = createTcpPacket();
            tcpPrtl = (IRecordSetValue) etherPrtl.findField("payload/ipv4/payload/tcp");
            ((IIntegerValue) tcpPrtl.findField("header/sequenceNumber"))
                    .setLong(currentLocalSeqNo);
            ((IIntegerValue) tcpPrtl.findField("header/ackNumber"))
                    .setLong(lastRemoteSeqNo + 1);
            ((IBooleanValue) tcpPrtl.findField("header/ack")).setBoolean(true);
            encodeAndWrite(etherPrtl);
        }
        // 关闭套接字
        socket.close();
    }

    public boolean isDumpPacket() {
        return dumpPacket;
    }

    public void setDumpPacket(boolean dumpPacket) {
        this.dumpPacket = dumpPacket;
    }

}
```