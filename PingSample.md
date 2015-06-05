# Introduction #

使用ICMPv4协议的Echo Request和Echo Reply报文来实现Ping应用。用了已定义的EtherProtocol类型和Ipv4Protocol和Icmpv4Protocol类型来实现了PingApp类，然后可以用该PingApp类来执行Ping功能。


# Details #

**PingApp类的使用方法例：**
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
//生成Ping对象
PingApp ping = new PingApp(socket, LOCAL_MAC, dstMac, LOCAL_IP);
//设置是否打印数据通信内容
ping.setDumpPacket(true);
//执行Ping(循环三次)
ping.ping(3, dstIp);
```

**上述代码的执行结果例:**
```
Reply from 192.168.11.1 bytes=32 time<=0.031(s) TTL=64
Reply from 192.168.11.1 bytes=32 time<=0.0(s) TTL=64
Reply from 192.168.11.1 bytes=32 time<=0.0(s) TTL=64
```

**Echo Request报文的打印例：**
```
0:74  EtherProtocol.EtherProtocol 
0:6     dstAddress           00:16:01:15:A4:88 
6:6     srcAddress           00:16:D4:17:25:C4 
12:2    etherType            2048 IPv4
14:60   payload              
14:60     ipv4               Ipv4Protocol.Ipv4Protocol
14:60 Ipv4Protocol.Ipv4Protocol 
14:20   header               
14:1      0000----           4 version 0xF0 
14:1      ----0000           5 headerLength 0x0F 
15:1      typeOfService      '00000000'B 
16:2      totalLength        60 
18:2      identification     1 
20:1      0---------------   0 reserved 0x8000 
20:1      -0--------------   false doNotFrag 0x4000 
20:1      --0-------------   false moreFrags 0x2000 
20:2      ---0000000000000   0 fragmentOffset 0x1FFF 
22:1      timeToLive         255 
23:1      protocol           1 ICMP: Internet Control Message Protocol
24:2      hcs                '0000'O 
26:4      sourceAddress      192.168.11.5 
30:4      destinationAddress 192.168.11.1 
34:0      options            omit 
34:40   payload              
34:40     icmpv4             Icmpv4Protocol.Icmpv4Protocol
34:40 Icmpv4Protocol.Icmpv4Protocol 
34:40   echoRequest          
34:1      icmpType           8 
35:1      icmpCode           0 
36:2      checksum           '0000'O 
38:2      identifier         17076 
40:2      sequenceNumber     0 
42:32     data               {} 
      0000 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ................
      0010 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f  ................
74:0    fcs                  omit 
```

**Echo Reply报文的打印例：**
```
0:74  EtherProtocol.EtherProtocol 
0:6     dstAddress           00:16:D4:17:25:C4 
6:6     srcAddress           00:16:01:15:A4:88 
12:2    etherType            2048 IPv4
14:60   payload              
14:60     ipv4               Ipv4Protocol.Ipv4Protocol
14:60 Ipv4Protocol.Ipv4Protocol 
14:20   header               
14:1      0000----           4 version 0xF0 
14:1      ----0000           5 headerLength 0x0F 
15:1      typeOfService      '00000000'B 
16:2      totalLength        60 
18:2      identification     51406 
20:1      0---------------   0 reserved 0x8000 
20:1      -0--------------   false doNotFrag 0x4000 
20:1      --0-------------   false moreFrags 0x2000 
20:2      ---0000000000000   0 fragmentOffset 0x1FFF 
22:1      timeToLive         64 
23:1      protocol           1 ICMP: Internet Control Message Protocol
24:2      hcs                '1A9C'O 
26:4      sourceAddress      192.168.11.1 
30:4      destinationAddress 192.168.11.5 
34:0      options            omit 
34:40   payload              
34:40     icmpv4             Icmpv4Protocol.Icmpv4Protocol
34:40 Icmpv4Protocol.Icmpv4Protocol 
34:40   echoReply            
34:1      icmpType           0 
35:1      icmpCode           0 
36:2      checksum           'CC4A'O 
38:2      identifier         17076 
40:2      sequenceNumber     0 
42:32     data               {} 
      0000 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ................
      0010 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f  ................
74:0    fcs                  omit 
```

**PingApp类的源代码：**
```
/**
 * 使用ICMPv4协议实现的Ping应用。 使用ICMPv4协议的Echo Request和Echo Reply报文来实现Ping应用。
 */
public class PingApp {
    protected static IModule module = IModuleRegistry.INSTANCE
            .resolveModule("EtherProtocol");
    protected static IFactory factory = module.getFactory();
    protected static IValueSerializer ser = IValueSerializer.INSTANCE;

    private static int ICMP_REQUEST_DATA_BYTES = 32;
    protected String srcMac;
    protected String dstMac;
    protected String srcIp;
    protected IPcapSocket socket;
    protected int timeout = ICommonSocket.DEFAULT_TIMEOUT;
    protected boolean dumpPacket;

    /**
     * 构造函数
     * 
     * @param socket PCAP套接字
     * @param srcMac 源设备的MAC地址
     * @param dstMac 目标设备的MAC地址
     * @param srcIp 源设备的IP地址
     */
    public PingApp(IPcapSocket socket, String srcMac, String dstMac, String srcIp) {
        this.socket = socket;
        this.srcMac = srcMac;
        this.dstMac = dstMac;
        this.srcIp = srcIp;
    }

    /**
     * 生成ICMPv4的Echo Request报文数据包。协议栈为Ethernet/IPv4/ICMPv4。
     * 
     * @param dstIp 目标设备的IP地址。
     * @param icmpId Echo Request中的标识符
     * @param icmpSeq Echo Request中的序号
     * @return
     */
    protected IRecordSetValue createPingRequest(String dstIp, int icmpId, int icmpSeq)
            throws MetaException {
        IRecordSetValue etherPrtl = (IRecordSetValue) factory
                .createValue("EtherProtocol");
        etherPrtl.getField("dstAddress").setTextAs(dstMac, IValueTextStyle.MAC_ADDRESS);
        etherPrtl.getField("srcAddress").setTextAs(srcMac, IValueTextStyle.MAC_ADDRESS);
        etherPrtl.getField("etherType").setText("0x0800");

        IRecordSetValue ipv4Prtl = (IRecordSetValue) etherPrtl.findField("payload/ipv4",
                true);
        IRecordSetValue header = (IRecordSetValue) ipv4Prtl.getField("header");
        header.getField("identification").setText("1");
        header.getField("timeToLive").setText("255");
        header.getField("protocol").setText("1");
        header.getField("sourceAddress").setTextAs(srcIp, IValueTextStyle.IPV4_ADDRESS);
        header.getField("destinationAddress").setTextAs(dstIp,
                IValueTextStyle.IPV4_ADDRESS);

        IRecordSetValue echoRequest = (IRecordSetValue) ipv4Prtl.findField(
                "payload/icmpv4/echoRequest", true);
        ((IIntegerValue) echoRequest.getField("identifier")).setInteger(icmpId);
        ((IIntegerValue) echoRequest.getField("sequenceNumber")).setInteger(icmpSeq);

        byte[] data = new byte[ICMP_REQUEST_DATA_BYTES];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        ((IOctetstringValue) echoRequest.getField("data", true)).setValue(data);
        return etherPrtl;
    }

    /**
     * 根据指示的目标设备IP地址通过ICMPv4协议来检验源设备到目标设备的网路是否连通。检验结果会被打印在 标准输出中。
     * 
     * @param cnt 检验次数，即Echo请求的发送次数。
     * @param dstIp 目标设备的IP地址
     * @throws Exception
     */
    public void ping(int cnt, String dstIp) throws Exception {
        byte[] resData = new byte[1514];
        socket.setTimeout(timeout);
        // 打开套接字
        socket.open();
        try {
            // 设置Pcap套接字的过滤条件。（过滤条件的书写规则可以参考WinPcap的用户手册）
            socket.setFilter("ip dst " + srcIp + " and icmp", true);
            // 生成随机的ICMP Echo请求的标识符
            int icmpId = (int) (Math.random() * 0xFFFF);
            // 进行多次Ping检验
            for (int i = 0; i < cnt; i++) {
                // ICMP Echo请求的序号
                int seqNo = i;
                // 生成ICMP Echo请求报文
                IRecordSetValue pingRequest = createPingRequest(dstIp, icmpId, seqNo);
                // 对报文数据包内的可计算字段进行自动计算（这里是IP协议的HeaderLength和TotalLength字段）
                ser.calculate(pingRequest);
                // 打印报文内容
                if (dumpPacket) {
                    IValueDumper.INSTANCE.dump(pingRequest);
                }
                // 编码
                byte data[] = ser.encode(pingRequest, false);
                // 发送编码数据
                socket.write(data);
                // 起始时间
                long startTime = System.currentTimeMillis();
                // 已花费时间（计算超时）
                long totalTime = 0;
                // 循环接收数据包直到超时
                while (totalTime < timeout) {
                    // 接收数据
                    int len;
                    try {
                        len = socket.read(resData);
                    } catch (CommTimeoutException e) {
                        totalTime = timeout;
                        break;
                    }
                    // 解码（底层协议为Ethernet所以使用EtherProtocol作为推测类型）
                    IRecordSetValue pingResponse = (IRecordSetValue) ProtocolUtils
                            .decode(resData, 0, len, module.getType("EtherProtocol"));
                    // 打印报文
                    if (dumpPacket) {
                        IValueDumper.INSTANCE.dump(pingResponse);
                    }
                    // 取得花费时间
                    totalTime = System.currentTimeMillis() - startTime;
                    // 从Icmpv4Protocol中取出EchoReply字段
                    IRecordSetValue echoReply = (IRecordSetValue) pingResponse
                            .findField("payload/ipv4/payload/icmpv4/echoReply");
                    if (echoReply == null) {
                        continue;
                    }
                    // 判断EchoReply的标识符和序号是否与EchoRequest的一致
                    if (((IIntegerValue) echoReply.getField("identifier")).getInteger() != icmpId
                            || ((IIntegerValue) echoReply.getField("sequenceNumber"))
                                    .getInteger() != seqNo) {
                        continue;
                    }
                    // 取得目标设备的IP地址
                    IRecordSetValue ipv4Header = (IRecordSetValue) pingResponse
                            .findField("payload/ipv4/header");
                    String tempIp = ipv4Header.getField("sourceAddress").getTextAs(
                            IValueTextStyle.IPV4_ADDRESS);
                    // 取得EchoReply中的Data字段的长度（字节数）
                    int dataLen = ((IOctetstringValue) echoReply.getField("data"))
                            .getLength();
                    // 取得IPv4的TTL字段值
                    int ttl = ((IIntegerValue) ipv4Header.getField("timeToLive"))
                            .getInteger();
                    // 打印检验结果
                    String msg = "Reply from " + tempIp + " bytes=" + dataLen + " time<="
                            + totalTime / 1000.0 + "(s)" + " TTL=" + ttl;
                    System.out.println(msg);
                    break;
                }
                // 判断是否超时
                if (totalTime >= timeout) {
                    System.out.println("timeout");
                }
            }
        } finally {
            // 关闭套接字
            socket.close();
        }
    }

    public boolean isDumpPacket() {
        return dumpPacket;
    }

    public void setDumpPacket(boolean dumpPacket) {
        this.dumpPacket = dumpPacket;
    }
}
```