# Introduction #

使用ICMPv4协议的Echo Request和Echo Reply报文和IPv4协议的TTL字段来实现Traceroute应用。用了已定义的EtherProtocol类型和Ipv4Protocol和Icmpv4Protocol类型来实现了TracerouteApp类，然后可以用该TracerouteApp类来执行Traceroute功能。

# Details #

**TracerouteApp类的使用方法例：**
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
//生成Ping对象
TracerouteApp trace = new TracerouteApp(socket, LOCAL_MAC, dstMac, LOCAL_IP);
trace.setDumpPacket(true);
//执行
trace.trace(dstIp);
```

**上述代码的执行结果例:**
```
(1) from 192.168.11.1, 16(ms),  ttl=64.
(2) from 218.11.160.248, 78(ms),  ttl=126.
(3) from 222.72.254.129, 47(ms),  ttl=253.
(4) from 124.74.210.165, 46(ms),  ttl=252.
(5) from 61.152.86.42, 32(ms),  ttl=251.
(6) from 202.97.35.118, 47(ms),  ttl=250.
(7) from 202.97.34.50, 15(ms),  ttl=249.
(8) from 202.97.33.5, 62(ms),  ttl=248.
(9) from 202.97.61.38, 78(ms),  ttl=247.
(10) from 202.97.62.214, 63(ms),  ttl=245.
(11) from 209.85.241.56, 78(ms),  ttl=244.
(12) from 66.249.94.6, 78(ms),  ttl=244.
(13) from 64.233.189.147, 110(ms),  ttl=243.
Traceroute completed. 64.233.189.147 reached.
```

**Echo Request报文的打印例：**
除了IPv4的TTL字段外，与PingSample基本相同。

**Echo Reply报文的打印例：**
除了IPv4的TTL字段外，与PingSample基本相同。

**TracerouteApp类的源代码：**
```
/**
 * 使用ICMPv4协议实现的Traceroute应用。 使用ICMPv4协议的Echo Request和Echo
 * Reply报文和IPv4的TTL字段来实现Traceroute应用。
 */
public class TracerouteApp extends PingApp {
    public final static int DEFAULT_MAX_HOPS = 40;
    private int maxHops = DEFAULT_MAX_HOPS;

    public TracerouteApp(IPcapSocket socket, String srcMac, String dstMac,
            String srcIp) {
        super(socket, srcMac, dstMac, srcIp);
    }

    public void trace(String dstIp) throws Exception {
        byte[] resData = new byte[1514];
        socket.setTimeout(timeout);
        // 打开套接字
        socket.open();
        try {
            // 设置Pcap套接字的过滤条件。（过滤条件的书写规则可以参考WinPcap的用户手册）
            socket.setFilter("ip dst " + srcIp + " and icmp", true);
            // 生成随机的ICMP Echo请求的标识符
            int icmpId = (int) (Math.random() * 0xFFFF);
            boolean reachedDst = false;
            // 持续尝试直到到达了最大的HOP数
            for (int i = 1; i <= maxHops; i++) {
                // sequence NO. of ICMP
                int seqNo = i;
                // field of TTL in IP, increase 1 each time
                int ttl = i;
                // 生成ICMP Echo请求报文
                IRecordSetValue pingRequest = createPingRequest(dstIp, icmpId,
                        seqNo);
                pingRequest.findField("payload/ipv4/header/timeToLive")
                        .setText(Integer.toString(ttl));
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
                            .decode(resData, 0, len, module
                                    .getType("EtherProtocol"));
                    // 打印报文
                    if (dumpPacket) {
                        IValueDumper.INSTANCE.dump(pingResponse);
                    }
                    // 取得花费时间
                    totalTime = System.currentTimeMillis() - startTime;
                    // 从Icmpv4Protocol中取出EchoReply字段
                    IRecordSetValue echoReply = (IRecordSetValue) pingResponse
                            .findField("payload/ipv4/payload/icmpv4/echoReply");
                    if (echoReply != null) {
                        // 判断EchoReply的标识符和序号是否与EchoRequest的一致
                        if (((IIntegerValue) echoReply.getField("identifier"))
                                .getInteger() != icmpId
                                || ((IIntegerValue) echoReply
                                        .getField("sequenceNumber"))
                                        .getInteger() != seqNo) {
                            continue;
                        }
                        reachedDst = true;
                    }
                    if (echoReply != null
                            || pingResponse
                                    .findField("payload/ipv4/payload/icmpv4/timeExceeded") != null) {
                        // 取得目标设备的IP地址
                        IRecordSetValue ipv4Header = (IRecordSetValue) pingResponse
                                .findField("payload/ipv4/header");
                        String tempIp = ipv4Header.getField("sourceAddress")
                                .getTextAs(IValueTextStyle.IPV4_ADDRESS);
                        String newTtl = ipv4Header.getField("timeToLive")
                                .getText();
                        // 打印检验结果
                        String msg = "(" + i + ") from " + tempIp + ", "
                                + totalTime + "(ms), " + " ttl=" + newTtl + ".";
                        System.out.println(msg);
                        break;
                    }
                }
                // 判断是否超时
                if (totalTime >= timeout) {
                    System.out.println("timeout");
                }
                // 判断是否到达了目标点
                if (!reachedDst) {
                    continue;
                } else {
                    break;
                }
            }
            // 打印统计信息
            String msg = "Traceroute completed. ";
            if (reachedDst) {
                msg += dstIp + " reached.";
            } else {
                msg += dstIp + " didn't reach.";
            }
            System.out.println(msg);

        } finally {
            // 关闭套接字
            socket.close();
        }

    }

    public int getMaxHops() {
        return maxHops;
    }

    public void setMaxHops(int maxHops) {
        this.maxHops = maxHops;
    }
}
```