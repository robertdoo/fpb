# 概要 #

使用HTTP协议的GET命令来取得网站的资源.通过发送HTTP Reqeust报文，然后接收HTTP Response报文，从而获得所要得资源。通过执行HttpGetSample类的doGetAction来执行例子。


# 详细 #

**HttpGetSample类的使用方法：**

```
//目标主机地址
String remoteHost = "www.google.com";
//目标端口
int remotePort = 80;
HttpGetSample sample = new HttpGetSample();
//设置是否打印数据通信内容
sample.setDumpPacket(true);
//执行HTTP GET动作（取得URI为/的资源，超时时间为1分钟）
IValue response = sample.doGetAction(remoteHost, remotePort, "/", 60000);
//取得应答报文中的数据并打印至标准输出
assert "200".equals(response.findField("response/responseLine/status").getText());
IValue body = response.findField("response/message/httpBody");
//IValueDumper.INSTANCE.dump(body);
byte[] bodyData = IValueSerializer.INSTANCE.encode(body, false);
System.out.println(new String(bodyData));
```


**上述代码的执行结果例：**

上述代码执行后HTTP应答报文内的数据部分将会以文本形式被打印在标准输出中，详细内容这里省略。


**HTTP Request报文打印例：**
```
0:247  HttpProtocol.HttpProtocol 
0:247    request       
0:16       requestLine 
0:3          method    "GET" 
3:1          space1    " " 
4:1          uri       "/" 
5:1          space2    " " 
6:8          version   
6:5            prefix  "HTTP/" 
11:3           number  "1.1" 
14:2         crlf      '0D0A'O 
16:231     message     
16:229       headers   
16:13          [0]     
16:6             name  "Accept" 
22:1             colon ":" 
23:1             space " " 
24:3             value "*/*" 
27:2             crlf  '0D0A'O 
29:24          [1]     
29:15            name  "Accept-Language" 
44:1             colon ":" 
45:1             space " " 
46:5             value "en_US" 
51:2             crlf  '0D0A'O 
53:26          [2]     
53:15            name  "Accept-Encoding" 
68:1             colon ":" 
69:1             space " " 
70:7             value "deflate" 
77:2             crlf  '0D0A'O 
79:120         [3]     
79:10            name  "User-Agent" 
89:1             colon ":" 
90:1             space " " 
91:106           value {} 
       "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1
       ; SV1; GTB6; .NET CLR 2.0.50727; .NET CLR 1.1.4322
       ; CIBA)"
197:2            crlf  '0D0A'O 
199:22         [4]     
199:4            name  "Host" 
203:1            colon ":" 
204:1            space " " 
205:14           value "www.google.com" 
219:2            crlf  '0D0A'O 
221:24         [5]     
221:10           name  "Connection" 
231:1            colon ":" 
232:1            space " " 
233:10           value "Keep-Alive" 
243:2            crlf  '0D0A'O 
245:2        emptyLine '0D0A'O 
247:0        httpBody  omit 
247:0        trailers  omit 
```

**HttpGetSample类源代码：**
```
/**
 * 使用HTTP协议的GET命令来取得网站的资源.通过发送HTTP Reqeust报文，然后接收HTTP Response报文，
 * 从而获得所要得资源。
 * 
 * @author JiangMin
 *
 */
public class HttpGetSample {
    private static String USER_AGENT = 
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; GTB6; .NET CLR 2.0.50727; .NET CLR 1.1.4322; CIBA)";
    private static IValueSerializer ser = IValueSerializer.INSTANCE;
    private static IModule module = IModuleRegistry.INSTANCE.resolveModule("HttpProtocol");
    private static IFactory factory = module.getFactory();
    private static IType httpPrtlType =  module.getType("HttpProtocol");

    private boolean dumpPacket;
    
    /**
     * 执行HTTP1.1的GET动作，返回HTTP应答报文。
     * @param remoteHost 目标主机名或IP地址
     * @param remotePort 目标主机的端口号
     * @param httpUri 请求资源的URI
     * @param timeout 读取数据的超时时间，毫秒单位。
     * @return 解码后的应答报文对象。
     */
    public IValue doGetAction(String remoteHost, int remotePort, String httpUri, int timeout) 
    throws MetaException, IOException, ExecutionException, InterruptedException {
        //生成Get Request报文
        IValue prtl = factory.createValue("HttpProtocol");
        IValue request = prtl.findField("request", true);
        //uri
        request.findField("requestLine/method").setText("GET");
        request.findField("requestLine/uri").setText(httpUri);
        IValue message = request.findField("message");
        //headers
        setHeader(message, 0, "Accept", "*/*");
        setHeader(message, 1, "Accept-Language", "en_US");
        setHeader(message, 2, "Accept-Encoding", "deflate");
        setHeader(message, 3, "User-Agent", USER_AGENT);
        setHeader(message, 4, "Host", remoteHost);
        setHeader(message, 5, "Connection", "Keep-Alive");
        
        //编码
        byte[] data = ser.encode(prtl, false);
        if (dumpPacket) {
            IValueDumper.INSTANCE.dump(prtl);
        }
        
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(remoteHost, remotePort));
//        socket.setSoTimeout(1000);
        OutputStream outStm = socket.getOutputStream();
        final InputStream inStm = socket.getInputStream();
        final IEnsurableBitBuffer buffer = IBitBufferFactory.INSTANCE.createEnsurableBuffer();
        buffer.setEnsureTimeout(timeout);
        //发送Request
        outStm.write(data);
        //接收数据
        ExecutorService service = Executors.newSingleThreadExecutor();
        Future<Integer> recvJob = service.submit(new Callable<Integer>() {
            
            @Override
            public Integer call() throws Exception {
                byte[] recvData = new byte[1024];
                try {
                    int len = inStm.read(recvData);
                    while(len >= 0) {
//                        System.out.println("read:"+len);
                        //写数据
                        buffer.putByte(recvData, 0, len);
                        //读数据
                        len = inStm.read(recvData);
                    }
                } catch (IOException e) {
                    //忽略Socket关闭情况
                    if (!"socket closed".equals(e.getMessage())) {
                        throw e;
                    }
                    
                }
                //EOF
                buffer.setEof();
                return 1;
            }
        });
        
       //增量解码 
       IValue response = ProtocolUtils.incrementDecode(buffer, httpPrtlType);
       if (dumpPacket) {
           IValueDumper.INSTANCE.dump(response);
       }
       //关闭Socket
       socket.close();
       //等待接收任务结束
       recvJob.get();
       //停止线程池
       service.shutdown();
       //返回应答报文
       return response;
    }

    private void setHeader(IValue message, int index, String name, String value) throws MetaException {
        IContainerValue header = (IContainerValue)message.findField(
                "headers["+index+"]", true);
        header.getField("name").setText(name);
        header.getField("value").setText(value);
    }

    public boolean isDumpPacket() {
        return dumpPacket;
    }

    public void setDumpPacket(boolean dumpPacket) {
        this.dumpPacket = dumpPacket;
    }
}
```