# AE-MINING-VERIFY
Some information for mine pool of AE.

# AE Stratum通信协议

总体来说，协议源自标准BTC-Stratum协议，绝大部分与BTC的一致，少量变动如下：



## 设置难度

```
{"id": null, "method": "mining.set_difficulty", "params": [1]}
```

*注意：diff 1对应的target为 0xFFFF000000000000000000000000000000000000000000000000000000000000



## 广播任务

```
{ 
	"id":null,
	"method":"mining.notify", 
	"params":[
    	"jobid", //任务id
         "af8cecebf98...43100000000", // 任务hash，
         "3078",//高度
         "2400ffff",//nbits 网络难度
          false // 是否重置任务,true时需要强制打断并更新
     ] 
 }
```





## 任务提交

```
{ 
     "id":1,
	"method": "mining.submit",
     "params": [
     	"user", //用户名
     	"jobid", //任务id
        "00000000", //extranonce2，【extranonce1+extranonce2】作最终nonce使用 总长度为8字节
        [ff,fff,ffff,fffff,ffffff,....42个]//soln hex类型，从小到大排列
      ], 
  }
```



# 具体的逻辑如下：



**一、获取任务**

GET  http://HOST:PORT/v2/key-blocks/pending

得到

{

​	"beneficiary":"ak_nv5B93FPzRHrGNmMdTDfGdd5xGZvep3MVSpJqzcQmMp59bBCv",
	"hash":"kh_MnKqPJa5Ufw3AoFK9boZVwyuvosnxysZrPyMi7WQAUnukxNdF",
	"height":61252,
	"info":"cb_Xfbg4g==",
	"miner":"ak_2CFBBH56MovGZaKNiXnwNhuxM3ZFYfAdJvty9QRMEpnnXrA62F",
	"prev_hash":"mh_2JaucLFSmsKjxBGtiWBrePpRqdYqVbhigJGDvtFaV5H8LyGfF",
	"prev_key_hash":"kh_2Y8bDb2cBzYwoEm1a4FwwVMk2tmWqQ7qhwJho6gEhQj5c627M6",
	"state_hash":"bs_ebUW1svahK2hvTqJgrYZbLXdoZMqWbUYSrBDA7e9pAc32LT6P",
	"target":503666254,
	"time":1554391693687,
	"version":2
}

**二、下发任务**

​	将上面获得的hash字段，去除前面kh_后，通过base58解码，得到一个带校验码的hash字符串

```
2f2fd55716b37ae827777bb151a7905bf88e70701e837cb63da29969df130d53b296b8b2
```

，

其中最后4字节的[**b296b8b2**]为校验位，我们取前面32个字节作为运算hash下发给矿机，同时nbits为target的hex形式，**503666254**转换为 **1e05564e**

## 

```
{ 
	"id":null,
	"method":"mining.notify", 
	"params":[
    	 "01", //任务id
         "2f2fd55716b37ae827777bb151a7905bf88e70701e837cb63da29969df130d53", // 任务hash，
         "61252",//高度
         "1e05564e",//nbits 网络难度
          true // 是否重置任务,true时需要强制打断并更新
     ] 
 }
```



**三、矿池验证**

我们假定在subscribe的时候，矿池下发的extranonce1是 **00000001**，矿机提交的extranonce2为**ffffffff**，那么nonce值即为 **00000001ffffffff**

我们将42个pow值转换为高位的hex类型，同时记得补位为4个字节（int32），将这些值连接起来，得到一个4*42长度字符串，我们将这个字符串进行blake2b hash运算，得到一个新的32字节hash，这个hash即为验证是否符合难度的依据。

将我们得到的hash转为bigint后与target进行比较，即可很容易得知是否符合难度。

网络target的计算方式为，取nbits的第一位转为num，用32-num得到填充字节数，填充到后三个字节的前方，然后在后方填充0至32字节。如 1e05564e 对应的网络target：

```
000005564e000000000000000000000000000000000000000000000000000000
```

在判断是否符合难度之后，我们还要对pow进行验证以防止用户伪造

将  下发任务的 hash：2f2fd55716b37ae827777bb151a7905bf88e70701e837cb63da29969df130d53 进行base64_encode得到字符串A，将nonce **00000001ffffffff** 取低位 ，变为**ffffffff01000000** 后也进行base64_encode得到字符串B。理论上来说A的长度为44字节，B的长度为12字节，我们将A,B连接起来，同时将字符串用0补位至80字节。

```
base64_encode(2f2fd55716b37ae827777bb151a7905bf88e70701e837cb63da29969df130d53)+base64_encode(Little_endian(00000001ffffffff)+000000000000000000000000000000000000000000000000)
```

将得到的80字节header信息通过blake2b算法得到一个hash

将这个hash以及上面得到的pow（4*42）字符串传入验证方法中进行验证，验证结果为true即为通过。

验证的C代码请查阅hash.cpp文件，入口函数为 cuckoo_hash，input为这个hash pow为pow字符串，均为char*类型

> **特别提醒，在本文中提到的字节长度均为bin类型的字节长度，而非为了演示而输出的明文长度。所有在过程中的计算也都是以bin格式！**



**四、钱包提交**

POST http://HOST:PORT/v2/key-blocks

> 这里值得注意的是，提交的端口与获取任务的端口不在一起。默认情况下，这个端口钱包绑定为本地ip了，若有需要可以自行代理。

提交参数为

```
$submitData = array(
                'beneficiary' => $jobInfo['beneficiary'],
                'hash' => $blockInfo['hash'],
                'height' => $jobInfo['height'],
                'miner' => $jobInfo['miner'],
                'nonce' => $blockInfo['nonce'],
                'pow' => $blockInfo['pow'],
                'prev_hash' => $jobInfo['prev_hash'],
                'prev_key_hash' => $jobInfo['prev_key_hash'],
                'state_hash' => $jobInfo['state_hash'],
                'target' => $jobInfo['target'],
                'time' => $jobInfo['time'],
                'version' => $jobInfo['version']
            );
```

我们仅仅需要将nonce，pow两个参数替换为对应的bigint即可，如

```
nonce=>946100507733033697 
pow=>[1560783,19899683,26686884,46248240,67228330,67462610,81845721,82212294,95644328,117214348,131016563,134907685,149152069,167975924,172121090,176628994,181680730,199555343,213336391,236833391,249002949,250003707,253186513,257023444,260854574,283273465,291448562,302932608,334509518,378329704,390835709,399857883,403430292,439781816,449635696,454957446,456197940,456798583,460230294,467496111,517848387,524126360]
```

值得注意的是，此处必须都为bigint类型，不能为字符串，否则钱包的api过滤器会直接过滤。



**然后就可以享受胜利的果实啦！**

