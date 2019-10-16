# SM3
a demo of message extension attack on SM3 hash function
SM3密码摘要算法是中国国家密码管理局2010年公布的中国商用密码杂凑算法标准。SM3算法适用于商用密码应用中的数字签名和验证，是在SHA-256基础上改进实现的一种算法。SM3算法采用Merkle-Damgard结构，消息分组长度为512位，摘要值长度为256位。
SM3算法的压缩函数与SHA-256的压缩函数具有相似的结构,但是SM3算法的设计更加复杂,比如压缩函数的每一轮都使用2个消息字。
首先找到SM3算法的相关C语言源文件，主要有以下几个函数。
![Image text](https://github.com/gytsg/SM3/blob/master/images/1.png)
  以及一个上下文结构体，规定了要处理的字节数、中间摘要状态、数据分组块等。
![Image text](https://github.com/gytsg/SM3/blob/master/images/2.png)
使用sm3_start、sm3_update、sm3_finish相关函数，通过构造的原始消息数据值、密钥，得到相应hash后的摘要值。
例如，设置原始消息数据值为“sspku”，设置密文值为“secret”，摘要结果为16进制输出，结果如图。
![Image text](https://github.com/gytsg/SM3/blob/master/images/4.png)
根据获取到的摘要，并构造{secret||data||added_data}数据，便可以在知道密文长度但不知道密文具体内容的情况下进行哈希长度扩展攻击，获得构造数据的摘要值。
主要函数如文末，输入原始数据、密文长度、原始摘要和新增的数据（为“gyt”），返回原始数据消息扩展后并添加而外数据的消息内容。
将结构体成员初始值设置为上次SM3哈希操作后状态。将字寄存器值设置为原始数据对应的摘要hash值，相当于在SM3计算过程中，完成了对前一个块的计算，直接对后续添加数据进行计算就行了。
![Image text](https://github.com/gytsg/SM3/blob/master/images/3.png)
结果如下图
![Image text](https://github.com/gytsg/SM3/blob/master/images/5.png)
根据扩展后的新消息数据，结合原密文，计算摘要值，对结果进行验证。发现两个摘要值相同，说明消息扩展攻击成功。
![Image text](https://github.com/gytsg/SM3/blob/master/images/6.png)
Demo完整输出
![Image text](https://github.com/gytsg/SM3/blob/master/images/7.png)
主要函数代码
![image text](https://github.com/gytsg/SM3/blob/master/images/8.png)
![image text](https://github.com/gytsg/SM3/blob/master/images/9.png)
