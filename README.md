# SM3
a demo of message extension attack on SM3 hash function
SM3密码摘要算法是中国国家密码管理局2010年公布的中国商用密码杂凑算法标准。SM3算法适用于商用密码应用中的数字签名和验证，是在SHA-256基础上改进实现的一种算法。SM3算法采用Merkle-Damgard结构，消息分组长度为512位，摘要值长度为256位。
SM3算法的压缩函数与SHA-256的压缩函数具有相似的结构,但是SM3算法的设计更加复杂,比如压缩函数的每一轮都使用2个消息字。
首先找到SM3算法的相关C语言源文件，主要有以下几个函数。
![Image text](https://github.com/gytsg/SM3/tree/master/images/1.png)
  以及一个上下文结构体，规定了要处理的字节数、中间摘要状态、数据分组块等。
![Image text](https://github.com/gytsg/SM3/tree/master/images/2.png)
使用sm3_start、sm3_update、sm3_finish相关函数，通过构造的原始消息数据值、密钥，得到相应hash后的摘要值。
例如，设置原始消息数据值为“sspku”，设置密文值为“secret”，摘要结果为16进制输出，结果如图。
![Image text](https://github.com/gytsg/SM3/tree/master/images/4.png)
根据获取到的摘要，并构造{secret||data||added_data}数据，便可以在知道密文长度但不知道密文具体内容的情况下进行哈希长度扩展攻击，获得构造数据的摘要值。
主要函数如文末，输入原始数据、密文长度、原始摘要和新增的数据（为“gyt”），返回原始数据消息扩展后并添加而外数据的消息内容。
将结构体成员初始值设置为上次SM3哈希操作后状态。将字寄存器值设置为原始数据对应的摘要hash值，相当于在SM3计算过程中，完成了对前一个块的计算，直接对后续添加数据进行计算就行了。
![Image text](https://github.com/gytsg/SM3/tree/master/images/3.png)
结果如下图
![Image text](https://github.com/gytsg/SM3/tree/master/images/5.png)
根据扩展后的新消息数据，结合原密文，计算摘要值，对结果进行验证。发现两个摘要值相同，说明消息扩展攻击成功。
![Image text](https://github.com/gytsg/SM3/tree/master/images/6.png)
Demo完整输出
![Image text](https://github.com/gytsg/SM3/tree/master/images/7.png)
/**
 * \brief          SM3 generate stretch data
 *
 * \param originalMessage      Original Message Data
 * \param keylength            length of the secret key
 * \param hash                 Original Signature
 * \param added                Added Message Data
 * \param newSig               New Signature
 */
/*
* SM3 generate stretched data
*/
vector<unsigned char>* GenerateStretchedData(vector<unsigned char> originalMessage, int keylength,
                                             unsigned char * hash, vector<unsigned char> added,
                                             unsigned char * newSig)
{
	vector<unsigned char> * ret = new vector<unsigned char>();
	for(unsigned int x = 0; x < originalMessage.size(); x++)
		ret->push_back(originalMessage[x]);
	int tailLength = ret->size() + keylength;
	tailLength *= 8;
	ret->push_back(0x80);
	while((ret->size() + keylength + 8) % 64 != 0)
	{
		ret->push_back(0x00);
	}
	for (int i = 0; i < 4; ++i)
		ret->push_back(0x00);
	ret->push_back((tailLength >> 24) & 0xFF);
	ret->push_back((tailLength >> 16) & 0xFF);
	ret->push_back((tailLength >> 8) & 0xFF);
	ret->push_back((tailLength) & 0xFF);
	sm3_context stretch;
	sm3_starts(&stretch);
	stretch.total[0] = (ret->size() + keylength);
	stretch.state[0] = hash[3] | (hash[2] << 8) | (hash[1] << 16) | (hash[0] << 24);
	stretch.state[1] = hash[7] | (hash[6] << 8) | (hash[5] << 16) | (hash[4] << 24);
	stretch.state[2] = hash[11] | (hash[10] << 8) | (hash[9] << 16) | (hash[8] << 24);
	stretch.state[3] = hash[15] | (hash[14] << 8) | (hash[13] << 16) | (hash[12] << 24);
	stretch.state[4] = hash[19] | (hash[18] << 8) | (hash[17] << 16) | (hash[16] << 24);
	stretch.state[5] = hash[23] | (hash[22] << 8) | (hash[21] << 16) | (hash[20] << 24);
	stretch.state[6] = hash[27] | (hash[26] << 8) | (hash[25] << 16) | (hash[24] << 24);
	stretch.state[7] = hash[31] | (hash[30] << 8) | (hash[29] << 16) | (hash[28] << 24);
	unsigned char * toadd = new unsigned char[added.size()];
	for(unsigned int x = 0; x < added.size(); x++)
	{
		toadd[x] = added[x];
	}
	sm3_update(&stretch, toadd, added.size());
	sm3_finish(&stretch, newSig);

	delete [] toadd;
	for(unsigned int x = 0; x < added.size(); x++)
	{
		ret->push_back(added.at(x));
	}
	return ret;
}
