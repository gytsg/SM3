#include <bits/stdc++.h>
#include "sm3.h"

using namespace std;

vector<unsigned char> StringToVector(unsigned char * str);
vector<unsigned char>* GenerateStretchedData(vector<unsigned char> originalMessage, int keylength,
                                             unsigned char * hash, vector<unsigned char> added,
                                             unsigned char * newSig);


int main()
{
    sm3_context ctx;
    string key = "secret";
    int key_len = 6;
    string input = "sspku";
    int input_len = 5;
    unsigned char output[32];
    printf("Input Message Is:\n");
    cout<<input<<endl;
    sm3_starts(&ctx);
    sm3_update(&ctx, (unsigned char*)key.c_str(), key_len);
    sm3_update(&ctx, (unsigned char*)input.c_str(), input_len);
    sm3_finish(&ctx, output);
    
    printf("The Hash Value Is:\n");
    for(int i=0; i<32; ++i)
    {
        printf("%02x", output[i]);
        if(((i+1) % 4) == 0) printf(" ");
    }
    printf("\n");

    string addedstr = "gyt";
    vector<unsigned char> added = StringToVector((unsigned char*)addedstr.c_str());
    vector<unsigned char> originmessage = StringToVector((unsigned char*)input.c_str());
    unsigned char second_signature[32];

    vector<unsigned char> * new_data = GenerateStretchedData(originmessage, key_len, output,
                          added, second_signature);

    string newdata;
    for(vector<unsigned char>::iterator it=new_data->begin();
        it!=new_data->end(); it++)
    {
        newdata += (*it);
    }
    cout<<"Extended Message Data Is:"<<endl;
    cout<<newdata<<endl;
    cout<<"The New Hash Value Is:"<<endl;
    for(int i=0; i<32; ++i)
    {
        printf("%02x", second_signature[i]);
        if(((i+1) % 4) == 0) printf(" ");
    }
    printf("\n");

    sm3_context ctx2;
    unsigned char output2[32];
    sm3_starts(&ctx2);
    sm3_update(&ctx2, (unsigned char*)key.c_str(), key_len);
    sm3_update(&ctx2, (unsigned char*)newdata.c_str(), newdata.size());
    sm3_finish(&ctx2, output2);

    printf("The Verified Hash value Is:\n");
    for(int i=0; i<32; ++i)
    {
        printf("%02x", output2[i]);
        if(((i+1) % 4) == 0) printf(" ");
    }
    printf("\n");
    return 0;
}



vector<unsigned char> StringToVector(unsigned char * str)
{
	vector<unsigned char> ret;
	for(unsigned int x = 0; x < strlen((char*)str); x++)
	{
		ret.push_back(str[x]);
	}
	return ret;
}

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
