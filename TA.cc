#include <omnetpp.h>
#include <Crypto++/sha.h>
#include <Crypto++/sha3.h>
#include <Crypto++/eccrypto.h>
#include <Crypto++/oids.h>
#include <Crypto++/hex.h>
#include <Crypto++/osrng.h>
#include <Crypto++/queue.h>
#include <Crypto++/filters.h>
#include <string>
#include "Partial_Priv_Key_reqMsg.h"
#include "Encrypted_Msg.h"
#include "Partial_Priv_Key_Msg.h"
#include<Public_Key_Req.h>
#include "Public_Key_msg.h"
#include "Confirmation_Msg.h"
#include"Public_Key_Req_msg.h"
#include "Requested_Public_Key_Msg.h"
#include<TAPublicKey.h>

using namespace omnetpp;
using namespace CryptoPP;
using namespace std;

class TA : public cSimpleModule {
private:
    DL_GroupParameters_EC<ECP> params;
    ECP::Point PublicKey_TA;
    Integer PrivateKey_TA;
    AutoSeededRandomPool prng;
    map<int, pair<ECP::Point, ECP::Point>> Cloud;
    string PublicKeySignature;
    ECP::Point multiplyScalar(const Integer &k, const ECP::Point &P, const DL_GroupParameters_EC<ECP> &param);
    string signPublicKey(const pair<ECP::Point, ECP::Point>& publicKey, const Integer& privateKey);
    void serializeECPPoint(const ECP::Point& point, string& output);
protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
};

Define_Module(TA);

void TA::initialize() {
    params = ASN1::secp256r1();

    ECP::Point D = params.GetSubgroupGenerator();

    PrivateKey_TA = Integer(prng, Integer::One(), params.GetSubgroupOrder() - 1);
    PublicKey_TA = multiplyScalar(PrivateKey_TA, D, params);

}
void TA::handleMessage(cMessage *msg) {

     /* Public_Key_Req *pubToTA = dynamic_cast<Public_Key_Req *>(msg);

        Cloud[pubToTA->getID()] = pubToTA->getPublicKey(); */
     if (Public_Key_msg *publickey = dynamic_cast<Public_Key_msg *>(msg)) {

               Cloud[publickey->getID()]= publickey->getKey();
               EV<<publickey->getID()-1<<endl;
               EV<<Cloud[publickey->getID()].first.x<<endl;
               Confirmation_Msg *confirmation=new Confirmation_Msg;
               confirmation->setDone(true);
               confirmation->setVehicleID(publickey->getID());
               send(confirmation,"TAOUT",0);

               TA_PublicKey *ta_publickey=new TA_PublicKey();
               ta_publickey->setTAPublicKey(PublicKey_TA);
               ta_publickey->setVehicleID(publickey->getID());
               send(ta_publickey,"TAOUT",0);

            }
     else if (Public_Key_Req_Msg *public_key_req_msg = dynamic_cast<Public_Key_Req_Msg *>(msg)) {
               Requested_Public_Key_Msg *RequestedPublicKey=new Requested_Public_Key_Msg();
               RequestedPublicKey->setRequestedPublickey(Cloud[public_key_req_msg->getID()]);
               RequestedPublicKey->setDestinationVehicleId(public_key_req_msg->getSenderVehicleId());

               PublicKeySignature=signPublicKey(Cloud[public_key_req_msg->getID()],PrivateKey_TA);

               RequestedPublicKey->setDigitalSignature(PublicKeySignature);
               send(RequestedPublicKey,"TAOUT",0);
            }

}
ECP::Point TA::multiplyScalar(const Integer &k, const ECP::Point &P, const DL_GroupParameters_EC<ECP> &param) {
    ECP ec = param.GetCurve();
    ECP::Point result = ec.ScalarMultiply(P, k);
    return result;
}
// TA module

string TA::signPublicKey(const pair<ECP::Point, ECP::Point>& publicKey, const Integer& privateKey) {

    AutoSeededRandomPool prng;

    // Initialize the ECDSA signer with the private key
    ECDSA<ECP, SHA256>::Signer signer;
    signer.AccessKey().Initialize(params, privateKey);

    // Serialize the public key points to strings
    string publicKeyStr;
    serializeECPPoint(publicKey.first, publicKeyStr);
    serializeECPPoint(publicKey.second, publicKeyStr);

    // Sign the serialized public key
    SecByteBlock signature(signer.MaxSignatureLength());
    size_t signatureLength = signer.SignMessage(prng, (const byte*)publicKeyStr.data(), publicKeyStr.size(), signature);
    signature.resize(signatureLength);

    // Convert the signature to a hexadecimal string
    string signatureStr;
    StringSource(signature, signature.size(), true, new HexEncoder(new StringSink(signatureStr)));
    return signatureStr;
}

void TA::serializeECPPoint(const ECP::Point& point, string& output) {
    // Serialize x-coordinate
    string xStr;
    HexEncoder encoder(new StringSink(xStr));  // Create a HexEncoder with a StringSink
    point.x.Encode(encoder, point.x.MinEncodedSize());
    encoder.MessageEnd();  // Signal the end of the message

    // Serialize y-coordinate
    string yStr;
    HexEncoder encoder2(new StringSink(yStr));  // Create a second HexEncoder with a StringSink
    point.y.Encode(encoder2, point.y.MinEncodedSize());
    encoder2.MessageEnd();  // Signal the end of the message

    output += xStr + yStr;  // Append serialized coordinates to output
}








