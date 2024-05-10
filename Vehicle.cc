#include <omnetpp.h>
#include <cmath>
#include <Crypto++/sha.h>
#include <Crypto++/sha3.h>
#include <Crypto++/eccrypto.h>
#include <Crypto++/oids.h>
#include <Crypto++/hex.h>
#include <Crypto++/osrng.h>
#include <Partial_Priv_Key_reqMsg.h>
#include <Encrypted_Msg.h>
#include <Crypto++/dh.h>
#include <Crypto++/aes.h>
#include <Crypto++/modes.h>
#include <Public_Key_Req.h>
#include <Public_Key_msg.h>
#include <string>
#include "Partial_Priv_Key_Msg.h"
#include "Public_Key_msg.h"
#include "Public_Key_Req_msg.h"
#include "Confirmation_Msg.h"
#include "Requested_Public_Key_Msg.h"
#include "CompromizedSharedSecretKey.h"
#include<Attacker.h>
#include<TAPublicKey.h>

using namespace omnetpp;
using namespace CryptoPP;
using namespace std;

class Vehicle : public cSimpleModule {
private:
    int Src;
    int Dest;
    Integer Qd;
    ECP::Point Od;
    DL_GroupParameters_EC<ECP> params;
    pair<ECP::Point, ECP::Point> PublicKey;
    pair<Integer, Integer> PrivateKey;
    Integer sharedSecret;
    string CipherText;
    string digitalSignature; // New member variable for digital signature
    ECP::Point SrcVehiclePublicKey;
    ECP::Point DestVehiclePublicKey;
    AutoSeededRandomPool prng;
    int lastSequenceNumberSent;
    int lastSequenceNumberReceived;
    vector<int> SequenceNumRecived;
    int NumRecivedMsgs;
    int AttackNum;
    int NumOfEncMsgSent=0;
    bool SendMultiLegitEncMsg=false; //To test multiple encrypted messages sent from legitimate source
    Encrypted_Msgr *encryptedMsg;
    TA_PublicKey *ta_publickey;
    ECP::Point TAPublicKey;
    Public_Key_Req_Msg *public_key_req_msg;
    Integer performKeyExchange(const ECP::Point& Public_Key_msg, const Integer& privateKey);
    string symmetricEncrypt(const string& plaintext, const Integer& sharedSecret);
    string symmetricDecrypt(const string& ciphertext, const Integer& sharedSecret);
    ECP::Point multiplyScalar(const Integer &k, const ECP::Point &P, const DL_GroupParameters_EC<ECP> &param);
    Integer hash(string& input);
    string generateDigitalSignature(const string& message, const Integer& privateKey); // New function for digital signature generation
    bool verifyDigitalSignature(const string& message, const string& signature, const ECP::Point& publicKey); // New function for digital signature verification
    Encrypted_Msgr* SetEncryptedMsg(Requested_Public_Key_Msg *requested_public_key);
    void CheckSequenceNumber(string& DecryptedMessage,Encrypted_Msgr *encryptedMsg);
    bool verifyPublicKeySignature(const pair<ECP::Point, ECP::Point>& publicKey, const string& signature, const ECP::Point& TAPublicKey);
    void serializeECPPoint(const ECP::Point& point, string& output);
protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;

};

Define_Module(Vehicle);

void Vehicle::initialize() {

       params = ASN1::secp256r1();
       Src = par("src");
       Dest = par("dest");

       ECP::Point D = params.GetSubgroupGenerator();


       Qd = Integer(prng, Integer::One(), params.GetSubgroupOrder() - 1);    // first priv key generated inside vehicle
       Od = multiplyScalar(Qd, D, params);    // first public key generated inside vehicle

       // Initialize variables

       lastSequenceNumberReceived = 0;
       lastSequenceNumberSent=0;
       NumRecivedMsgs = 0;


       // Calculate a randomized delay before sending the partial private key request
       // Average time between each random number is 1/0.1=10
       double delay = exponential(0.1);  // Adjust the delay distribution as needed

       // Schedule the partial private key request message to be sent after the delay
       Partial_Priv_Key_reqMsg *message = new Partial_Priv_Key_reqMsg();
       scheduleAt(simTime() + delay, message);  // Schedule message with delay

       Attacker attackerModule; // Create an object of the Attacker class
       AttackNum = attackerModule.attackNum;

}


void Vehicle::handleMessage(cMessage *msg) {

    if (msg->isSelfMessage()){
            // If the message is a self-message, it's time to send the partial private key request
            if(Partial_Priv_Key_reqMsg *partialPrivKeyReqMsg = dynamic_cast<Partial_Priv_Key_reqMsg *>(msg)){
            partialPrivKeyReqMsg->setOd(Od);
            partialPrivKeyReqMsg->setID(getId());
            send(partialPrivKeyReqMsg,"Vout");
            }
        }


    if (Partial_Priv_Key_Msg *Pb_Pr_Msg = dynamic_cast<Partial_Priv_Key_Msg *>(msg)) {
        //here we extract the information that KGC sent
           ECP::Point zeta_d_received = Pb_Pr_Msg->getZeta_d();
           Integer beta_d = Pb_Pr_Msg->getBeta_d();
           ECP::Point gamma = Pb_Pr_Msg->getgamma();
           EV << "Vehicle received partial private key" << endl;
//here this equ. is used to generate the public and private keys using partial private key or extracted value above

          // Calculate gamma*Qd
           ECP::Point gamma_Qd = multiplyScalar(Qd, gamma, params);
           Integer xCoord = gamma_Qd.x;
           Integer yCoord = gamma_Qd.y;

           // Concatenate ID_d with x and y coordinates of gamma*Qd
           string xCoordStr = IntToString(xCoord);
           string yCoordStr = IntToString(yCoord);
           string xyCoord = xCoordStr + yCoordStr;
           string concatenatedString = to_string(getId()) + xyCoord;

           // Calculate hash(ID_d, gamma*Qd)
           Integer hash_ID_gamma_Qd = hash(concatenatedString);

           // Calculate Yd = beta_d - hash(ID_d, gamma*Q_d)
           Integer y_d = beta_d - hash_ID_gamma_Qd;

           // Calculate z_d = Y_d * D
           ECP::Point z_d = multiplyScalar(y_d, params.GetSubgroupGenerator(), params);

//here we make pair with the new generated  private and public key .
               // Store the public and private keys
               PublicKey = make_pair(Od, z_d);
               PrivateKey = make_pair(Qd, y_d);


               EV << "Vehicle calculating its public and private key" << endl;
               EV << "Public key of: " <<getName()<<" "<<PublicKey.first.x <<endl;
               EV << "Private key of: " <<getName()<<" "<< PrivateKey.second <<endl;
               // Proceed with sending the public key message
               Public_Key_msg *pub_key_msg = new Public_Key_msg();
               pub_key_msg->setKey(PublicKey);
               pub_key_msg->setID(getId());
               send(pub_key_msg, "Vout");

       }



//here the TA confrim with the vehicle that its public key is stored

    if (Confirmation_Msg *confirmation = dynamic_cast<Confirmation_Msg *>(msg)) {
        //here SRC vehicle want to get DEST vehicle's public key
        if (Src == getId()) {
            public_key_req_msg = new Public_Key_Req_Msg();
            public_key_req_msg->setID(Dest);
            public_key_req_msg->setSenderVehicleId(Src);
            cMessage *msg=new cMessage("null"); // here this message is made to help him know which type of message is needed
            scheduleAt(simTime() + 0.2, msg);
        }
    }if(msg->isSelfMessage() && strcmp(msg->getName(), "null") == 0){
       send(public_key_req_msg,"Vout");
    }
    // this is the part where vehicle recieves the TA pk
   if((ta_publickey = dynamic_cast<TA_PublicKey *>(msg))){

       TAPublicKey=ta_publickey->getTAPublicKey();

   }


//here he make sure that the source that req. the public jey of the dest.
    if (Requested_Public_Key_Msg *requested_public_key = dynamic_cast<Requested_Public_Key_Msg *>(msg)) {
        if (Src == getId()) {
//here the replay attack where the attacker gets the req. public key of the source.
            if(AttackNum == 1){
                Encrypted_Msgr *message = SetEncryptedMsg(requested_public_key);
                send(message, "Vout2");
            }else if(AttackNum == 2){
                Encrypted_Msgr *message = SetEncryptedMsg(requested_public_key);
                 send(message, "Vout2");
                 CompromizedSharedSecretKey *compromizedsharedsecretkey=new CompromizedSharedSecretKey();
                 compromizedsharedsecretkey->setComprSharedSecret(sharedSecret);
                 send(compromizedsharedsecretkey,"Vout2");

            }else if((AttackNum < 1 || AttackNum > 2) && AttackNum!=5){
                Encrypted_Msgr *message = SetEncryptedMsg(requested_public_key);
                send(message, "Vout");
                if(SendMultiLegitEncMsg){
                   NumOfEncMsgSent++;
                   if(NumOfEncMsgSent < 4){
                   scheduleAt(simTime() + 0.01, new Requested_Public_Key_Msg());
                   }else{
                        return;
                     }
                }
            }else if(AttackNum ==5){
                bool VerifyRequestedPublicKey=verifyPublicKeySignature(requested_public_key->getRequestedPublickey(),requested_public_key->getDigitalSignature(), TAPublicKey);
                            if(VerifyRequestedPublicKey){
                                EV<<"Public key received is authenticated"<<endl;
                            }else{
                                EV<<"Wrong key:Not the key of the intended vehicle"<<endl;
                                scheduleAt(simTime() + 2.0,new Confirmation_Msg());
                                return;
                            }


                            Encrypted_Msgr *message = SetEncryptedMsg(requested_public_key);
                            send(message, "Vout");
            }


        } else if (Dest == getId()) {

            SrcVehiclePublicKey = requested_public_key->getRequestedPublickey().second;
            Integer sharedSecret = performKeyExchange(SrcVehiclePublicKey, PrivateKey.second);
            EV << "Shared secret for vehicle 2 " << sharedSecret << endl;
            string DecryptedMessage = symmetricDecrypt(CipherText, sharedSecret);

            EV<<"Decrypted message: "<<DecryptedMessage<<endl;
            EV<<"Digital signature: "<<digitalSignature<<endl;


            if(AttackNum == 1||SendMultiLegitEncMsg){
                CheckSequenceNumber(DecryptedMessage,encryptedMsg);
            }

            bool signatureValid = verifyDigitalSignature(DecryptedMessage, digitalSignature,requested_public_key->getRequestedPublickey().first); // Verify digital signature
            if (signatureValid) {
                EV << "Digital signature verification succeeded!" << endl;
            } else {
                EV << "Digital signature verification failed! Possible tampering detected." << endl;
                // Handle the case where the signature is invalid
            }


        }
    }

    if ((encryptedMsg = dynamic_cast<Encrypted_Msgr *>(msg))) {
        CipherText = encryptedMsg->getMessage();
        digitalSignature = encryptedMsg->getDigitalSignature();

        if (NumRecivedMsgs == 0) {
            Public_Key_Req_Msg *public_key_req_msg = new Public_Key_Req_Msg();
            public_key_req_msg->setID(Src);
            public_key_req_msg->setSenderVehicleId(Dest);
            send(public_key_req_msg, "Vout");

            NumRecivedMsgs++;
        } else {
            Integer sharedSecret = performKeyExchange(SrcVehiclePublicKey, PrivateKey.second);
            EV << "Shared secret for vehicle 2 " << sharedSecret << endl;
            string DecryptedMessage = symmetricDecrypt(CipherText, sharedSecret);
            EV<<"Decrypted message: "<<DecryptedMessage<<endl;
            NumRecivedMsgs++;
            CheckSequenceNumber(DecryptedMessage,encryptedMsg);

        }
    }

}
void Vehicle::CheckSequenceNumber(string& DecryptedMessage,Encrypted_Msgr *encryptedMsg){
    size_t pos = DecryptedMessage.find_last_of(' ');
    string sequenceNumberStr = DecryptedMessage.substr(pos + 1);
    lastSequenceNumberReceived=stoi(sequenceNumberStr);

    auto it = std::find(SequenceNumRecived.begin(), SequenceNumRecived.end(), lastSequenceNumberReceived);
    if(NumRecivedMsgs > 1){
         if (it != SequenceNumRecived.end()) {
            EV << "Replay Attack" << endl;
            EV<<"Discard Message"<<endl;
            delete encryptedMsg;

          } else {
            EV << "Not Replay Attack" << endl;
            SequenceNumRecived.push_back(lastSequenceNumberReceived); // Add lastSequenceNumberReceived to SequenceNumRecived
         }
   }else{
        SequenceNumRecived.push_back(lastSequenceNumberReceived); // Add lastSequenceNumberReceived to SequenceNumRecived
    }
}
Encrypted_Msgr* Vehicle::SetEncryptedMsg(Requested_Public_Key_Msg *requested_public_key){

    DestVehiclePublicKey = requested_public_key->getRequestedPublickey().second;
    Encrypted_Msgr *message = new Encrypted_Msgr();
    message->setMessage("accident on road 9 SEQ# "+to_string(lastSequenceNumberSent));
    string plaintextMessage = message->getMessage();
    sharedSecret = performKeyExchange(DestVehiclePublicKey, PrivateKey.second);
    EV << "Shared secret for vehicle 1 " << sharedSecret << endl;
    string encryptedMessage = symmetricEncrypt(plaintextMessage, sharedSecret);
    digitalSignature = generateDigitalSignature(plaintextMessage, PrivateKey.first); // Generate digital signature
    EV << "Digital Signature: " << digitalSignature << endl;
    EV << "Encrypted Message: " << encryptedMessage << endl;
    message->setMessage(encryptedMessage);
    message->setDigitalSignature(digitalSignature);
    lastSequenceNumberSent++;
    return message;

}
ECP::Point Vehicle::multiplyScalar(const Integer &k, const ECP::Point &P, const DL_GroupParameters_EC<ECP> &param) {

    ECP::Point result = param.GetCurve().ScalarMultiply(P, k);
    return result;

}

Integer Vehicle::hash(string& input) {
    SHA3_256 hash;
    byte digest[SHA3_256::DIGESTSIZE];
    hash.Update(reinterpret_cast<const byte*>(input.data()), input.size());
    hash.Final(digest);
    Integer hashResult;
    hashResult.Decode(digest, SHA3_256::DIGESTSIZE);
    return hashResult;
}

Integer Vehicle::performKeyExchange(const ECP::Point& Public_Key, const Integer& privateKey) {
    Integer PrivateKey = privateKey;
    ECP::Point PublicKey = Public_Key;
    ECDH<ECP>::Domain dh(ASN1::secp256r1());
    SecByteBlock privateKeyBytes;
    PrivateKey.Encode(privateKeyBytes, privateKeyBytes.SizeInBytes());
    SecByteBlock Public_Key_Bytes;
    PublicKey.x.Encode(Public_Key_Bytes, Public_Key_Bytes.SizeInBytes());
    PublicKey.y.Encode(Public_Key_Bytes, Public_Key_Bytes.SizeInBytes());
    SecByteBlock agreedValue(dh.AgreedValueLength());
    dh.Agree(agreedValue, privateKeyBytes, Public_Key_Bytes);
    Integer sharedSecret(agreedValue, agreedValue.size());
    return sharedSecret;
}

string Vehicle::symmetricEncrypt(const string& plaintext, const Integer& sharedSecret) {
    SecByteBlock key(AES::MAX_KEYLENGTH);
    sharedSecret.Encode(key, key.size());
    CFB_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, key.size(), key);
    string ciphertext;
    StringSource(plaintext, true, new StreamTransformationFilter(encryption, new StringSink(ciphertext)));
    return ciphertext;
}

string Vehicle::symmetricDecrypt(const string& ciphertext, const Integer& sharedSecret) {
    SecByteBlock key(AES::MAX_KEYLENGTH);
    sharedSecret.Encode(key, key.size());
    CFB_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, key.size(), key);
    string decryptedMessage;
    StringSource(ciphertext, true, new StreamTransformationFilter(decryption, new StringSink(decryptedMessage)));
    return decryptedMessage;
}


string Vehicle::generateDigitalSignature(const string& message, const Integer& privateKey) {

    AutoSeededRandomPool prng;

    // Initialize the ECDSA signer with the private key
    ECDSA<ECP, SHA256>::Signer signer;
    signer.AccessKey().Initialize(params, privateKey);

    // Sign the message
    SecByteBlock signature(signer.MaxSignatureLength());
    size_t signatureLength = signer.SignMessage(prng, (const byte*)message.data(), message.size(), signature);
    signature.resize(signatureLength);

    // Convert the signature to a hexadecimal string
    string signatureStr;
    StringSource(signature, signature.size(), true, new HexEncoder(new StringSink(signatureStr)));

    return signatureStr;
}

bool Vehicle::verifyDigitalSignature(const string& message, const string& signature, const ECP::Point& publicKey) {
    AutoSeededRandomPool prng;

    // Initialize the ECDSA public key
    ECDSA<ECP, SHA256>::PublicKey ecPublicKey;
    ecPublicKey.Initialize(params, publicKey);

    // Decode the signature from hexadecimal
    string signatureDecoded;
    StringSource(signature, true, new HexDecoder(new StringSink(signatureDecoded)));

    // Initialize the ECDSA verifier
    ECDSA<ECP, SHA256>::Verifier verifier(ecPublicKey);

    // Verify the message signature
    return verifier.VerifyMessage((const byte*)message.data(), message.size(), (const byte*)signatureDecoded.data(), signatureDecoded.size());
}

// Vehicle module

bool Vehicle::verifyPublicKeySignature(const pair<ECP::Point, ECP::Point>& publicKey, const string& signature, const ECP::Point& TAPublicKey) {
    // Serialize the public key points to a string
    string publicKeyStr;
    serializeECPPoint(publicKey.first, publicKeyStr);
    serializeECPPoint(publicKey.second, publicKeyStr);

    // Initialize the ECDSA verifier with the TA's public key
    ECDSA<ECP, SHA256>::Verifier verifier;
    verifier.AccessKey().Initialize(params, TAPublicKey);

    // Decode the signature from hexadecimal
    string signatureDecoded;
    StringSource(signature, true, new HexDecoder(new StringSink(signatureDecoded))); // Decode the signature

    // Verify the signature of the serialized public key
    // Implement your verification logic here using 'verifier' and 'signatureDecoded'
    // For example:
     return verifier.VerifyMessage((const byte*)publicKeyStr.data(), publicKeyStr.size(), (const byte*)signatureDecoded.data(), signatureDecoded.size());
}



void Vehicle::serializeECPPoint(const ECP::Point& point, string& output) {
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


