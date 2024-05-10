#include <omnetpp.h>
#include <Crypto++/sha.h>
#include <Crypto++/sha3.h>
#include <Crypto++/eccrypto.h>
#include <Crypto++/oids.h>
#include <Crypto++/hex.h>
#include <Crypto++/osrng.h>
#include<string>
#include<Partial_Priv_Key_reqMsg.h>
#include "Partial_Priv_Key_Msg.h"


using namespace omnetpp;
using namespace CryptoPP;
using namespace std;

class KGC : public cSimpleModule {

private:
    Integer private_key;
    ECP::Point public_key;
    map<Integer, Integer> deviceSecretValues;
    DL_GroupParameters_EC<ECP> params;
    Partial_Priv_Key_Msg *Part_Pr_Msg;
    int receivedID;
protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
public:
    void constructPartialPrivateKey(const int& deviceId, const ECP::Point& Od);
    ECP::Point multiplyScalar(const Integer &k, const ECP::Point &P, const DL_GroupParameters_EC<ECP> &param);
    string PointToString(const ECP::Point& point);
    Integer hash1(string& input);
    Integer hash2(string& input);
    void Setup();
};

Define_Module(KGC);

void KGC::initialize() {
    //Setup() is function used to generate KGC public and private key
    Setup();
}

void KGC::handleMessage(cMessage *msg) {
      //Here the KGC receives the partial private key request message
      Partial_Priv_Key_reqMsg *ReqMsg = check_and_cast<Partial_Priv_Key_reqMsg *>(msg);
      //Then the KGC extract the OD and id of vehicle from the partial private key msg request
      receivedID = ReqMsg->getID();
      ECP::Point receivedOd = ReqMsg->getOd();
      //The KGC calls function constructPartialPrivateKey and give it the extracted values above
      constructPartialPrivateKey(receivedID, receivedOd);
}

//Setup is used to generate KGC public and private key
void KGC::Setup(){
    params = ASN1::secp256r1();
    EV<<"KGC SETUP PHASE:"<<endl;
    EV<<"1-KGC starts by generating the Elliptic curve"<<endl;


            // Generate eta in the range [0, p]
            AutoSeededRandomPool prng;
            //generate private key which is random value its range is from (0 to subgroup order-1) subgroup order is the number of points generated from repeatedly adding Generator point to itself
            Integer eta(prng, Integer::Zero(), params.GetSubgroupOrder() - 1);
            // Compute public key which is gamma = eta * generator point D
            ECP::Point gamma = multiplyScalar(eta,params.GetSubgroupGenerator(),params);

             private_key=eta;
             public_key=gamma;

}

void KGC::constructPartialPrivateKey(const int& deviceId, const ECP::Point& Od) {
   //The following equations are used to generate the partial private key for the vehicle using the received ID and Od
    AutoSeededRandomPool prng;
    Integer delta_d(prng, Integer::Zero(), params.GetCurve().GetField().GetModulus() - 1);



    ECP::Point zeta_d = multiplyScalar(delta_d,params.GetSubgroupGenerator(),params);


    string IDd_Od_zeta_d = to_string(deviceId) + PointToString(Od) + PointToString(zeta_d);
    Integer mu_d = hash1(IDd_Od_zeta_d);


    Integer eta= private_key;
    Integer delta_d_plus_mu_d_eta = delta_d + mu_d * eta;


    string IDd_eta_Od = to_string(deviceId) +  PointToString(multiplyScalar(eta,Od,params));
    Integer beta_d = delta_d_plus_mu_d_eta + hash2(IDd_eta_Od);

    //This part is responsible for creating instance of Partial_Priv_Key_Msg and set it with some values computed above and then send it to vehicle
    Part_Pr_Msg=new Partial_Priv_Key_Msg ();
    Part_Pr_Msg->setZeta_d(zeta_d);
    Part_Pr_Msg->setBeta_d(beta_d);
    Part_Pr_Msg->setgamma(public_key);
    Part_Pr_Msg->setDestId(receivedID);
    send(Part_Pr_Msg,"OutKGC",0);

}

Integer KGC::hash1(string& input){

        SHA256 hash;
        std::string hashDigest;

        StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(hashDigest))));

        Integer result(hashDigest.c_str());

        return result;
}
Integer KGC::hash2(string& input){

    // Create a SHA-3 hash object with a specific digest size (e.g., 256 bits)
        SHA3_256 hash;

        // Calculate the hash of the input
        byte digest[SHA3_256::DIGESTSIZE];
        hash.Update(reinterpret_cast<const byte*>(input.data()), input.size());
        hash.Final(digest);

        // Convert the digest to an Integer
        Integer hashResult;
        hashResult.Decode(digest, SHA3_256::DIGESTSIZE);

        return hashResult;

}
ECP::Point KGC::multiplyScalar(const Integer &k, const ECP::Point &P, const DL_GroupParameters_EC<ECP> &param)
{

    ECP ec = param.GetCurve();  // Get the curve from Params
    ECP::Point result= ec.ScalarMultiply(P, k);

    return result;

}
string KGC:: PointToString(const ECP::Point& point)
{
        string encodedX, encodedY;
        HexEncoder xEncoder(new StringSink(encodedX));
        HexEncoder yEncoder(new StringSink(encodedY));

        point.x.Encode(xEncoder, point.x.MinEncodedSize());
        point.y.Encode(yEncoder, point.y.MinEncodedSize());

        // Concatenate the encoded X and Y coordinates
        string encoded = encodedX + encodedY;

        return encoded;
}
