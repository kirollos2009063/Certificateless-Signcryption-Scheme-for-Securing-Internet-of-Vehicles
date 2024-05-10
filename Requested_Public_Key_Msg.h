

#ifndef REQUESTED_PUBLIC_KEY_MSG_H_
#define REQUESTED_PUBLIC_KEY_MSG_H_

#include <omnetpp.h>
#include <Crypto++/eccrypto.h>

using namespace omnetpp;
using namespace CryptoPP;
using namespace std;

class Requested_Public_Key_Msg : public cMessage {

private:
    std::pair<ECP::Point, ECP::Point> RequestedPublickey;
    int DestinationVehicleId;
    string DigitalSignature;

public:
    Requested_Public_Key_Msg(const char *name = nullptr, int kind = 0);
    ~Requested_Public_Key_Msg();  // Declare destructor

    void setRequestedPublickey(const std::pair<ECP::Point, ECP::Point>& value) { RequestedPublickey = value; }
    std::pair<ECP::Point, ECP::Point> getRequestedPublickey() const { return RequestedPublickey; }

    void setDestinationVehicleId(const int& value) { DestinationVehicleId = value; }
    int getDestinationVehicleId() const { return DestinationVehicleId; }

    void setDigitalSignature(const string& value) {  DigitalSignature= value; }
    string getDigitalSignature() const { return DigitalSignature; }
};




#endif /* REQUESTED_PUBLIC_KEY_MSG_H_ */
