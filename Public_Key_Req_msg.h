/*
 * Public_Key_Req_msg.h
 *
 *  Created on: Feb 23, 2024
 *      Author: Lenovo
 */

#ifndef PUBLIC_KEY_REQ_MSG_H_
#define PUBLIC_KEY_REQ_MSG_H_


#include <omnetpp.h>
#include <Crypto++/eccrypto.h>

using namespace omnetpp;
using namespace CryptoPP;

class Public_Key_Req_Msg : public cMessage {
private:
    int ID;
    int SenderVehicleId;

public:
    Public_Key_Req_Msg (const char *name = nullptr, int kind = 0);
    ~Public_Key_Req_Msg ();

    void setID(const int& value) { ID = value; }
    int getID() const { return ID; }

    void setSenderVehicleId(const int& value) { SenderVehicleId = value; }
    int getSenderVehicleId() const { return SenderVehicleId; }

};


#endif /* PUBLIC_KEY_REQ_MSG_H_ */
