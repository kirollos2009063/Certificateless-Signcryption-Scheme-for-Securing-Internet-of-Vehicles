/*
 * Public_Key_msg.h
 *
 *  Created on: Jan 16, 2024
 *      Author: Lenovo
 */

#ifndef Public_Key_msg_H_
#define Public_Key_msg_H_

#include <omnetpp.h>
#include <Crypto++/eccrypto.h>

using namespace omnetpp;
using namespace CryptoPP;

class Public_Key_msg : public cMessage {

private:
    std::pair<ECP::Point, ECP::Point> key;
    int ID;

public:
    Public_Key_msg(const char *name = nullptr, int kind = 0);
    ~Public_Key_msg();  // Declare destructor

    void setKey(const std::pair<ECP::Point, ECP::Point>& value) { key = value; }
    std::pair<ECP::Point, ECP::Point> getKey() const { return key; }

    void setID(const int& value) { ID = value; }
    int getID() const { return ID; }
};


#endif /* Public_Key_msg_H_ */
