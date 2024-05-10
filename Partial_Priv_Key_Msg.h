/*
 * Priv&Pub.h
 *
 *  Created on: Jan 11, 2024
 *      Author: Lenovo
 */

#ifndef PRIVANDPUB_H_
#define PRIVANDPUB_H_

#include <omnetpp.h>
#include <Crypto++/eccrypto.h>

using namespace omnetpp;
using namespace CryptoPP;

class Partial_Priv_Key_Msg : public cMessage {
private:
    ECP::Point zeta_d;
    Integer beta_d;
    ECP::Point gamma;
    int DestId;

public:
    Partial_Priv_Key_Msg(const char *name = nullptr, int kind = 0);
    ~Partial_Priv_Key_Msg();

    void setZeta_d(const ECP::Point& value) { zeta_d = value; }
    ECP::Point getZeta_d() const { return zeta_d; }

    void setBeta_d(const Integer& value) { beta_d = value; }
    Integer getBeta_d() const { return beta_d; }

    void setgamma(const ECP::Point& value) { gamma = value; }
    ECP::Point getgamma() const { return gamma; }

    void setDestId(const int& value) { DestId = value; }
    int getDestId() const { return DestId; }

};




#endif /* PRIVANDPUB_H_ */
