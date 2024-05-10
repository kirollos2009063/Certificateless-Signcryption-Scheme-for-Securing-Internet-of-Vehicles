// RSU.cc

#include <omnetpp.h>
#include <Crypto++/sha.h>
#include <Crypto++/sha3.h>
#include <Crypto++/eccrypto.h>
#include <Crypto++/oids.h>
#include <Crypto++/hex.h>
#include <Crypto++/osrng.h>
#include <string>
#include "Partial_Priv_Key_reqMsg.h"
#include "Encrypted_Msg.h"
#include "Partial_Priv_Key_Msg.h"
#include "Public_Key_msg.h"
#include "Confirmation_Msg.h"
#include"Public_Key_Req_msg.h"
#include "Requested_Public_Key_Msg.h"
#include<TAPublicKey.h>
#include<Attacker.h>

using namespace omnetpp;
using namespace CryptoPP;
using namespace std;

#define V 9
class RSU : public cSimpleModule {
private:

   int graph[V][V];
   int VehicleLocationInRsu[9][3];
   map<int,string>RSU;
   map<int,int>DosCheckKGC;
   map<int,int>DosCheckTA;
   map<int,int>DosCheckVehicle;
   int DestinationVehicleID;
   int AttackNum;
   int count=0; //to make sure that attack number 5 is processed 1 time;
protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;

    void handlePartialPrivKeyRequest(Partial_Priv_Key_reqMsg *msg);
    void handleEncryptedMessage(Encrypted_Msgr *msg);
    void handlePartialPrivKeyResponse(Partial_Priv_Key_Msg *msg);
    void handlePublic_Key_msg(Public_Key_msg *msg);
    void handleConfirmationMsg(Confirmation_Msg *msg);
    void handlePublicKeyReqMsg(Public_Key_Req_Msg *msg);
    void handleRequestedMsg(Requested_Public_Key_Msg *msg);
    int minDistance(int dist[], bool sptSet[]);
    void printPath(int path[], int path_len);
    void printSolution(int dist[], int n, int parent[], int src, int dest);
    void dijkstra(int graph[V][V], int src, int dest, int*& shortest_path, int& path_length);
    void handleTAPublicKeyMsg(TA_PublicKey *msg);
};


Define_Module(RSU);

void RSU::initialize() {
       RSU[0]="rsu1";
       RSU[1]="rsu2";
       RSU[2]="rsu3";
       RSU[3]="rsu4";
       RSU[4]="rsu5";
       RSU[5]="rsu6";
       RSU[6]="rsu7";
       RSU[7]="rsu8";
       RSU[8]="rsu9";


           graph[0][0] = 0;
           graph[0][1] = 1;
           graph[0][2] = 1;
           graph[0][3] = 0;
           graph[0][4] = 0;
           graph[0][5] = 0;
           graph[0][6] = 0;
           graph[0][7] = 0;
           graph[0][8] = 0;

           graph[1][0] = 1;
           graph[1][1] = 0;
           graph[1][2] = 0;
           graph[1][3] = 1;
           graph[1][4] = 0;
           graph[1][5] = 0;
           graph[1][6] = 0;
           graph[1][7] = 0;
           graph[1][8] = 0;

           graph[2][0] = 1;
           graph[2][1] = 0;
           graph[2][2] = 0;
           graph[2][3] = 0;
           graph[2][4] = 1;
           graph[2][5] = 0;
           graph[2][6] = 0;
           graph[2][7] = 0;
           graph[2][8] = 0;

           graph[3][0] = 0;
           graph[3][1] = 1;
           graph[3][2] = 0;
           graph[3][3] = 0;
           graph[3][4] = 0;
           graph[3][5] = 1;
           graph[3][6] = 0;
           graph[3][7] = 0;
           graph[3][8] = 0;

           graph[4][0] = 0;
           graph[4][1] = 0;
           graph[4][2] = 1;
           graph[4][3] = 0;
           graph[4][4] = 0;
           graph[4][5] = 0;
           graph[4][6] = 1;
           graph[4][7] = 0;
           graph[4][8] = 0;

           graph[5][0] = 0;
           graph[5][1] = 0;
           graph[5][2] = 0;
           graph[5][3] = 1;
           graph[5][4] = 0;
           graph[5][5] = 0;
           graph[5][6] = 0;
           graph[5][7] = 1;
           graph[5][8] = 0;

           graph[6][0] = 0;
           graph[6][1] = 0;
           graph[6][2] = 0;
           graph[6][3] = 0;
           graph[6][4] = 1;
           graph[6][5] = 0;
           graph[6][6] = 0;
           graph[6][7] = 0;
           graph[6][8] = 1;

           graph[7][0] = 0;
           graph[7][1] = 0;
           graph[7][2] = 0;
           graph[7][3] = 0;
           graph[7][4] = 0;
           graph[7][5] = 1;
           graph[7][6] = 0;
           graph[7][7] = 0;
           graph[7][8] = 1;

           graph[8][0] = 0;
           graph[8][1] = 0;
           graph[8][2] = 0;
           graph[8][3] = 0;
           graph[8][4] = 0;
           graph[8][5] = 0;
           graph[8][6] = 1;
           graph[8][7] = 1;
           graph[8][8] = 0;


               VehicleLocationInRsu[0][0] = 2;
               VehicleLocationInRsu[0][1] = 3;
               VehicleLocationInRsu[0][2] = 4;

               VehicleLocationInRsu[1][0] = 5;
               VehicleLocationInRsu[1][1] = 6;
               VehicleLocationInRsu[1][2] = 7;

               VehicleLocationInRsu[2][0] = 8;
               VehicleLocationInRsu[2][1] = 9;
               VehicleLocationInRsu[2][2] = 10;

               VehicleLocationInRsu[3][0] = 11;
               VehicleLocationInRsu[3][1] = 12;
               VehicleLocationInRsu[3][2] = 13;

               VehicleLocationInRsu[4][0] = 14;
               VehicleLocationInRsu[4][1] = 15;
               VehicleLocationInRsu[4][2] = 16;

               VehicleLocationInRsu[5][0] = 17;
               VehicleLocationInRsu[5][1] = 18;
               VehicleLocationInRsu[5][2] = 19;

               VehicleLocationInRsu[6][0] = 20;
               VehicleLocationInRsu[6][1] = 21;
               VehicleLocationInRsu[6][2] = 22;

               VehicleLocationInRsu[7][0] = 23;
               VehicleLocationInRsu[7][1] = 24;
               VehicleLocationInRsu[7][2] = 25;

               VehicleLocationInRsu[8][0] = 26;
               VehicleLocationInRsu[8][1] = 27;
               VehicleLocationInRsu[8][2] = 28;

               DestinationVehicleID = getParentModule()->getSubmodule("vehicle1")->par("dest");

               Attacker attackerModule; // Create an object of the Attacker class
               AttackNum = attackerModule.attackNum;

}

void RSU::handleMessage(cMessage *msg) {

        // Handle incoming messages
        if (Partial_Priv_Key_reqMsg *partial_priv_key_reqMsg = dynamic_cast<Partial_Priv_Key_reqMsg *>(msg)) {
            handlePartialPrivKeyRequest(partial_priv_key_reqMsg);
        }
        else if (Encrypted_Msgr *encmsg = dynamic_cast<Encrypted_Msgr *>(msg)) {
            handleEncryptedMessage(encmsg);
        }
        else if (Partial_Priv_Key_Msg *privPub = dynamic_cast<Partial_Priv_Key_Msg *>(msg)) {
            handlePartialPrivKeyResponse(privPub);
        }
        else if (Public_Key_msg *publickey = dynamic_cast<Public_Key_msg *>(msg)) {
            handlePublic_Key_msg(publickey);
        }
        else if (Confirmation_Msg *confirmation = dynamic_cast<Confirmation_Msg *>(msg)) {
                   handleConfirmationMsg(confirmation);
               }
        else if (TA_PublicKey *ta_publickey = dynamic_cast<TA_PublicKey *>(msg)) {
                   handleTAPublicKeyMsg(ta_publickey);
               }
        else if (Public_Key_Req_Msg *public_key_req_msg = dynamic_cast<Public_Key_Req_Msg *>(msg)) {
                          handlePublicKeyReqMsg(public_key_req_msg);
               }
        else if (Requested_Public_Key_Msg *requested_public_key = dynamic_cast<Requested_Public_Key_Msg *>(msg)) {
                                 handleRequestedMsg(requested_public_key);
               }

        else {
            EV_WARN << "Unknown message type received\n";
            delete msg;
        }

}

void RSU::handlePartialPrivKeyRequest(Partial_Priv_Key_reqMsg *msg) {
    //Defining some Variables
    int numGates = par("numGates").intValue();//Gets number of gates of each RSU
    cModule *senderModule = msg->getSenderModule(); //Gets pointer to the previous module that sent the message
    const char *RSUName = getName();//Retrieve the current RSU name

    //checking whether sender module is null or not
    if (!senderModule) {
        EV_WARN << "Sender module not found." << endl;
        delete msg; // If sender module not found, delete the message and return
        return;
    }

    //checking whether sender module is vehicle or attacker and not RSU
    //This part is used to count the number of sent messages from one module and make sure that they dont exceed the limit of sending Partial_Priv_Key_reqMsg
    //It is added into a map<int(id),int(counter for msgs)> and if id is associated with counter >=1 then delete the msg because it will exceed the limit
    if(senderModule->hasPar("isCar") || senderModule->hasPar("isAttacker")){
            if(DosCheckKGC[senderModule->getId()] >=1){
                delete msg;
                return;
            }
            else{
                DosCheckKGC[senderModule->getId()]++;
            }

        }

     //Checks that this RSU is not the destination rsu which is rsu3 because rsu3 is connected directly to the KGC
    if (strcmp(RSUName, "rsu3") != 0) {
        //Here we begin by setting the SRC (RSU) and DEST(RSU) but DEST(RSU) is =2 which is rsu3 that is connected to the KGC
        //src=getId-29 because the first rsu (rsu1) has ID 29
        int src = getId() - 29, dest = 2;
        int* shortest_path;
        int path_length;
        //call dijkestra algorithm to compute shortest path from src rsu to dest rsu
        dijkstra(graph, src, dest, shortest_path, path_length);



        // Check if the gates exist before processing
        if (numGates <= 0) {
            EV_WARN << "No gates found." << endl;
            delete[] shortest_path; // Cleanup allocated memory
            return;
        }
        // Initialize j and it is used to iterate through the shortest_path array returned by the dijkestra algorithm it starts from 1
        //because 0 is the index of the RSU we are in right now
        int j = 1;

        //Iterate through all gates of the current RSU
        for (int gateIndex = 0; gateIndex < numGates; gateIndex++) {
            cGate *inGate = gate("InPut", gateIndex); //the inGate contains pointer to the gate with the index of gateIndex
            if (!inGate) {
                EV_WARN << "Gate " << gateIndex << " not found." << endl;
                continue; // Skip to next iteration if gate not found
            }

            //See connected module to this gate
            cModule *connectedModule = inGate->getPathStartGate()->getOwnerModule();//so this return pointer to the module that is connected to the rsu through this gate
            //Checking that connectedModule is not null pointer
            if (!connectedModule) {
                EV_WARN << "Connected module not found for gate " << gateIndex << endl;
                continue; // Skip to next iteration if module not found
            }

            //Get the name of the RSU connected to this gate
            const char *connectedRSUName = connectedModule->getName();

            if (j < path_length) {
             //Check the name of the RSU connected to this gate is equal to the intended RSU as specified by the Dijkestra algorithm's shortest_path array
                if (strcmp(connectedRSUName, RSU[shortest_path[j]].c_str()) == 0) {
                    cout << "Sending message to gate " << gateIndex << endl;
                    send(msg, "OutPut", gateIndex);//send the msg through the gate with index =gateIndex
                    j++; //increment j to iterate to the next value in the shortes_path array to see which RSU is the next
                }
                //if not go through the loop again to see another gate
            }

            //if j is equal to path_length then j has exceeded the shortest_path array so break;
            else {
                break;
            }
        }

        delete[] shortest_path;
    }
    //if current RSU is rsu3 so this is the dest rsu so send the message directly to gate number 5
    else {
        send(msg, "OutPut", 5);
    }
}




void RSU::handleEncryptedMessage(Encrypted_Msgr *msg) {
    const char *RSUName = getName();//Retrieve the name of the current RSU
    bool DestinationFound = false;
    int src=getId()-29,dest;
    int numGates = par("numGates").intValue();//Gets number of gates of each RSU
    cModule *senderModule = msg->getSenderModule();//Gets pointer to the previous module that sent the message
    //checking whether sender module is null or not
    if (!senderModule) {
        EV_WARN << "Sender module not found." << endl;
        delete msg; // If sender module not found, delete the message and return
        return;
    }

    //checking whether sender module is vehicle or attacker and not RSU
    //This part is used to count the number of sent messages from one module and make sure that they dont exceed the limit of sending Encrypted msg to counter DOS attack
    //It is added into a map<int(id),int(counter for msgs)> and if id is associated with counter >=limit we choose then delete the msg because it will exceed the limit
    if(senderModule->hasPar("isCar") || senderModule->hasPar("isAttacker")){
            if(DosCheckVehicle[senderModule->getId()] >= 3){
                delete msg;
                return;
            }
            else{
                DosCheckVehicle[senderModule->getId()]++;
            }

        }

    //here we start by finding the destination RSU where the destination vehicle is found to receive the encrypted msg
    for (int i = 0; i < 9; i++){ //RSU numbers
            for (int j = 0; j < 3; j++){ //vehicle numbers for each RSU{
                //We iterate through VehicleLocationInRsu 2D array to see where the id will be equal to DestinationVehicleID
                if (VehicleLocationInRsu[i][j] == DestinationVehicleID) {
                    DestinationFound = true;
                    dest = i; //set dest to i which is the RSU that we found the destination vehicle connected to it
                    break;
                }
            }
            if (DestinationFound) {
                break;
            }
    }
        //Checks that this RSU is not the destination RSU that contains the destination vehicle
    if (strcmp(RSUName, RSU[dest].c_str()) != 0) {
           int* shortest_path;
           int path_length;
           dijkstra(graph, src, dest, shortest_path, path_length); //call dijkestra algorithm to compute shortest path from src rsu to dest rsu

           // Check if the gates exist before processing
           if (numGates <= 0) {
               EV_WARN << "No input gates found." << endl;
               delete[] shortest_path; // Cleanup allocated memory
               return;
           }


           // Initialize j and it is used to iterate through the shortest_path array returned by the dijkestra algorithm it starts from 1
           //because 0 is the index of the RSU we are in right now
           int j = 1;
           //Iterate through all gates of the current RSU
           for (int i = 0; i < numGates; i++) {
               cGate *inGate = gate("InPut", i);
               if (!inGate) {
                   EV_WARN << "Input gate " << i << " not found." << endl;
                   continue; // Skip to next iteration if gate not found
               }
               //See connected module to this gate
               cModule *connectedModule = inGate->getPathStartGate()->getOwnerModule();

               //Checking that connectedModule is not null pointer
               if (!connectedModule) {
                   EV_WARN << "Connected module not found for gate " << i << endl;
                   continue; // Skip to next iteration if module not found
               }
               //Get the name of the RSU connected to this gate
               const char *connectedRSUName = connectedModule->getName();

               if (j < path_length) {
                   if (strcmp(connectedRSUName, RSU[shortest_path[j]].c_str()) == 0) {
                       cout << "Sending message to gate " << i << endl;
                       send(msg, "OutPut", i);
                       j++;
                   }
               } else {
                   break;
               }
           }

           delete[] shortest_path;
       }

    // Destination is the same RSU that contains the intended vehicle
    else {
        //Iterate through all gates of the current RSU
           for (int i = 0; i < numGates; i++) {
               cGate *inGate = gate("InPut", i);//the inGate contains pointer to the gate with the index i
               if (!inGate) {
                   EV_WARN << "Input gate " << i << " not found." << endl;
                   continue; // Skip to next iteration if gate not found
               }
               //See connected module to this gate
               cModule *connectedModule = inGate->getPreviousGate()->getOwnerModule();//connectedModule contains pointer to the module connected to this gate
               if (!connectedModule) {
                   EV_WARN << "Connected module not found for gate " << i << endl;
                   continue; // Skip to next iteration if module not found
               }
               //return the connectedModule ID
               // Check if the connected module is the same as the DestinationVehicleID
               int ConnectedVehicleID = connectedModule->getId();
               if (ConnectedVehicleID == DestinationVehicleID) {
                   cout << "Found destination vehicle connected to gate " << i << endl; // Debugging output
                   send(msg, "OutPut", i);//send msg to gate with index i
                   cout << "Message sent to gate " << i << endl; // Debugging output
                   break; // Exit loop once message is sent
               }
           }
       }


}



void RSU::handlePartialPrivKeyResponse(Partial_Priv_Key_Msg *msg) {
    const char *RSUName = getName();
    int DestVehicleId = msg->getDestId();
    bool DestinationFound = false;
    int src = getId()-29, dest;
    int numGates = par("numGates").intValue();

    if(DestVehicleId != 40){
    // Determine the destination RSU based on the destination vehicle ID
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 3; j++) {
            if (VehicleLocationInRsu[i][j] == DestVehicleId) {
                DestinationFound = true;
                dest = i;
                break;
            }
        }
        if (DestinationFound) {
            break;
        }
    }
   }else{
       dest=0;
   }


    // Check if the destination is not the same RSU
    if (strcmp(RSUName, RSU[dest].c_str()) != 0) {
        int* shortest_path;
        int path_length;
        dijkstra(graph, src, dest, shortest_path, path_length);

        // Check if the gates exist before processing
        if (numGates <= 0) {
            EV_WARN << "No input gates found." << endl;
            delete[] shortest_path; // Cleanup allocated memory
            return;
        }

        // Traverse the shortest path to find the correct output gate
        int j = 1; // Initialize j here for clarity
        for (int i = 0; i < numGates; i++) {
            cGate *inGate = gate("InPut", i);
            if (!inGate) {
                EV_WARN << "Input gate " << i << " not found." << endl;
                continue; // Skip to next iteration if gate not found
            }

            cModule *connectedModule = inGate->getPathStartGate()->getOwnerModule();
            if (!connectedModule) {
                EV_WARN << "Connected module not found for gate " << i << endl;
                continue; // Skip to next iteration if module not found
            }

            const char *connectedRSUName = connectedModule->getName();

            if (j < path_length) {
                if (strcmp(connectedRSUName, RSU[shortest_path[j]].c_str()) == 0) {
                    cout << "Sending message to gate " << i << endl;
                    send(msg, "OutPut", i);
                    j++;
                }
            } else {
                break;
            }
        }

        delete[] shortest_path;
    } else {
        // Destination is the same as the RSU, handle accordingly
        for (int i = 0; i < numGates;i++) {
            cGate *inGate = gate("InPut", i);
            if (!inGate) {
                EV_WARN << "Input gate " << i << " not found." << endl;
                continue; // Skip to next iteration if gate not found
            }

            cModule *connectedModule = inGate->getPreviousGate()->getOwnerModule();
            if (!connectedModule) {
                EV_WARN << "Connected module not found for gate " << i << endl;
                continue; // Skip to next iteration if module not found
            }

            // Check if the connected module has the specific ID
            int ConnectedVehicleID = connectedModule->getId();
            if (ConnectedVehicleID == DestVehicleId) {
                cout << "Found destination vehicle connected to gate " << i << endl; // Debugging output
                send(msg, "OutPut", i);
                cout << "Message sent to gate " << i << endl; // Debugging output
                break; // Exit loop once message is sent
            }
        }
    }
}



void RSU::handlePublic_Key_msg(Public_Key_msg *msg){
      const char *RSUName = getName();
      int src=getId()-29 ,dest=1;

      int numGates = par("numGates").intValue();
      if (strcmp(RSUName, RSU[1].c_str()) != 0){
          int* shortest_path;
          int path_length;
          dijkstra(graph, src, dest, shortest_path, path_length);

          if (numGates <= 0) {
                      EV_WARN << "No input gates found." << endl;
                      delete[] shortest_path; // Cleanup allocated memory
                      return;
                  }

                  // Traverse the shortest path to find the correct output gate
                  int j = 1; // Initialize j here for clarity
                  for (int i = 0; i < numGates; i++) {
                      cGate *inGate = gate("InPut", i);
                      if (!inGate) {
                          EV_WARN << "Input gate " << i << " not found." << endl;
                          continue; // Skip to next iteration if gate not found
                      }

                      cModule *connectedModule = inGate->getPathStartGate()->getOwnerModule();
                      if (!connectedModule) {
                          EV_WARN << "Connected module not found for gate " << i << endl;
                          continue; // Skip to next iteration if module not found
                      }

                      const char *connectedRSUName = connectedModule->getName();

                      if (j < path_length) {
                          if (strcmp(connectedRSUName, RSU[shortest_path[j]].c_str()) == 0) {
                              cout << "Sending message to gate " << i << endl;
                              send(msg, "OutPut", i);
                              j++;
                          }
                      } else {
                          break;
                      }
                  }

                  delete[] shortest_path;
              }


      else {
              send(msg,"OutPut",5);
          }


}
void RSU::handleConfirmationMsg(Confirmation_Msg *msg){
    const char *RSUName = getName();
    int DestVehicleId = msg->getVehicleID();
    bool DestinationFound = false;
    int src = getId()-29, dest;
    int numGates = par("numGates").intValue();

       // Determine the destination RSU based on the destination vehicle ID
       for (int i = 0; i < 9; i++) {
           for (int j = 0; j < 3; j++) {
               if (VehicleLocationInRsu[i][j] == DestVehicleId) {
                   DestinationFound = true;
                   dest = i;
                   break;
               }
           }
           if (DestinationFound) {
               break;
           }
       }

       if (strcmp(RSUName, RSU[dest].c_str()) != 0) {
              int* shortest_path;
              int path_length;
              dijkstra(graph, src, dest, shortest_path, path_length);

              cout << "Shortest Path Length: " << path_length << endl;

              // Check if the gates exist before processing
              if (numGates <= 0) {
                  EV_WARN << "No input gates found." << endl;
                  delete[] shortest_path; // Cleanup allocated memory
                  return;
              }

              // Traverse the shortest path to find the correct output gate
              int j = 1; // Initialize j here for clarity
              for (int i = 0; i < numGates; i++) {
                  cGate *inGate = gate("InPut", i);
                  if (!inGate) {
                      EV_WARN << "Input gate " << i << " not found." << endl;
                      continue; // Skip to next iteration if gate not found
                  }

                  cModule *connectedModule = inGate->getPathStartGate()->getOwnerModule();
                  if (!connectedModule) {
                      EV_WARN << "Connected module not found for gate " << i << endl;
                      continue; // Skip to next iteration if module not found
                  }

                  const char *connectedRSUName = connectedModule->getName();

                  if (j < path_length) {
                      if (strcmp(connectedRSUName, RSU[shortest_path[j]].c_str()) == 0) {
                          cout << "Sending message to gate V5" << i << endl;
                          send(msg, "OutPut", i);
                          j++;
                      }
                  } else {
                      break;
                  }
              }

              delete[] shortest_path;
          }else {
              // Destination is the same as the RSU, handle accordingly
              for (int i = 0; i < numGates; i++) {
                  cGate *inGate = gate("InPut", i);
                  if (!inGate) {
                      EV_WARN << "Input gate " << i << " not found." << endl;
                      continue; // Skip to next iteration if gate not found
                  }

                  cModule *connectedModule = inGate->getPreviousGate()->getOwnerModule();
                  if (!connectedModule) {
                      EV_WARN << "Connected module not found for gate " << i << endl;
                      continue; // Skip to next iteration if module not found
                  }

                  // Check if the connected module has the specific ID
                  int ConnectedVehicleID = connectedModule->getId();
                  if (ConnectedVehicleID == DestVehicleId) {
                      cout << "Found destination vehicle connected to gate " << i << endl; // Debugging output
                      send(msg, "OutPut", i);
                      cout << "Message sent to gate " << i << endl; // Debugging output
                      break; // Exit loop once message is sent
                  }
              }
          }

 }



void RSU::handleTAPublicKeyMsg(TA_PublicKey *msg){

    const char *RSUName = getName();
    int DestVehicleId = msg->getVehicleID();
    bool DestinationFound = false;
    int src = getId()-29, dest;
    int numGates = par("numGates").intValue();

       // Determine the destination RSU based on the destination vehicle ID
       for (int i = 0; i < 9; i++) {
           for (int j = 0; j < 3; j++) {
               if (VehicleLocationInRsu[i][j] == DestVehicleId) {
                   DestinationFound = true;
                   dest = i;
                   break;
               }
           }
           if (DestinationFound) {
               break;
           }
       }

       if (strcmp(RSUName, RSU[dest].c_str()) != 0) {
              int* shortest_path;
              int path_length;
              dijkstra(graph, src, dest, shortest_path, path_length);

              // Check if the gates exist before processing
              if (numGates <= 0) {
                  EV_WARN << "No input gates found." << endl;
                  delete[] shortest_path; // Cleanup allocated memory
                  return;
              }

              // Traverse the shortest path to find the correct output gate
              int j = 1; // Initialize j here for clarity
              for (int i = 0; i < numGates; i++) {
                  cGate *inGate = gate("InPut", i);
                  if (!inGate) {
                      EV_WARN << "Input gate " << i << " not found." << endl;
                      continue; // Skip to next iteration if gate not found
                  }

                  cModule *connectedModule = inGate->getPathStartGate()->getOwnerModule();
                  if (!connectedModule) {
                      EV_WARN << "Connected module not found for gate " << i << endl;
                      continue; // Skip to next iteration if module not found
                  }

                  const char *connectedRSUName = connectedModule->getName();
                  if (j < path_length) {
                      if (strcmp(connectedRSUName, RSU[shortest_path[j]].c_str()) == 0) {
                          cout << "Sending message to gate " << i << endl;
                          send(msg, "OutPut", i);
                          j++;
                      }
                  } else {
                      break;
                  }
              }

              delete[] shortest_path;
          }else {
              // Destination is the same as the RSU, handle accordingly
              for (int i = 0; i < numGates; i++) {
                  cGate *inGate = gate("InPut", i);
                  if (!inGate) {
                      EV_WARN << "Input gate " << i << " not found." << endl;
                      continue; // Skip to next iteration if gate not found
                  }

                  cModule *connectedModule = inGate->getPreviousGate()->getOwnerModule();
                  if (!connectedModule) {
                      EV_WARN << "Connected module not found for gate " << i << endl;
                      continue; // Skip to next iteration if module not found
                  }

                  // Check if the connected module has the specific ID
                  int ConnectedVehicleID = connectedModule->getId();
                  if (ConnectedVehicleID == DestVehicleId) {
                      cout << "Found destination vehicle connected to gate " << i << endl; // Debugging output
                      send(msg, "OutPut", i);
                      cout << "Message sent to gate " << i << endl; // Debugging output
                      break; // Exit loop once message is sent
                  }
              }
          }

 }












void RSU::handlePublicKeyReqMsg(Public_Key_Req_Msg *msg){
    const char *RSUName = getName();
    int src = getId()-29, dest=1;
    cModule *senderModule = msg->getSenderModule();
    int numGates = par("numGates").intValue();


    if (!senderModule) {
        EV_WARN << "Sender module not found." << endl;
        delete msg; // If sender module not found, delete the message and return
        return;
    }

    if(senderModule->hasPar("isCar") || senderModule->hasPar("isAttacker")){
            if(DosCheckTA[senderModule->getId()] >= 15){
                delete msg;
                return;
            }
            else{
                DosCheckTA[senderModule->getId()]++;
            }

        }


          if (strcmp(RSUName, RSU[dest].c_str()) != 0) {
                 int* shortest_path;
                 int path_length;
                 dijkstra(graph, src, dest, shortest_path, path_length);

                 // Check if the gates exist before processing
                 if (numGates <= 0) {
                     EV_WARN << "No input gates found." << endl;
                     delete[] shortest_path; // Cleanup allocated memory
                     return;
                 }

                 // Traverse the shortest path to find the correct output gate
                 int j = 1; // Initialize j here for clarity
                 for (int i = 0; i < numGates; ++i) {
                     cGate *inGate = gate("InPut", i);
                     if (!inGate) {
                         EV_WARN << "Input gate " << i << " not found." << endl;
                         continue; // Skip to next iteration if gate not found
                     }

                     cModule *connectedModule = inGate->getPathStartGate()->getOwnerModule();
                     if (!connectedModule) {
                         EV_WARN << "Connected module not found for gate " << i << endl;
                         continue; // Skip to next iteration if module not found
                     }

                     const char *connectedRSUName = connectedModule->getName();

                     if (j < path_length) {
                         if (strcmp(connectedRSUName, RSU[shortest_path[j]].c_str()) == 0) {
                             cout << "Sending message to gate " << i << endl;
                             send(msg, "OutPut", i);
                             j++;
                         }
                     } else {
                         break;
                     }
                 }

                 delete[] shortest_path;
             }else {
                 send(msg,"OutPut",5);
             }



 }

void RSU::handleRequestedMsg(Requested_Public_Key_Msg *msg){
    const char *RSUName = getName();
    int DestVehicleId = msg->getDestinationVehicleId();
    bool DestinationFound = false;
    int src = getId()-29, dest;
    int numGates = par("numGates").intValue();

    if(AttackNum ==5 && (strcmp(RSUName,"rsu1") == 0) && DestVehicleId==2 && count == 0){
          send(msg,"OutPut",5);
          count++;
    }else{
        if(DestVehicleId != 40){
          // Determine the destination RSU based on the destination vehicle ID
          for (int i = 0; i < 9; i++) {
              for (int j = 0; j < 3; j++) {
                  if (VehicleLocationInRsu[i][j] == DestVehicleId) {
                      DestinationFound = true;
                      dest = i;
                      break;
                  }
              }
              if (DestinationFound) {
                  break;
              }
          }
      }else{
        dest=0;
      }

          if (strcmp(RSUName, RSU[dest].c_str()) != 0) {
                 int* shortest_path;
                 int path_length;
                 dijkstra(graph, src, dest, shortest_path, path_length);

                 // Check if the gates exist before processing
                 if (numGates <= 0) {
                     EV_WARN << "No input gates found." << endl;
                     delete[] shortest_path; // Cleanup allocated memory
                     return;
                 }

                 // Traverse the shortest path to find the correct output gate
                 int j = 1; // Initialize j here for clarity
                 for (int i = 0; i < numGates; i++) {
                     cGate *inGate = gate("InPut", i);
                     if (!inGate) {
                         EV_WARN << "Input gate " << i << " not found." << endl;
                         continue; // Skip to next iteration if gate not found
                     }

                     cModule *connectedModule = inGate->getPathStartGate()->getOwnerModule();
                     if (!connectedModule) {
                         EV_WARN << "Connected module not found for gate " << i << endl;
                         continue; // Skip to next iteration if module not found
                     }

                     const char *connectedRSUName = connectedModule->getName();

                     if (j < path_length) {

                         if (strcmp(connectedRSUName, RSU[shortest_path[j]].c_str()) == 0) {
                             cout << "Sending message to gate " << i << endl;
                             send(msg, "OutPut", i);
                             j++;
                         }
                     } else {
                         break;
                     }
                 }

                 delete[] shortest_path;
             }else {
                 // Destination is the same as the RSU, handle accordingly
                 for (int i = 0; i < numGates;i++) {
                     cGate *inGate = gate("InPut", i);
                     if (!inGate) {
                         EV_WARN << "Input gate " << i << " not found." << endl;
                         continue; // Skip to next iteration if gate not found
                     }

                     cModule *connectedModule = inGate->getPreviousGate()->getOwnerModule();
                     if (!connectedModule) {
                         EV_WARN << "Connected module not found for gate " << i << endl;
                         continue; // Skip to next iteration if module not found
                     }

                     // Check if the connected module has the specific ID
                     int ConnectedVehicleID = connectedModule->getId();
                     if (ConnectedVehicleID == DestVehicleId) {
                         cout << "Found destination vehicle connected to gate " << i << endl; // Debugging output
                         send(msg, "OutPut", i);
                         cout << "Message sent to gate " << i << endl; // Debugging output
                         break; // Exit loop once message is sent
                     }
                 }
             }
    }

 }
int RSU::minDistance(int dist[], bool sptSet[]) {
    int min = INT_MAX, min_index;

    for (int v = 0; v < V; v++)
        if (sptSet[v] == false && dist[v] <= min)
            min = dist[v], min_index = v;

    return min_index;
}

void RSU::dijkstra(int graph[V][V], int src, int dest, int*& shortest_path, int& path_length) {
    int dist[V];
    bool sptSet[V];
    int parent[V];

    for (int i = 0; i < V; i++) {
        parent[i] = -1;
        dist[i] = INT_MAX;
        sptSet[i] = false;
    }


    dist[src] = 0;

    for (int count = 0; count < V - 1; count++) {
        int u = minDistance(dist, sptSet);
        sptSet[u] = true;

        for (int v = 0; v < V; v++) {
            if (!sptSet[v] && graph[u][v] && dist[u] != INT_MAX && dist[u] + graph[u][v] < dist[v]) {
                parent[v] = u;
                dist[v] = dist[u] + graph[u][v];
            }
        }
    }

    // Build the path array and its length
    shortest_path = new int[V];
    path_length = 0;
    int current = dest;
    while (current != -1) {
        shortest_path[path_length++] = current;
        current = parent[current];
    }

    // Reverse the order of nodes in the path array (from destination to source)
    for (int i = 0; i < path_length / 2; i++) {
        swap(shortest_path[i], shortest_path[path_length - i - 1]);
    }
}

