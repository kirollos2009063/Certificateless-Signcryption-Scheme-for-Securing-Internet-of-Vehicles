import inet.mobility.single.LinearMobility;
import inet.physicallayer.wireless.common.contract.packetlevel.IRadioMedium;
import ned.IdealChannel;


network MyNetwork
{
    parameters:
        @display("bgb=1195,565"); // Set the size of the overall network

    submodules:
        vehicle1: Vehicle {
            @display("p=81,520");
        }
        vehicle2: Vehicle {
            @display("p=254,520");
        }
        vehicle3: Vehicle {
            @display("p=472,520");
        }
        vehicle4: Vehicle {
            @display("p=737,510");
        }
        vehicle5: Vehicle {
            @display("p=907,520");
        }
        vehicle6: Vehicle {
            @display("p=1039,531");
        }

        rsu: RSU {

            @display("p=233,377;i=device/antennatower;is=l");
        }
        rsu1: RSU {
            @display("p=888,377;i=device/antennatower;is=l");
        }



        kgc: KGC {
            @display("p=93,112;i=device/server;is=vl");
        }
        server: Server {
            @display("p=924,93;is=vl;i=device/server2");
        }
    connections:
    vehicle1.Vout --> IdealChannel --> rsu.InPut[0];
    rsu.OutPut[0] --> IdealChannel --> vehicle1.Vin;

    vehicle2.Vout --> IdealChannel --> rsu.InPut[1];
    rsu.OutPut[1] --> IdealChannel --> vehicle2.Vin;

    vehicle3.Vout --> IdealChannel --> rsu.InPut[2];
    rsu.OutPut[2] --> IdealChannel --> vehicle3.Vin;

    vehicle4.Vout --> IdealChannel --> rsu1.InPut[0];
    rsu1.OutPut[0] --> IdealChannel --> vehicle4.Vin;

    vehicle5.Vout --> IdealChannel --> rsu1.InPut[1];
    rsu1.OutPut[1] --> IdealChannel --> vehicle5.Vin;

    vehicle6.Vout --> IdealChannel --> rsu1.InPut[2];
    rsu1.OutPut[2] --> IdealChannel --> vehicle6.Vin;

    // Connections between KGC and RSUs
    kgc.OutKGC++ --> rsu.InPut[3];
    kgc.InKGC++ <-- rsu.OutPut[3];

    kgc.OutKGC++ --> rsu1.InPut[3];
    kgc.InKGC++ <-- rsu1.OutPut[3];

    
    // Connections between RSUs and Server
    rsu.OutPut[4] --> server.ServIn[0];
    rsu.InPut[4] <-- server.ServOut[0];
    
    // Connections between RSUs
    rsu.OutPut[5] --> IdealChannel --> rsu1.InPut[4];
    rsu.InPut[5] <-- IdealChannel <-- rsu1.OutPut[4];

    rsu1.OutPut[5] --> server.ServIn[1];
    rsu1.InPut[5] <-- server.ServOut[1];

}
