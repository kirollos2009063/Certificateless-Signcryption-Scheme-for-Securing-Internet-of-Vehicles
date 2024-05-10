network Network
{
    parameters:
        @display("bgb=2369.0625,1282.5"); // Set the size of the overall network

    submodules:
        vehicle1: Vehicle {
            @display("p=665,1053.9062;i=block/process");
        }
        vehicle2: Vehicle {
            @display("p=914.394,738.03595;i=block/process");
        }
        vehicle3: Vehicle {
            @display("p=938.12494,1018.2812;i=block/process");
        }
        vehicle4: Vehicle {
            @display("p=1157.8125,1116.25;i=block/process");
        }
        vehicle5: Vehicle {
            @display("p=1392.3438,1095.4688;i=block/process");
        }
        vehicle6: Vehicle {
            @display("p=1487.3436,938.12494;i=block/process");
        }
        vehicle7: Vehicle {
            @display("p=181.09373,831.24994;i=block/process");
        }
        vehicle8: Vehicle {
            @display("p=340.86,941.06995;i=block/process");
        }
        vehicle9: Vehicle {
            @display("p=500.916,844.74;i=block/process");
        }
        vehicle10: Vehicle {
            @display("p=1787.1874,902.49994;i=block/process");
        }
        vehicle11: Vehicle {
            @display("p=1836.1979,652.07996;i=block/process");
        }
        vehicle12: Vehicle {
            @display("p=1530.9059,625.404;i=block/process");
        }
        vehicle13: Vehicle {
            @display("p=127.451996,625.404;i=block/process");
        }
        vehicle14: Vehicle {
            @display("p=157.092,397.176;i=block/process");
        }
        vehicle15: Vehicle {
            @display("p=456.456,438.672;i=block/process");
        }
        vehicle16: Vehicle {
            @display("p=2000.7,554.268;i=block/process");
        }
        vehicle17: Vehicle {
            @display("p=2178.54,481.65;i=block/process");
        }
        vehicle18: Vehicle {
            @display("p=2033.304,363.09;i=block/process");
        }
        vehicle19: Vehicle {
            @display("p=297.882,192.65999;i=block/process");
        }
        vehicle20: Vehicle {
            @display("p=443.11798,81.509995;i=block/process");
        }
        vehicle21: Vehicle {
            @display("p=666.89996,62.244;i=block/process");
        }
        vehicle22: Vehicle {
            @display("p=1719.12,250.458;i=block/process");
        }
        vehicle23: Vehicle {
            @display("p=1689.48,106.703995;i=block/process");
        }
        vehicle24: Vehicle {
            @display("p=1433.094,93.366;i=block/process");
        }
        vehicle25: Vehicle {
            @display("p=874.37994,287.508;i=block/process");
        }
        vehicle26: Vehicle {
            @display("p=1019.61597,363.09;i=block/process");
        }
        vehicle27: Vehicle {
            @display("p=1160.406,305.292;i=block/process");
        }



        rsu1: RSU {

            @display("p=775.086,831.402;i=device/antennatower;is=l");
            numGates = 6;
        }
        rsu2: RSU {
            @display("p=1304.1599,844.74;i=device/antennatower;is=l");
            numGates = 6;
        }

        rsu3: RSU {
            @display("p=410.51398,721.73395;i=device/antennatower;is=l");
            numGates = 6;
        }
        rsu4: RSU {
            @display("p=1650.948,720.25195;i=device/antennatower;is=l");
            numGates = 5;
        }

        rsu5: RSU {
            @display("p=262.314,481.65;i=device/antennatower;is=l");
            numGates = 5;
        }
        rsu6: RSU {
            @display("p=1822.86,438.672;i=device/antennatower;is=l");
            numGates = 5;
        }
        rsu7: RSU {
            @display("p=560.196,192.65999;i=device/antennatower;is=l");
            numGates = 5;
        }
        rsu8: RSU {
            @display("p=1511.6399,250.458;i=device/antennatower;is=l");
            numGates = 5;
        }
        rsu9: RSU {
            @display("p=1019.61597,163.01999;i=device/antennatower;is=l");
            numGates = 5;
        }

        kgc: KGC {
            @display("p=741,554.268;i=device/server;is=vl");
        }
        ta: TA {
            @display("p=1157.8125,623.4375;i=misc/house;is=vl");
        }

        attacker: Attacker {
            @display("p=409.68747,1074.6875");
        }
    connections allowunconnected:
        // vehicle connection to rsu
        //rsu1
        vehicle1.Vout --> rsu1.InPut[0];
        vehicle1.Vin <-- rsu1.OutPut[0];

        vehicle2.Vout --> rsu1.InPut[1];
        vehicle2.Vin <-- rsu1.OutPut[1];

        vehicle3.Vout --> rsu1.InPut[2];
        vehicle3.Vin <-- rsu1.OutPut[2];


        //rsu2


        vehicle4.Vout --> rsu2.InPut[0];
        vehicle4.Vin <-- rsu2.OutPut[0];

        vehicle5.Vout --> rsu2.InPut[1];
        vehicle5.Vin <-- rsu2.OutPut[1];

        vehicle6.Vout --> rsu2.InPut[2];
        vehicle6.Vin <-- rsu2.OutPut[2];

        //rsu3

        vehicle7.Vout --> rsu3.InPut[0];
        vehicle7.Vin <-- rsu3.OutPut[0];

        vehicle8.Vout --> rsu3.InPut[1];
        vehicle8.Vin <-- rsu3.OutPut[1];

        vehicle9.Vout --> rsu3.InPut[2];
        vehicle9.Vin <-- rsu3.OutPut[2];


        //rsu4


        vehicle10.Vout --> rsu4.InPut[0];
        vehicle10.Vin <-- rsu4.OutPut[0];

        vehicle11.Vout --> rsu4.InPut[1];
        vehicle11.Vin <-- rsu4.OutPut[1];

        vehicle12.Vout --> rsu4.InPut[2];
        vehicle12.Vin <-- rsu4.OutPut[2];

        //rsu5

        vehicle13.Vout --> rsu5.InPut[0];
        vehicle13.Vin <-- rsu5.OutPut[0];

        vehicle14.Vout --> rsu5.InPut[1];
        vehicle14.Vin <-- rsu5.OutPut[1];

        vehicle15.Vout --> rsu5.InPut[2];
        vehicle15.Vin <-- rsu5.OutPut[2];

        //rsu6     

        vehicle16.Vout --> rsu6.InPut[0];
        vehicle16.Vin <-- rsu6.OutPut[0];

        vehicle17.Vout --> rsu6.InPut[1];
        vehicle17.Vin <-- rsu6.OutPut[1];

        vehicle18.Vout --> rsu6.InPut[2];
        vehicle18.Vin <-- rsu6.OutPut[2];


        //rsu7

        vehicle19.Vout --> rsu7.InPut[0];
        vehicle19.Vin <-- rsu7.OutPut[0];

        vehicle20.Vout --> rsu7.InPut[1];
        vehicle20.Vin <-- rsu7.OutPut[1];

        vehicle21.Vout --> rsu7.InPut[2];
        vehicle21.Vin <-- rsu7.OutPut[2];


        //rsu8 

        vehicle22.Vout --> rsu8.InPut[0];
        vehicle22.Vin <-- rsu8.OutPut[0];

        vehicle23.Vout --> rsu8.InPut[1];
        vehicle23.Vin <-- rsu8.OutPut[1];

        vehicle24.Vout --> rsu8.InPut[2];
        vehicle24.Vin <-- rsu8.OutPut[2];

        //rsu9

        vehicle25.Vout --> rsu9.InPut[0];
        vehicle25.Vin <-- rsu9.OutPut[0];

        vehicle26.Vout --> rsu9.InPut[1];
        vehicle26.Vin <-- rsu9.OutPut[1];

        vehicle27.Vout --> rsu9.InPut[2];
        vehicle27.Vin <-- rsu9.OutPut[2];

        //rsu1 to rsu2
        rsu1.OutPut[3] --> rsu2.InPut[3];
        rsu1.InPut[3] <-- rsu2.OutPut[3];


        //rsu1 to rsu3
        rsu1.OutPut[4] --> rsu3.InPut[3];
        rsu1.InPut[4] <-- rsu3.OutPut[3];


        //rsu3 to rsu5
        rsu3.OutPut[4] --> rsu5.InPut[3];
        rsu3.InPut[4] <-- rsu5.OutPut[3];


        // rsu5 to rsu7
        rsu5.OutPut[4] --> rsu7.InPut[3];
        rsu5.InPut[4] <-- rsu7.OutPut[3];


         // rsu7 to rsu9
        rsu7.OutPut[4] --> rsu9.InPut[3];
        rsu7.InPut[4] <-- rsu9.OutPut[3];


         // rsu2 to rsu4
        rsu2.OutPut[4] --> rsu4.InPut[3];
        rsu2.InPut[4] <-- rsu4.OutPut[3];

         // rsu4 to rsu6
        rsu4.OutPut[4] --> rsu6.InPut[3];
        rsu4.InPut[4] <-- rsu6.OutPut[3];

         // rsu6 to rsu8
        rsu6.OutPut[4] --> rsu8.InPut[3];
        rsu6.InPut[4] <-- rsu8.OutPut[3];

        // rsu8 to rsu9
        rsu8.OutPut[4] --> rsu9.InPut[4];
        rsu8.InPut[4] <-- rsu9.OutPut[4];



        //KGC

        kgc.OutKGC[0] --> rsu3.InPut[5];
        kgc.InKGC[0] <-- rsu3.OutPut[5];

        //TA  

        ta.TAOUT[0] --> rsu2.InPut[5];
        ta.TAIN[0] <-- rsu2.OutPut[5];

        // attacker

        vehicle1.Vout2 --> attacker.in;
        attacker.out2 --> vehicle1.Vin2;
        rsu1.InPut[5] <-- attacker.out;
        rsu1.OutPut[5] --> attacker.in2;

}
