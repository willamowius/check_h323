#include <ptlib.h>
#include <ptlib/sockets.h>
#include <ptclib/asner.h>
#include "h225.h"
#include "h323.h"
#include "h323pdu.h"

#ifdef H323_H450
#include "h450/h4501.h"
#include "h450/h450pdu.h"
#endif // H323_H450

const char H225_ProtocolID[] = "0.0.8.2250.0.2";

class Client : public PProcess, public PUDPSocket
{
protected:
    void Main();

    void SendGRQ();
    void SendLRQ();
    void SendSetup();
    void SendReleaseComplete();

    WORD gk_port;
    Address gk_addr, my_addr;
};

PCREATE_PROCESS(Client)

void Client::Main()
{
	PArgList & args = GetArguments();
	args.Parse("glsp:");
	if (args.GetCount() != 1) {
        cout << "Usage: check_h323 [-l|-g [-p port] host" << endl;
        exit(1);
	}

    PString hostname = args.GetParameter(0);
	struct addrinfo hints;
	struct addrinfo * result = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	if (getaddrinfo(hostname, NULL, &hints, &result) == 0) {
        gk_addr = PIPSocket::Address(result->ai_family, result->ai_addrlen, result->ai_addr);
	} else {
		cout << "CRITICAL - DNS lookup failed for " << hostname << endl;
		exit(2);
	}
	freeaddrinfo(result);

    gk_port = 1719;
    if (args.HasOption('s')) {
    	gk_port = 1720;
	}
    if (args.HasOption('p')) {
        gk_port = args.GetOptionString('p').AsUnsigned();
    }

    GetHostAddress(my_addr);

	// Read-Timeout
	SetReadTimeout(PTimeInterval(3 * 1000));

    if (args.HasOption('l')) {
        SendLRQ();
    } else if (args.HasOption('s')) {
        SendReleaseComplete();
//        SendSetup();
    } else {
        SendGRQ();
    }
}

void SetUUIE(Q931 & q931, const H225_H323_UserInformation & uuie)
{
    PPER_Stream strm;
    uuie.Encode(strm);
    strm.CompleteEncoding();
    q931.SetIE(Q931::UserUserIE, strm);
}

struct TPKTV3 {
        TPKTV3(WORD);
        BYTE header, padding;
        WORD length;
    };

TPKTV3::TPKTV3(WORD len)
    : header(3), padding(0)
{
    length = PIPSocket::Host2Net(WORD(len + sizeof(TPKTV3)));
}

bool WriteTPKT(PTCPSocket & sock, const PBYTEArray & wtbuf)
{
    WORD len = (WORD)wtbuf.GetSize(), tlen = len + sizeof(TPKTV3);
    PBYTEArray tbuf(tlen);
    BYTE *bptr = tbuf.GetPointer();
    new (bptr) TPKTV3(len); // placement operator
    memcpy(bptr + sizeof(TPKTV3), wtbuf, len);
    return sock.Write(bptr, tlen);
}

void Client::SendReleaseComplete()
{
    Q931 q931;
    H225_H323_UserInformation uuie;
	q931.BuildReleaseComplete(1, true);
	uuie.m_h323_uu_pdu.m_h323_message_body.SetTag(H225_H323_UU_PDU_h323_message_body::e_releaseComplete);
	H225_ReleaseComplete_UUIE & rc = uuie.m_h323_uu_pdu.m_h323_message_body;
	rc.m_protocolIdentifier.SetValue(H225_ProtocolID);
    rc.m_callIdentifier.m_guid = OpalGloballyUniqueID();
	SetUUIE(q931, uuie);

	PBYTEArray rdbuf(20480), wtbuf;

	q931.Encode(wtbuf);

	PTCPSocket sock(gk_port);
	if (!sock.Connect(gk_addr))
	{
		cout << "CRITICAL - Can not connect to the gatekeeper " << gk_addr << endl;
		sock.Close();
		exit(2);
	}

    if (!WriteTPKT(sock, wtbuf)) {
		cout << "CRITICAL - Can not send to the gatekeeper " << gk_addr << endl;
		sock.Close();
		exit(2);
    }

    // TODO: check reply
}

void Client::SendSetup()
{
    Q931 q931;
    H225_H323_UserInformation uuie;
	q931.BuildSetup(1);
	uuie.m_h323_uu_pdu.m_h323_message_body.SetTag(H225_H323_UU_PDU_h323_message_body::e_setup);
	H225_Setup_UUIE & setup = uuie.m_h323_uu_pdu.m_h323_message_body;
	setup.m_protocolIdentifier.SetValue(H225_ProtocolID);
	setup.m_conferenceID = OpalGloballyUniqueID();
    setup.m_callIdentifier.m_guid = setup.m_conferenceID;

#ifdef H323_H450
    // H.450
    uuie.m_h323_uu_pdu.IncludeOptionalField(H225_H323_UU_PDU::e_h4501SupplementaryService);
    H4501_SupplementaryService supplementaryService;
    //H4501_InterpretationApdu & interpretation = supplementaryService.m_interpretationApdu;
    supplementaryService.m_serviceApdu.SetTag(H4501_ServiceApdus::e_rosApdus);
    PPER_Stream resultStream;
    supplementaryService.Encode(resultStream);
    resultStream.CompleteEncoding();
    uuie.m_h323_uu_pdu.m_h4501SupplementaryService.SetSize(1);
    uuie.m_h323_uu_pdu.m_h4501SupplementaryService[0].SetValue(resultStream) ;
#else
#warning("No H.450 support");
#endif

	SetUUIE(q931, uuie);

	PBYTEArray rdbuf(20480), wtbuf;

	q931.Encode(wtbuf);

	PTCPSocket sock(gk_port);
	if (!sock.Connect(gk_addr))
	{
		cout << "CRITICAL - Can not connect to the gatekeeper " << gk_addr << endl;
		sock.Close();
		exit(2);
	}

    if (!WriteTPKT(sock, wtbuf)) {
		cout << "CRITICAL - Can not send to the gatekeeper " << gk_addr << endl;
		sock.Close();
		exit(2);
    }

    // TODO: check reply
}

void Client::SendGRQ()
{
	H225_RasMessage grq_ras, grq_rpl;
	grq_ras.SetTag(H225_RasMessage::e_gatekeeperRequest);
	H225_GatekeeperRequest & grq = grq_ras;

	grq.m_requestSeqNum.SetValue(1);
	grq.m_protocolIdentifier.SetValue(H225_ProtocolID);

	grq.m_rasAddress.SetTag(H225_TransportAddress::e_ipAddress);
	H225_TransportAddress_ipAddress & ipAddress = grq.m_rasAddress;
	ipAddress.m_ip[0] = my_addr.Byte1();
	ipAddress.m_ip[1] = my_addr.Byte2();
	ipAddress.m_ip[2] = my_addr.Byte3();
	ipAddress.m_ip[3] = my_addr.Byte4();
	ipAddress.m_port  = gk_port;

	grq.m_endpointType.IncludeOptionalField(grq.m_endpointType.e_terminal);

	grq.IncludeOptionalField(grq.e_endpointAlias);
	grq.m_endpointAlias.SetSize(1);
	H323SetAliasAddress(PString("Nagios Monitoring"), grq.m_endpointAlias[0]);

	PBYTEArray rdbuf(2048), wtbuf(2048);
	PPER_Stream rdstrm(rdbuf), wtstrm(wtbuf);

	grq_ras.Encode(wtstrm);
	wtstrm.CompleteEncoding();

	PUDPSocket sock(gk_port);
	if (!sock.Connect(gk_addr))
	{
		cout << "CRITICAL - Can not connect to the gatekeeper " << gk_addr << endl;
		sock.Close();
		exit(2);
	}

	sock.Write(wtstrm.GetPointer(), wtstrm.GetSize());

	sock.SetReadTimeout(GetReadTimeout());
	if (!sock.ReadFrom(rdstrm.GetPointer(), rdstrm.GetSize(), gk_addr, gk_port)) {
		cout << "CRITICAL - Timeout while waiting for GCF/GRJ" << endl;
		exit(2);
	}

	grq_rpl.Decode(rdstrm);
	sock.Close();

	cout << "OK - " << grq_rpl.GetTagName() << " from " << gk_addr << endl;
	exit(0);
}

void Client::SendLRQ()
{
    H225_RasMessage lrq_ras, lrq_rpl;
    lrq_ras.SetTag(H225_RasMessage::e_locationRequest);
    H225_LocationRequest & lrq = lrq_ras;

    lrq.m_requestSeqNum.SetValue(1);

	// set replyAddress (mandatory)
	lrq.m_replyAddress.SetTag(H225_TransportAddress::e_ipAddress);
	H225_TransportAddress_ipAddress & ipAddress = lrq.m_replyAddress;
	ipAddress.m_ip[0] = my_addr.Byte1();
	ipAddress.m_ip[1] = my_addr.Byte2();
	ipAddress.m_ip[2] = my_addr.Byte3();
	ipAddress.m_ip[3] = my_addr.Byte4();
	ipAddress.m_port  = gk_port;

    lrq.m_destinationInfo.SetSize(1);
    H323SetAliasAddress(PString("Nagios Monotoring"), lrq.m_destinationInfo[0]);

    // TODO: add H.460.18 so GK answers to apparent IP ?

    // Send LRQ
    PBYTEArray rdbuf(2048), wtbuf(2048);
    PPER_Stream rdstrm(rdbuf), wtstrm(wtbuf);

    lrq_ras.Encode(wtstrm);
    wtstrm.CompleteEncoding();

   PUDPSocket sock(gk_port);
   if (!sock.Connect(gk_addr)) {
		cout << "CRITICAL - Can not connect to the gatekeeper " << gk_addr << endl;
		sock.Close();
		exit(2);
    }

    sock.Write(wtstrm.GetPointer(), wtstrm.GetSize());

	// wait for LCF / LRJ
	sock.SetReadTimeout(GetReadTimeout());
    sock.ReadFrom(rdstrm.GetPointer(), rdstrm.GetSize(), gk_addr, gk_port);
    lrq_rpl.Decode(rdstrm);
    sock.Close();

    if ((lrq_rpl.GetTag() == H225_RasMessage::e_locationConfirm)
		|| (lrq_rpl.GetTag() == H225_RasMessage::e_locationReject)) {
		cout << "OK - " << lrq_rpl.GetTagName() << " from " << gk_addr << endl;
		exit(0);
	} else {
		cout << "CRITICAL - no answer" << endl;
		exit(1);
	}
}

