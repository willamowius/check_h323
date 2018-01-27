/*
 *
 * check_h323 - A H.323 monitoring plugin
 *
 * License: GPL
 *
 * (c) Relaxed Communications GmbH, 2009-2018
 *     jan@willamowius.de, https://www.willamowius.com
 *
 */

#include <ptlib.h>
#include <ptlib/sockets.h>
#include "h225.h"
#include "h323pdu.h"

const char H225_ProtocolID[] = "0.0.8.2250.0.2";

// convert a socket IP address into an H225 transport address
H225_TransportAddress SocketToH225TransportAddr(const PIPSocket::Address & Addr, WORD Port)
{
	H225_TransportAddress Result;

	if (Addr.GetVersion() == 6) {
		Result.SetTag(H225_TransportAddress::e_ip6Address);
		H225_TransportAddress_ip6Address & ResultIP = Result;
		for (int i = 0; i < 16; ++i)
			ResultIP.m_ip[i] = Addr[i];
		ResultIP.m_port = Port;
	} else {
		Result.SetTag(H225_TransportAddress::e_ipAddress);
		H225_TransportAddress_ipAddress & ResultIP = Result;
		for (int i = 0; i < 4; ++i)
			ResultIP.m_ip[i] = Addr[i];
		ResultIP.m_port = Port;
	}

	return Result;
}

class Client : public PProcess, public PUDPSocket
{
protected:
    void Main();

    void SendGRQ();
    void SendLRQ();

    WORD gk_port;
    Address gk_addr, my_addr;
};

PCREATE_PROCESS(Client)

void Client::Main()
{
	PArgList & args = GetArguments();
	args.Parse("glp:");
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
		exit(1);
	}
	freeaddrinfo(result);

    gk_port = 1719;
    if (args.HasOption('p')) {
        gk_port = args.GetOptionString('p').AsUnsigned();
    }

    GetHostAddress(my_addr);

	// Read-Timeout
	SetReadTimeout(PTimeInterval(3 * 1000));

    if (args.HasOption('l')) {
        SendLRQ();
    } else {
        SendGRQ();
    }
}

struct TPKTV3 {
    TPKTV3(WORD);
    BYTE header;
    BYTE padding;
    WORD length;
};

TPKTV3::TPKTV3(WORD len)
    : header(3), padding(0)
{
    length = PIPSocket::Host2Net(WORD(len + sizeof(TPKTV3)));
}

bool WriteTPKT(PTCPSocket & sock, const PBYTEArray & wtbuf)
{
    WORD len = (WORD)wtbuf.GetSize();
    WORD tlen = len + sizeof(TPKTV3);
    PBYTEArray tbuf(tlen);
    BYTE *bptr = tbuf.GetPointer();
    new (bptr) TPKTV3(len); // placement operator
    memcpy(bptr + sizeof(TPKTV3), wtbuf, len);
    return sock.Write(bptr, tlen);
}

void Client::SendGRQ()
{
	H225_RasMessage grq_ras, grq_rpl;
	grq_ras.SetTag(H225_RasMessage::e_gatekeeperRequest);
	H225_GatekeeperRequest & grq = grq_ras;

	grq.m_requestSeqNum.SetValue(1);
	grq.m_protocolIdentifier.SetValue(H225_ProtocolID);

	grq.m_rasAddress = SocketToH225TransportAddr(my_addr, gk_port);
	grq.m_endpointType.IncludeOptionalField(grq.m_endpointType.e_terminal);

	grq.IncludeOptionalField(grq.e_endpointAlias);
	grq.m_endpointAlias.SetSize(1);
	H323SetAliasAddress(PString("check_h323"), grq.m_endpointAlias[0]);

	PBYTEArray rdbuf(2048), wtbuf(2048);
	PPER_Stream rdstrm(rdbuf), wtstrm(wtbuf);

	grq_ras.Encode(wtstrm);
	wtstrm.CompleteEncoding();

	PUDPSocket sock(gk_port);
	if (!sock.Connect(gk_addr))
	{
		cout << "CRITICAL - Can not connect to the gatekeeper " << gk_addr << endl;
		sock.Close();
		exit(1);
	}

	sock.Write(wtstrm.GetPointer(), wtstrm.GetSize());

	sock.SetReadTimeout(GetReadTimeout());
	if (!sock.ReadFrom(rdstrm.GetPointer(), rdstrm.GetSize(), gk_addr, gk_port)) {
		cout << "CRITICAL - Timeout while waiting for GCF/GRJ" << endl;
		exit(1);
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
	lrq.m_replyAddress = SocketToH225TransportAddr(my_addr, gk_port);

    lrq.m_destinationInfo.SetSize(1);
    H323SetAliasAddress(PString("check_h323"), lrq.m_destinationInfo[0]);

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
		exit(1);
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
