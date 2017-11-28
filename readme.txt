check_h323 - A Nagios plugin to monitor H.323 devices
=====================================================

Author: Jan Willamowius <jan@willamowius.de>
		Relaxedcommunications GmbH
		https://www.willamowius.com/

License: GPL (https://www.gnu.org/copyleft/gpl.html)

Homepage: https://www.gnugk.org/nagios-h323.html

To compile use H323Plus and PTLib and say "make optnoshared".

Usage: check_h323 [-l|-g] [-p port] host

Options:
-g	send GRQ to host
-l	send LRQ to host


As Docker health check:

HEALTHCHECK CMD /usr/local/bin/check_h323 127.0.0.1

