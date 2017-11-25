check_h323 - A Nagios plugin to monitor H.323 devices
=====================================================

Author: Jan Willamowius <jan@willamowius.de>
		Relaxedcommunications GmbH
		https://www.willamowius.com/

License: GPL (http://www.gnu.org/copyleft/gpl.html)

Homepage: https://www.gnugk.org/nagios-h323.html

To compile use H323Plus and PTLib and say "make optnoshared". I use H323Plus 1.26.5 and PTLib 2.10.9.

Usage: check_h323 [-l|-g] [-p port] host

Options:
-g	send GRQ to host
-l	send LRQ to host

