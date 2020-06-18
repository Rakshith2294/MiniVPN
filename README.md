# MiniVPN
MiniVPN is a lightweight Virtual Private Network (VPN) for linux.
VPN is built using TCP over TLS. 
VPN Client authenticates the server using certificates. 
VPN Server authenticates the client using hashed entries in the shadow file. 
Data is encapsulated inside a TCP header, and it encrypted using TLS before it is routed via tunnel. 
For usage check the tasks 3-5. 
