#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <crypt.h>
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stdout); exit(2); }
struct addrinfo hints, *result;

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx); 
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject = %s\n", buf);
    if (preverify_ok == 1) {
       printf("Verification passed\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n", 
     X509_verify_cert_error_string(err));
       exit(2); 
    }
}

SSL* setupTLSClient(const char* hostname)
{
   SSL_library_init();
   SSL_load_error_strings();
   SSL_METHOD *meth = (SSL_METHOD *)TLSv1_2_method();
   SSL_CTX* ctx = SSL_CTX_new(meth);;
   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
   if(SSL_CTX_load_verify_locations(ctx,NULL,"/home/seed/vpn/ca_client/") < 1){
  printf("Location verification failed\n");
  exit(0);}
   SSL* ssl = SSL_new (ctx);
   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);
   return ssl;
}

int setupTCPClient(const char* hostname, int port)
{
   struct sockaddr_in server_addr;
   hints.ai_family = AF_INET;
   getaddrinfo(hostname, NULL, &hints, &result);
   struct sockaddr* ip = (struct sockaddr *) result->ai_addr;
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
   memset (&server_addr, '\0', sizeof(server_addr));
   server_addr.sin_addr = ((struct sockaddr_in*)ip)->sin_addr; 
   server_addr.sin_port   = htons (port);
   server_addr.sin_family = AF_INET;
   connect(sockfd, (struct sockaddr*) &server_addr,
   sizeof(server_addr));
   return sockfd;
}

struct sockaddr_in peerAddr;
int createTunDevice() {
	int tunfd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 
	tunfd = open("/dev/net/tun", O_RDWR); 
	ioctl(tunfd, TUNSETIFF, &ifr);  
	return tunfd;
}

void tunSelected(int tunfd, int sockfd, SSL *ssl) {
	int  len;
	char buff[BUFF_SIZE];
	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE); 
	buff[len] = '\0';
	SSL_write(ssl, buff, len);
}

void socketSelected(int tunfd, int sockfd, SSL *ssl) {
	int  len;
	char buff[BUFF_SIZE];
	bzero(buff, BUFF_SIZE);
	len = SSL_read (ssl, buff, BUFF_SIZE);
	buff[len] = '\0';
	write(tunfd, buff, len);  
}

int client_auth(SSL *ssl, char* hostname)
{
   char buf[6000];
   char username[90];
   printf("Username : ");
   scanf("%s",username);
   SSL_write(ssl, username, strlen(username));
   int len;
   len = SSL_read (ssl, buf, sizeof(buf) - 1);
   if(buf[0] == '0') {
  printf("User account does not exist\n");
  exit(0);
   }
   char* pwd = getpass("Password: ");
   SSL_write(ssl, pwd, strlen(pwd));
   len = SSL_read (ssl, buf, sizeof(buf) - 1);
   if(buf[0] == '0') {
  printf("Incorrect password!\n");
  exit(0);
   }
}

int main(int argc, char *argv[])
{
  char *hostname;
   int port;
   if (argc < 2){
	printf("Incorrect parameters please provide hostname and port no \n");
	exit(0);
   }   	
   if (argc > 1)   hostname = argv[1];
   if (argc > 2)   port = atoi(argv[2]);
   printf("Connecting to server %s...\n", hostname);
   int tunfd;
   //Create a TUN interface
   tunfd = createTunDevice();
   system("/home/seed/vpn/config_client.sh");
   /*TLS initialization*/
   SSL *ssl   = setupTLSClient(hostname);
   /*TCP Handshake*/
   int sockfd = setupTCPClient(hostname,port);
   /*TLS handshake*/
   SSL_set_fd(ssl, sockfd);
   int err = SSL_connect(ssl);
   CHK_SSL(err);
   printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
   printf("Please enter your username and password\n");
   client_auth(ssl,hostname);
   printf("You are now connected to the VPN\n");
   printf("MiniVPN Connection successful\n");
   while (1) {
	   fd_set readFDSet;
	   FD_ZERO(&readFDSet);
	   FD_SET(sockfd, &readFDSet);
	   FD_SET(tunfd, &readFDSet);
	   select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
	   if (FD_ISSET(tunfd, &readFDSet)) tunSelected(tunfd, sockfd,ssl);
	   if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd,ssl);
   }
}
