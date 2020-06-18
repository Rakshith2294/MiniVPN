#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>
#include <stdlib.h>

#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

int  setupTCPServer();                   
void processRequest(SSL* ssl, int sockfd, int tunfd); 
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

int main(){

  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL *ssl;
  int err;
  SSL_library_init();
  SSL_load_error_strings();
  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_use_certificate_file(ctx, "/home/seed/VPN-lab/cert_server/server_crt.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "/home/seed/VPN-lab/cert_server/server_key.pem", SSL_FILETYPE_PEM);
  ssl = SSL_new(ctx);
  int tunfd,sockfd;
  tunfd = createTunDevice();
  system("/home/seed/VPN-lab/vpn/config_server.sh");  
  struct sockaddr_in sa_client;
  int client_len = sizeof(sa_client);
  int listen_sock = setupTCPServer();
  while(1){
    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
    if (fork() == 0) { // The child process
       close (listen_sock);
       SSL_set_fd (ssl, sock);
       int err = SSL_accept (ssl);
       CHK_SSL(err);
       printf ("SSL connection established!\n");
       processRequest(ssl, sock, tunfd);
       close(sock);
       return 0;
    } else { // The parent process
        close(sock);
    }
  } 
}

int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;
    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4433);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind"); 
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

void processRequest(SSL* ssl, int sockfd, int tunfd)
{
    char buf[1024];
    int len = SSL_read (ssl, buf, sizeof(buf) - 1);
    buf[len] = '\0';
    printf("Connection request from client %s \n",buf);
    struct spwd *pass;
    char *hash;
    pass = getspnam(buf);
  if (pass == NULL) {
   printf("Request Terminated: User not found\n");
   SSL_write(ssl, "0", 1);
   return;
  }
    SSL_write(ssl, "1", 1);
    len = SSL_read (ssl, buf, sizeof(buf) - 1);
    buf[len] = '\0';
    hash = crypt(buf, pass->sp_pwdp);
    if (strcmp(hash, pass->sp_pwdp)) {
  printf("Incorrect password\n");
  SSL_write(ssl, "0", 1);
  return;
  }
    printf("Successfully Authenticated\n");
    SSL_write(ssl, "1", 1);
    while (1) {
    fd_set readFDSet;
    FD_ZERO(&readFDSet);
    FD_SET(sockfd, &readFDSet);
    FD_SET(tunfd, &readFDSet);
    select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
    if (FD_ISSET(tunfd, &readFDSet)) tunSelected(tunfd, sockfd,ssl);
    if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd,ssl);
  }
    SSL_shutdown(ssl);  SSL_free(ssl);
}