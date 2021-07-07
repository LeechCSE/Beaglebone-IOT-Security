// NAME:  Scott Lee
// EMAIL: bwlee6736@gmail.com
// ID:    204955724

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <mraa.h>
#include <mraa/aio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define EXIT_SUCCESS 0
#define EXIT_SYSCALL_ERR 1
#define EXIT_BADARG 1
#define EXIT_INV_HOST 1
#define EXIT_OTHER_ERR 2

int rtn;

sig_atomic_t volatile run_flag = 1;
int period = 1; // default 1/sec
char scale_mode = 'F'; // default Fahrenheit
int log_flag = 0;
char *log_file = NULL;
int logfd, socketfd;
int pause_flag = 0;
int id_flag = 0;
int host_flag = 0;

const SSL_METHOD *ssl_method;
SSL_CTX *ssl_context;
SSL *ssl;

void print_msg(struct tm *curtime, char *msg){
  char temp_buf[18];
  sprintf(temp_buf, "%02d:%02d:%02d %s\n",
	  curtime->tm_hour, curtime->tm_min, curtime->tm_sec, msg);
  rtn = SSL_write(ssl, temp_buf, strlen(temp_buf));
  if (rtn <= 0){
    fprintf(stderr, "Error: SSL_write(%s)\n",
	    strerror(SSL_get_error(ssl, rtn)));
    exit(EXIT_OTHER_ERR);
  }

  if (log_flag)
    dprintf(logfd, "%02d:%02d:%02d %s\n",
	    curtime->tm_hour, curtime->tm_min, curtime->tm_sec, msg); 
}

void print_temp(struct tm *curtime, float cur_temp){
  char temp_buf[14];
  sprintf(temp_buf, "%02d:%02d:%02d %.1f\n",
	 curtime->tm_hour, curtime->tm_min, curtime->tm_sec, cur_temp);
  rtn = SSL_write(ssl, temp_buf, strlen(temp_buf));
   if (rtn <= 0){
    fprintf(stderr, "Error: SSL_write(%s)\n",
	    strerror(SSL_get_error(ssl, rtn)));
    exit(EXIT_OTHER_ERR);
  }

  if (log_flag)
    dprintf(logfd, "%02d:%02d:%02d %.1f\n",
	    curtime->tm_hour, curtime->tm_min, curtime->tm_sec,
	    cur_temp);
}

void do_when_interrupted(){
  time_t t;
  time(&t);
  if (t == (time_t) -1){
    fprintf(stderr, "Error: ctime(%s)\n", strerror(errno));
    exit(EXIT_SYSCALL_ERR);
  }
  struct tm *curtime = localtime(&t);
  if (curtime == NULL){
    fprintf(stderr, "Error: localtime(%s)\n", strerror(errno));
    exit(EXIT_SYSCALL_ERR);
  }

  print_msg(curtime, "SHUTDOWN");

  run_flag = 0;
}

float read_temp(mraa_aio_context thermo){
  const int B = 4275;
  const int R0 = 100000;
  uint16_t dump = mraa_aio_read(thermo);
  float R = 1023.0 / dump - 1.0;
  R *= R0;
  float temp = 1.0 / (log(R/R0) / B + 1 / 298.15) - 273.15;
  if (scale_mode == 'F')
     temp = (temp * 9 / 5) + 32;

  return temp;
}

int main(int argc, char **argv){  
  if (argc < 2){
    fprintf(stderr, "Error: missing argument\n \
Usage: lab4c_tcp Portnum --id=9-digit-num --host=name|address --log=log_file \
[--period=#] [--scale=C | F]\n");
    exit(EXIT_BADARG);
  }

  char *host = NULL;
  int id;
  
  int option;
  struct option options[] = {
    {"period", required_argument, NULL, 'p'},
    {"scale", required_argument, NULL, 's'},
    {"log", required_argument, NULL, 'l'},
    {"id", required_argument, NULL, 'i'},
    {"host", required_argument, NULL, 'h'},
    {0, 0, 0, 0}
  };
  /* Parse option */
  while (1){
    option = getopt_long(argc, argv, "", options, NULL);
    if (option == -1)
      break;

    switch (option){
    case 'p':
      period = atoi(optarg);
      break;

    case 's':
      if (!strcmp(optarg, "C"))
	scale_mode = 'C';
      else if (!strcmp(optarg, "F"))
	scale_mode = 'F';
      else{
	fprintf(stderr, "Error: invalid argument for --scale\n \
Usage: lab4c_tcp Portnum --id=9-digit-num --host=name|address --log=log_file \
[--period=#] [--scale=C | F]\n");
	  exit(EXIT_BADARG);
      }
      break;

    case 'l':
      log_flag = 1;
      log_file = optarg;
      logfd = creat(log_file, 0666);
      if (logfd == -1){
	fprintf(stderr, "Error: creat(%s)\n", strerror(errno));
	exit(EXIT_SYSCALL_ERR);
      }
      break;

    case 'i':
      if (strlen(optarg) != 9){
	fprintf(stderr, "Error: invalid argument for --id: require 9 digits \
Usage: lab4c_tcp Portnum --id=9-digit-num --host=name|address --log=log_file \
[--period=#] [--scale=C | F]\n");
	exit(EXIT_BADARG);
      }
      else{
	id_flag = 1;
	id = atoi(optarg);
      }
      break;

    case 'h':
      host_flag = 1;
      host = optarg;
      break;

    default:
      fprintf(stderr, "Error: invalid option\n \
Usage: lab4c_tcp Portnum --id=9-digit-num --host=name|address --log=log_file \
[--period=#] [--scale=C | F]\n");      
      exit(EXIT_BADARG);
    }
  }

  int port = atoi(argv[optind]);

  /* Check mendatory params */
  if (!log_flag || !id_flag || !host_flag){
    fprintf(stderr, "Error: missing mandatory option\n \
Usage: lab4c_tcp Portnum --id=9-digit-num --host=name|address --log=log_file \
[--period=#] [--scale=C | F]\n");      
    exit(EXIT_BADARG);
  }

  /* Initilize SSL */
  rtn = SSL_library_init();
  if (rtn == -1){
    fprintf(stderr, "Error: SSL_library_init(lib. init. fail)\n");
    exit(EXIT_OTHER_ERR);
  }
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  ssl_method = TLS_client_method();
  ssl_context = SSL_CTX_new(ssl_method);
  if (ssl_context == NULL){
    fprintf(stderr, "Error: SSL_CTX_new(context init. fail)\n");
    exit(EXIT_OTHER_ERR);
  }
  ssl = SSL_new(ssl_context);
  if (ssl == NULL){
    fprintf(stderr, "Error: SSL_new(creation of a new SSL structure failed)");
    exit(EXIT_OTHER_ERR);
  }
  
  /* Open TLS Connection */
  struct hostent* server;
  struct sockaddr_in server_addr;
  // create socket
  socketfd = socket(AF_INET, SOCK_STREAM, 0);
  if (socketfd == -1){
    fprintf(stderr, "Error: socket(%s)\n", strerror(errno));
    exit(EXIT_SYSCALL_ERR);
  }
  // get host
  server = gethostbyname(host);
  if (server == NULL){
    fprintf(stderr, "Error: gethostbyname(%s)\n", strerror(errno));
    exit(EXIT_INV_HOST);
  }
  // connect
  memset((char *) &server_addr, 0, sizeof(struct sockaddr_in));
  server_addr.sin_family = AF_INET;
  memcpy((char *) &server_addr.sin_addr.s_addr, (char *) server->h_addr,
	 server->h_length);
  server_addr.sin_port = htons(port);
  rtn = connect(socketfd, (struct sockaddr *) &server_addr,
		sizeof(struct sockaddr_in));
  if (rtn == -1){
    fprintf(stderr, "Error: connect(%s)\n", strerror(errno));
    exit(EXIT_OTHER_ERR);
  }
  
  rtn = SSL_set_fd(ssl, socketfd);
  if (rtn != 1){
    fprintf(stderr, "Error: SSL_set_fd(failed)\n");
    exit(EXIT_OTHER_ERR);
  } 
  rtn = SSL_connect(ssl);
  if (rtn < 0){
    fprintf(stderr, "Error: SSL_connect(fatal error occurred)\n");
    exit(EXIT_OTHER_ERR);
  }
  else if (rtn == 0){
    fprintf(stderr, "Error: SSL_connect(%s)\n",
	    strerror(SSL_get_error(ssl, rtn)));
    exit(EXIT_OTHER_ERR);
  }

  /* Immediate send/log of ID */
  char temp_buf[14];
  sprintf(temp_buf, "ID=%d\n", id);  
  rtn = SSL_write(ssl, temp_buf, strlen(temp_buf));
  if (rtn <= 0){
    fprintf(stderr, "Error: SSL_write(%s)\n",
	    strerror(SSL_get_error(ssl, rtn)));
    exit(EXIT_OTHER_ERR);
  }
  dprintf(logfd, "ID=%d\n", id);
  
  /* Initialize HW */
  mraa_aio_context thermo;
  thermo = mraa_aio_init(1); // AIN0
  mraa_gpio_context button;
  button = mraa_gpio_init(60);
  mraa_gpio_dir(button, MRAA_GPIO_IN);
  /* When button is pushed ... */
  mraa_gpio_isr(button, MRAA_GPIO_EDGE_RISING, &do_when_interrupted, NULL);
  /* When keyborad interrupt ... */
  signal(SIGINT, do_when_interrupted);
  /* First report */
  time_t tf;
  time(&tf);
  if (tf == (time_t) -1){
    fprintf(stderr, "Error: ctime(%s)\n", strerror(errno));
    exit(EXIT_SYSCALL_ERR);
  }
  struct tm *curtimef = localtime(&tf);
  if (curtimef == NULL){
    fprintf(stderr, "Error: localtime(%s)\n", strerror(errno));
    exit(EXIT_SYSCALL_ERR);
  }
  
  float cur_temp = read_temp(thermo);
  print_temp(curtimef, cur_temp);
  sleep(period);
  
  /* Read/Print temp */
  struct pollfd pollfd;
  pollfd.fd = socketfd;
  pollfd.events = POLLIN;
  
  while (run_flag){
    rtn = poll(&pollfd, 1, 0); // timeout = 0 ms
    if (rtn == -1){
      fprintf(stderr, "Error: poll(%s)\n", strerror(errno));
      exit(EXIT_SYSCALL_ERR);
    }
    /* Initialize time */
    time_t t;
    time(&t);
    if (t == (time_t) -1){
      fprintf(stderr, "Error: ctime(%s)\n", strerror(errno));
      exit(EXIT_SYSCALL_ERR);
    }
    struct tm *curtime = localtime(&t);
    if (curtime == NULL){
      fprintf(stderr, "Error: localtime(%s)\n", strerror(errno));
      exit(EXIT_SYSCALL_ERR);
    }

    ssize_t sz;
    char buf[256] = "";
    if (pollfd.revents & POLLIN){ // when stdin is readable
      sz = SSL_read(ssl, buf, sizeof(buf));
      if (sz < 0){
	fprintf(stderr, "Error: SSL_read(%s)",
		strerror(SSL_get_error(ssl, sz)));
	exit(EXIT_OTHER_ERR);
      }
      // Handle cmd
      if (strstr(buf, "SCALE=F") == NULL
	  && strstr(buf, "SCALE=C") == NULL
	  && strstr(buf, "PERIOD=") == NULL
	  && strstr(buf, "STOP") == NULL
	  && strstr(buf, "START") == NULL
	  && strstr(buf, "LOG") == NULL
	  && strstr(buf, "OFF") == NULL){ // invalid command
	if (log_flag)
	  dprintf(logfd, buf);
      }
      if (strstr(buf, "SCALE=F") != NULL){
	scale_mode = 'F';
	if (log_flag)
	  dprintf(logfd, buf);
      }
      if (strstr(buf, "SCALE=C") != NULL){
	scale_mode = 'C';
	if (log_flag)
	  dprintf(logfd, buf);
      }
      if (strstr(buf, "PERIOD=") != NULL){
	char *res = strstr(buf, "PERIOD=");
	char str_period[strlen(res)-6];
	memcpy(str_period, &res[7], strlen(res));
	str_period[strlen(res)+1] = '\0';
	period = atoi(str_period);
	
	if (log_flag)
	  dprintf(logfd, buf);
      }
      if (strstr(buf, "STOP") != NULL){
	if (log_flag)
	  dprintf(logfd, buf);
	pause_flag = 1;
      }
      if (strstr(buf, "START") != NULL){
	if (log_flag)
	  dprintf(logfd, buf);
	pause_flag = 0;
      }
      if (strstr(buf, "LOG") != NULL){
	if (log_flag)
	  dprintf(logfd, buf);	
	// process msg(line of text) in Lab 4C
	/*
	  char *res = strstr(buf, "LOG");
	  char msg[strlen(res)-4];
	  memcpy(msg, &res[5], strlen(res));
	  msg[strlen(res)+1] = '\0';
	*/
      }
      if (strstr(buf, "OFF") != NULL){
	if (log_flag)
	  dprintf(logfd, buf);
	
	pause_flag = 1;
	do_when_interrupted();	
      }
    }
    memset(buf, 0, 256 * sizeof(buf[0])); // flush buf
    
    if (!pause_flag){ // pause_flag for STOP/START cmds
      cur_temp = read_temp(thermo);
      print_temp(curtime, cur_temp);
      sleep(period);
    }
  }
  
  /* Close HW */
  mraa_aio_close(thermo);
  mraa_gpio_close(button);
  
  exit(EXIT_SUCCESS);
}
