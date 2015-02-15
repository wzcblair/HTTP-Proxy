/*
 * proxy.c
 *
 *  Created on: Feb 15, 2015
 *      Author: Blair
 */

#include "proxy_parse.h"

const char *pcPgmName;

/* Create, bind, and listen on a stream socket on port pcPort and return socket */
int createSocket(char *pcPort) {
	enum {BACKLOG = 5};

  struct addrinfo aHints, *paRes;
  int iSockfd;

  /* Get address information for stream socket on input port */
  memset(&aHints, 0, sizeof(aHints));
  aHints.ai_family = AF_UNSPEC;
  aHints.ai_socktype = SOCK_STREAM;
  aHints.ai_flags = AI_PASSIVE;
  getaddrinfo(NULL, pcPort, &aHints, &paRes);

  /* Create, bind, listen */
  if ((iSockfd = socket(paRes->ai_family, paRes->ai_socktype, paRes->ai_protocol)) < 0) {
    perror("CREATE error");
    exit(EXIT_FAILURE);
  }
  if (bind(iSockfd, paRes->ai_addr, paRes->ai_addrlen) < 0) {
    perror("BIND error");
    exit(EXIT_FAILURE);
  }
  if (listen(iSockfd, BACKLOG) < 0) {
    perror("LISTEN error");
    exit(EXIT_FAILURE);
  }

  /* Free paRes, which was dynamically allocated by getaddrinfo */
  freeaddrinfo(paRes);

  return iSockfd;
}

static void handleRequest (int sockfd) {
	enum {BUF_SIZE = 4096};

	int iRecv, iPid;
	size_t addrLen;
	char buf[BUF_SIZE];
	struct sockaddr_in serverAddr, clientAddr;

	fflush(NULL);
	iPid = fork();
	if (iPid == -1) {
		perror(pcPgmName);
		close(sockfd);
		return;
	}

	if (iPid == 0)
	{
		/* This code is executed by only the child process. */
		ParsedRequest *req;
		if ((iRecv = recv(sockfd, buf, BUF_SIZE, 0)) < 0) {
			perror(pcPgmName);
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		req = ParsedRequest_create();
		if (ParsedRequest_parse(req, buf, iRecv) < 0) {
			fprintf(stderr, "Failed to parse request\n");
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		   printf("Method:%s\n", req->method);
		   printf("Host:%s\n", req->host);

		exit(EXIT_SUCCESS);
	}

	/* This code is executed by only the parent process. */

	/* Wait for the child process to finish. */
	iPid = wait(NULL);

	close(sockfd);
}

int main(int argc, char * argv[]) {
	int iSockfd, iClientfd, iLen;
	struct sockaddr aClient;

	  /* Single argument of argv[1] is the port number */
	  if (argc != 2) {
	    fprintf(stderr, "Usage: %s <port-number>\n", argv[0]);
	    exit(EXIT_FAILURE);
	  }

	  /* Prepare to process requests */
	  pcPgmName = argv[0];
	  iSockfd = createSocket(argv[1]);
	  iLen = sizeof(struct sockaddr);

	  /* Handle clients, one at a time */
	  while (1) {
	    /* Accept the client, skipping on failure */
	    if ((iClientfd = accept(iSockfd, &aClient, &iLen)) <=  0) {
	      perror(pcPgmName);
	      close(iClientfd);
	      continue;
	    }
	    handleRequest(iClientfd);
	  }
	  /*
	   * upon receiving connection, use fork()
	   */

	  /*
	   * when waiting on a child process, is proxy still listening for more connections? Should we be waiting?
	   */


	  /* Clean up */
	  close(iSockfd);




	return 0;
}
