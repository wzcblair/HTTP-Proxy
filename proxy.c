/*
 * proxy.c
 *
 *  Created on: Feb 15, 2015
 *      Author: Blair
 */

#include "proxy_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

const char *pcPgmName;

/* Create, bind, and listen on a stream socket on port pcPort and return socket */
static int createServerSocket(char *pcPort) {
	enum {BACKLOG = 5};

  struct addrinfo aHints, *paRes;
  int iSockfd;

  /* Get address information for stream socket on input port */
  memset(&aHints, 0, sizeof(aHints));
  aHints.ai_family = AF_UNSPEC;
  aHints.ai_socktype = SOCK_STREAM;
  aHints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(NULL, pcPort, &aHints, &paRes) != 0) {
      perror("GETADDR error");
      exit(EXIT_FAILURE);
  }

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

static int createClientSocket(char *pcAddress, char *pcPort) {
  struct addrinfo aHints, *paRes;
  int iSockfd;

  /* Get address information for stream socket on input port */
  memset(&aHints, 0, sizeof(aHints));
  aHints.ai_family = AF_UNSPEC;
  aHints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(pcAddress, pcPort, &aHints, &paRes) != 0) {
    perror("GETADDR error");
    exit(EXIT_FAILURE);
  }

  /* Create and connect */
  if ((iSockfd = socket(paRes->ai_family, paRes->ai_socktype, paRes->ai_protocol)) < 0) {
    perror("CREATE error");
    exit(EXIT_FAILURE);
  }
  if (connect(iSockfd, paRes->ai_addr, paRes->ai_addrlen) < 0) {
    perror("CONNECT error");
    exit(EXIT_FAILURE);
  }

  /* Free paRes, which was dynamically allocated by getaddrinfo */
  freeaddrinfo(paRes);

  return iSockfd;
}

static void handleRequest (int sockfd) {
	enum {BUF_SIZE = 4096};

	int iRecv, iPid, iServerfd, iHeadersLen, iRequestLen;
	size_t addrLen;
	char buf[BUF_SIZE];
	char *headersBuf;
	char *reqBuf;
	char *respBuf;
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
		struct ParsedRequest *req;
		if ((iRecv = recv(sockfd, buf, BUF_SIZE, 0)) < 0) {
			perror(pcPgmName);
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		req = ParsedRequest_create();
		if (ParsedRequest_parse(req, buf, iRecv) < 0) {
			fprintf(stderr, "Failed to parse request\n");
			ParsedRequest_destroy(req);
			close(sockfd);
			exit(EXIT_FAILURE);
		}
		if (req->port == NULL) req->port = "80";
		iServerfd = createClientSocket(req->host, req->port);
		ParsedHeader_set(req, "Connection", "close");

		iHeadersLen = ParsedHeader_headersLen(req);
		headersBuf = (char *) malloc(iHeadersLen + 1);
		if (headersBuf == NULL) {
			fprintf(stderr, "Memory allocation error\n");
			ParsedRequest_destroy(req);
			close(sockfd);
			close(iServerfd);
			exit(EXIT_FAILURE);
		}

		ParsedRequest_unparse_headers(req, headersBuf, iHeadersLen);
		headersBuf[iHeadersLen] = '\0';

		reqBuf = (char *) calloc(strlen(req->method) + strlen(req->path)
								+ strlen(req->version) + strlen(req->host) + strlen(req->port)
								+ iHeadersLen + 14, sizeof(char));
		if (reqBuf == NULL) {
			fprintf(stderr, "Memory allocation error\n");
			ParsedRequest_destroy(req);
			free(headersBuf);
			close(sockfd);
			close(iServerfd);
			exit(EXIT_FAILURE);
		}
		strcpy(reqBuf, req->method);
		strcat(reqBuf, " ");
		strcat(reqBuf, req->path);
		strcat(reqBuf, " ");
		strcat(reqBuf, req->version);
		strcat(reqBuf, "\r\n");
		strcat(reqBuf, "Host: ");
		strcat(reqBuf, req->host);
		strcat(reqBuf, ":");
		strcat(reqBuf, req->port);
		strcat(reqBuf, "\r\n");
		strcat(reqBuf, headersBuf);

		if (send(iServerfd, (void *) reqBuf, strlen(reqBuf), NULL) < 0) {
			perror("SEND error");
			ParsedRequest_destroy(req);
			free(headersBuf);
			free(reqBuf);
			close(sockfd);
			close(iServerfd);
			exit(EXIT_FAILURE);
		}

		recv(iServerfd, /*somebuf*/, ...);

		send(sockfd, /*somebuf*/, ...);
		ParsedRequest_destroy(req);
		free(headersBuf);
		free(reqBuf);
		close(sockfd);
		close(iServerfd);

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
	  iSockfd = createServerSocket(argv[1]);
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
