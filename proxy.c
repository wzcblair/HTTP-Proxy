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

enum {MAX_NUM_CHILD = 20};

const char *pcPgmName;
static int numChild;

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

static char *readFromClient(int sockfd) {
	enum {BUF_SIZE = 4096};

	int iRecv, iSize;
	int iReqSize = 0;
	char buf[BUF_SIZE + 1];
	char *request;

	request = (char *) malloc(BUF_SIZE + 1);
	if (request == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	iSize = BUF_SIZE;
	request[0] = '\0';

	while (1) {
		if ((iRecv = recv(sockfd, buf, BUF_SIZE, 0)) < 0) {
			perror(pcPgmName);
			close(sockfd);
			exit(EXIT_FAILURE);
		}
		buf[iRecv] = '\0';
		iReqSize += iRecv;
		if (iReqSize > iSize) {
			iSize *= 2;
			request = (char *) realloc(request, iSize + 1);
			if (request == NULL) {
				fprintf(stderr, "Memory allocation error\n");
				close(sockfd);
				exit(EXIT_FAILURE);
			}
		}
		strcat(request, buf);
		if (strstr(request, "\r\n\r\n") != NULL)
			break;
	}
	return request;
}

static char *readFromServer (int iClientfd, int iServerfd) {
	enum {BUF_SIZE = 4096};

	int iRecv, iSize;
	int iReqSize = 0;
	char buf[BUF_SIZE + 1];
	char *response;

	response = (char *) malloc(BUF_SIZE + 1);
	if (response == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		close(iClientfd);
		close(iServerfd);
		exit(EXIT_FAILURE);
	}
	iSize = BUF_SIZE;
	response[0] = '\0';

	while ((iRecv = recv(iServerfd, buf, BUF_SIZE, 0)) > 0) {
		buf[iRecv] = '\0';
		iReqSize += iRecv;
		if (iReqSize > iSize) {
			iSize *= 2;
			response = (char *) realloc(response, iSize + 1);
			if (response == NULL) {
				fprintf(stderr, "Memory allocation error\n");
				close(iClientfd);
				close(iServerfd);
				exit(EXIT_FAILURE);
			}
		}
		strcat(response, buf);
	}

	return response;
}

static char *clientToServer (struct ParsedRequest *req, char *clientReq, int iClientfd, int iServerfd) {
	int iHeadersLen;
	char *serverReq;
	char *headersBuf;

	ParsedHeader_set(req, "Host", req->host);
	ParsedHeader_set(req, "Connection", "close");

	iHeadersLen = ParsedHeader_headersLen(req);
	headersBuf = (char *) malloc(iHeadersLen + 1);
	if (headersBuf == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		close(iClientfd);
		close(iServerfd);
		exit(EXIT_FAILURE);
	}

	ParsedRequest_unparse_headers(req, headersBuf, iHeadersLen);
	headersBuf[iHeadersLen] = '\0';

	serverReq = (char *) malloc(strlen(req->method) + strlen(req->path)
								+ strlen(req->version) + iHeadersLen + 5);
	if (serverReq == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		close(iClientfd);
		close(iServerfd);
		exit(EXIT_FAILURE);
	}

	serverReq[0] = '\0';
	strcpy(serverReq, req->method);
	strcat(serverReq, " ");
	strcat(serverReq, req->path);
	strcat(serverReq, " ");
	strcat(serverReq, req->version);
	strcat(serverReq, "\r\n");
	strcat(serverReq, headersBuf);

	free(headersBuf);

	return serverReq;
}

static void writeToSocket (char *message, int sockfd, int otherfd) {
	int iSent;
	int iTotalSent = 0;
	int numBytes = strlen(message);
	char *cpMarker = message;

	while (*cpMarker) {
		if ((iSent = send(sockfd, (void *) cpMarker, numBytes - iTotalSent, 0)) < 0) {
			perror("SEND error");
			close(sockfd);
			close(otherfd);
			exit(EXIT_FAILURE);
		}
		cpMarker += iSent;
		iTotalSent += iSent;
	}
}

static void handleRequest (int sockfd) {
	int iPid, iServerfd;
	char *clientReq;
	char *serverReq;
	char *serverResp;

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

		clientReq = readFromClient(sockfd);

		req = ParsedRequest_create();
		if (ParsedRequest_parse(req, clientReq, strlen(clientReq)) < 0) {
			fprintf(stderr, "Failed to parse request\n");
			close(sockfd);
			exit(EXIT_FAILURE);
		}
		if (req->port == NULL) req->port = "80";

		iServerfd = createClientSocket(req->host, req->port);
		serverReq = clientToServer(req, clientReq, sockfd, iServerfd);
		writeToSocket(serverReq, iServerfd, sockfd);

		serverResp = readFromServer(sockfd, iServerfd);
		writeToSocket(serverResp, sockfd, iServerfd);

		ParsedRequest_destroy(req);
		free(serverReq);
		free(clientReq);
		free(serverResp);
		close(sockfd);
		close(iServerfd);

		exit(EXIT_SUCCESS);
	}

	/* This code is executed by only the parent process. */
	numChild++;

	while (waitpid(-1, NULL, WNOHANG) > 0)
		numChild--;
	if (numChild >= MAX_NUM_CHILD) {
		wait(NULL);
		numChild--;
	}

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
	  numChild = 0;
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

	  /* Clean up */
	  close(iSockfd);

	  return 0;
}
