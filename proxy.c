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
#include <sys/wait.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>

enum {MAX_NUM_CHILD = 20};

static int numChild;
static int errMessageLen = 31;
const char *pcPgmName;
const char *errMessage = "HTTP/1.0 500 INTERNAL ERROR\r\n\r\n";


/* Create, bind, and listen on a stream socket on port pcPort and return socket */
static int createServerSocket(char *pcPort) {
	enum {BACKLOG = 50};

  struct addrinfo aHints, *paRes;
  int iSockfd;

  /* Get address information for stream socket on input port */
  memset(&aHints, 0, sizeof(aHints));
  aHints.ai_family = AF_UNSPEC;
  aHints.ai_socktype = SOCK_STREAM;
  aHints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(NULL, pcPort, &aHints, &paRes) < 0) {
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

static void writeToSocket (const char *message, int sockfd, int otherfd, int *size) {
	int iSent;
	int iTotalSent = 0;

	while (iTotalSent < *size) {
		if ((iSent = send(sockfd, (void *) (message + iTotalSent), *size - iTotalSent, 0)) < 0) {
			perror("SEND error");
			shutdown(sockfd, SHUT_RDWR);
			close(sockfd);
			if (otherfd != -1) {
				shutdown(otherfd, SHUT_RDWR);
				close(otherfd);
			}
			exit(EXIT_FAILURE);
		}
		iTotalSent += iSent;
	}
}

static char *readFromClient(int sockfd) {
	enum {BUF_SIZE = 4096};

	int iRecv, iSize;
	int iReqSize = 0;
	char buf[BUF_SIZE + 1];
	char *request;

	request = (char *) malloc(BUF_SIZE + 1);
	if (request == NULL) {
		writeToSocket(errMessage, sockfd, -1, &errMessageLen);
		shutdown(sockfd, SHUT_RDWR);
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	iSize = BUF_SIZE;
	request[0] = '\0';
	
	while (strstr(request, "\r\n\r\n") == NULL) {
		if ((iRecv = recv(sockfd, buf, BUF_SIZE, 0)) < 0) {
			writeToSocket(errMessage, sockfd, -1, &errMessageLen);
			shutdown(sockfd, SHUT_RDWR);
			close(sockfd);
			exit(EXIT_FAILURE);
		}
		if (iRecv == 0) break;
		buf[iRecv] = '\0';
		iReqSize += iRecv;
		if (iReqSize > iSize) {

			iSize *= 2;
			request = (char *) realloc(request, iSize + 1);
			if (request == NULL) {
				writeToSocket(errMessage, sockfd, -1, &errMessageLen);
				shutdown(sockfd, SHUT_RDWR);
				close(sockfd);
				exit(EXIT_FAILURE);
			}
		}
		strcat(request, buf);
	
	}
	return request;
}

static char *readFromServer (int iClientfd, int iServerfd, int *reqSize) {

	int iRecv;
	int iSize = 4096;
	int iReqSize = 0;
	char *response;

	response = (char *) malloc(iSize);
	if (response == NULL) {
		writeToSocket(errMessage, iClientfd, iServerfd, &errMessageLen);
		shutdown(iClientfd, SHUT_RDWR);
		shutdown(iServerfd, SHUT_RDWR);
		close(iClientfd);
		close(iServerfd);
		exit(EXIT_FAILURE);
	}

	/*while ((iRecv = recv(iServerfd, response + iReqSize, iSize - iReqSize, 0)) > 0) {
		iReqSize += iRecv;
		if (iReqSize >= iSize) {
			iSize *= 2;
			response = (char *) realloc(response, iSize);
			if (response == NULL) {
				writeToSocket(errMessage, iClientfd, iServerfd, &errMessageLen);
				shutdown(iClientfd, SHUT_RDWR);
				shutdown(iServerfd, SHUT_RDWR);
				close(iClientfd);
				close(iServerfd);
				exit(EXIT_FAILURE);
			}
		}
		printf("%d\n", iSize - iReqSize);
		}*/
	while ((iRecv = recv(iServerfd, response, iSize, 0)) > 0) {
	      writeToSocket(response, iClientfd, iServerfd, &iRecv);
	}	
	if (iRecv < 0) {
	  writeToSocket(errMessage, iClientfd, iServerfd, &errMessageLen);
	  shutdown(iClientfd, SHUT_RDWR);
	  shutdown(iServerfd, SHUT_RDWR);
	  close(iClientfd);
	  close(iServerfd);
	  exit(EXIT_FAILURE);
	}


	*reqSize = iReqSize;
	return response;
}

static char *clientToServer (struct ParsedRequest *req, char *clientReq,
							 int iClientfd, int *reqLen) {
	int iHeadersLen;
	char *serverReq;
	char *headersBuf;
	/*char *host = (char *) malloc(strlen(req->host) + strlen(req->port) + 2);
	if (host == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		close(iClientfd);
		close(iServerfd);
		exit(EXIT_FAILURE);
	}

	host[0] = '\0';
	strcpy(host, req->host);
	strcat(host, ":");
	strcat(host, req->port); */

	ParsedHeader_set(req, "Host", req->host);
	ParsedHeader_set(req, "Connection", "close");

	iHeadersLen = ParsedHeader_headersLen(req);
	headersBuf = (char *) malloc(iHeadersLen + 1);
	if (headersBuf == NULL) {
		writeToSocket(errMessage, iClientfd, -1, &errMessageLen);
		shutdown(iClientfd, SHUT_RDWR);
		close(iClientfd);
		exit(EXIT_FAILURE);
	}

	ParsedRequest_unparse_headers(req, headersBuf, iHeadersLen);
	headersBuf[iHeadersLen] = '\0';

	*reqLen = strlen(req->method) + strlen(req->path) + strlen(req->version) + iHeadersLen + 4;
	serverReq = (char *) malloc(*reqLen + 1);
	if (serverReq == NULL) {
		writeToSocket(errMessage, iClientfd, -1, &errMessageLen);
		shutdown(iClientfd, SHUT_RDWR);
		close(iClientfd);
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

	/*free(host); */
	free(headersBuf);

	return serverReq;
}

static void handleRequest (int sockfd, int iSockfd) {
	int iPid, iServerfd;
	char *clientReq;
	char *serverReq;
	char *serverResp;

	fflush(NULL);
	iPid = fork();
	if (iPid == -1) {
		perror(pcPgmName);
		shutdown(sockfd, SHUT_RDWR);
		close(sockfd);
		return;
	}

	if (iPid == 0)
	{
		/* This code is executed by only the child process. */
		struct ParsedRequest *req;
		int iReqLen = 0;
		int iRespLen = 0;
		int *reqLen = &iReqLen;
		int *respLen = &iRespLen;
	
		clientReq = readFromClient(sockfd);
	
		req = ParsedRequest_create();
		if (ParsedRequest_parse(req, clientReq, strlen(clientReq)) < 0) {
			writeToSocket(errMessage, sockfd, -1, &errMessageLen);
			shutdown(sockfd, SHUT_RDWR);
			close(sockfd);
			exit(EXIT_FAILURE);
		}
		if (req->port == NULL) req->port = (char *) "80";

		serverReq = clientToServer(req, clientReq, sockfd, reqLen);
		iServerfd = createClientSocket(req->host, req->port);
		writeToSocket(serverReq, iServerfd, sockfd, reqLen);

		serverResp = readFromServer(sockfd, iServerfd, respLen);
		/*writeToSocket(serverResp, sockfd, iServerfd, respLen);*/
		
		ParsedRequest_destroy(req);
		free(serverReq);
		free(clientReq);
		free(serverResp);
		shutdown(sockfd, SHUT_RDWR);
		shutdown(iServerfd, SHUT_RDWR);
		close(sockfd);
		close(iServerfd);
		close(iSockfd);

		exit(EXIT_SUCCESS);
	}

	/* This code is executed by only the parent process. */
	numChild++;

	while (waitpid(-1, NULL, WNOHANG) > 0) {
		numChild--;
	}
	if (numChild >= MAX_NUM_CHILD) {
		wait(NULL);
		numChild--;
	}
	

	close(sockfd);
}

int main(int argc, char * argv[]) {
	int iSockfd, iClientfd;
	socklen_t iLen;
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

	  /* Handle clients */
	  while (1) {
	    /* Accept the client, skipping on failure */
	    if ((iClientfd = accept(iSockfd, &aClient, &iLen)) <=  0) {
	      perror(pcPgmName);
	      shutdown(iClientfd, SHUT_RDWR);
	      close(iClientfd);
	      continue;
	    }
	    handleRequest(iClientfd, iSockfd);
	  }

	  /* Clean up */
	  shutdown(iSockfd, SHUT_RDWR);
	  close(iSockfd);

	  return 0;
}
