/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2022 Haivision Systems Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "srt.h"

int main(int argc, char** argv)
{
    int ss, st;
    struct sockaddr_in sa;
    struct sockaddr_storage their_addr;
    const int s_yes = 1;
    //const int s_no = 0;
    const int keylength = 16; // 16 or 24 or 32

    if (argc != 4) {
      fprintf(stderr, "Usage: %s <host> <port> <passphrase>\n", argv[0]);
      return 1;
    }
    if (strlen(argv[3]) < 10)
    {
      fprintf(stderr, "<passphrase> must be be minimum 10 and maximum 79 characters long.\n");
      return 1;
    }

    printf("srt startup\n");
    st = srt_startup();
    if (st != 0)
    {
      fprintf(stderr, "failed to start up SRT\n");
      return 1;
    }
    srt_setloglevel(LOG_DEBUG);

    printf("srt socket\n");
    ss = srt_create_socket();
    if (ss == SRT_ERROR)
    {
        fprintf(stderr, "srt_socket: %s\n", srt_getlasterror_str());
        return 1;
    }

    printf("srt bind address\n");
    sa.sin_family = AF_INET;
    sa.sin_port = htons(atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &sa.sin_addr) != 1)
    {
        return 1;
    }

    printf("srt setsockflag with SRTO_RCVSYN\n");
    if (SRT_ERROR == srt_setsockflag(ss, SRTO_RCVSYN, &s_yes, sizeof s_yes))
    {
      fprintf(stderr, "srt_setsockflag SRTO_RCVSYN: %s\n", srt_getlasterror_str());
      return 1;
    }

    printf("srt setsockflag encryption, key length %d, passphrase %s\n", keylength, argv[3]);
    if (SRT_ERROR == srt_setsockflag(ss, SRTO_ENFORCEDENCRYPTION, &s_yes, sizeof(s_yes)))
    {
      fprintf(stderr, "srt_setsockflag SRTO_ENFORCEDENCRYPTION: %s\n", srt_getlasterror_str());
      return 1;
    }
    if (SRT_ERROR == srt_setsockflag(ss, SRTO_PBKEYLEN, &keylength, sizeof(keylength)))
    {
      fprintf(stderr, "srt_setsockflag SRTO_PBKEYLEN: %s\n", srt_getlasterror_str());
      return 1;
    }
    if (SRT_ERROR == srt_setsockflag(ss, SRTO_PASSPHRASE, argv[3], strlen(argv[3])))
    {
      fprintf(stderr, "srt_setsockflag SRTO_PASSPHRASE: %s\n", srt_getlasterror_str());
      return 1;
    }

    printf("srt bind\n");
    st = srt_bind(ss, (struct sockaddr*)&sa, sizeof sa);
    if (st == SRT_ERROR)
    {
        fprintf(stderr, "srt_bind: %s\n", srt_getlasterror_str());
        return 1;
    }

    printf("srt listen\n");
    st = srt_listen(ss, 2);
    if (st == SRT_ERROR)
    {
        fprintf(stderr, "srt_listen: %s\n", srt_getlasterror_str());
        return 1;
    }

    printf("srt accept\n");
    int addr_size = sizeof their_addr;
    int their_fd = srt_accept(ss, (struct sockaddr *)&their_addr, &addr_size);
    if (their_fd == -1)
    {
        fprintf(stderr, "srt_accept: %s\n", srt_getlasterror_str());
        return 1;
    }

    int i;
    for (i = 0; i < 100; i++)
    {
        printf("srt recvmsg #%d... ",i);
        char msg[2048];
        st = srt_recvmsg(their_fd, msg, sizeof msg);
        if (st == SRT_ERROR)
        {
            fprintf(stderr, "srt_recvmsg: %s\n", srt_getlasterror_str());
            goto end;
        }

        printf("Got msg of len %d << %s\n", st, msg);
    }

end:
    printf("srt close\n");
    st = srt_close(ss);
    if (st == SRT_ERROR)
    {
        fprintf(stderr, "srt_close: %s\n", srt_getlasterror_str());
        return 1;
    }

    printf("srt cleanup\n");
    srt_cleanup();
    return 0;
}
