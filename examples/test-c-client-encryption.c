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
#ifdef _WIN32
#define usleep(x) Sleep(x / 1000)
#else
#include <unistd.h>
#endif

#include "srt.h"

int main(int argc, char** argv)
{
    int ss, st;
    struct sockaddr_in sa;
    const char message [] = "This message should be encrypted sent to the other side";
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

    printf("srt remote address\n");
    sa.sin_family = AF_INET;
    sa.sin_port = htons(atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &sa.sin_addr) != 1)
    {
        return 1;
    }

    printf("srt setsockflag with SRTO_SNDSYN\n");
    srt_setsockflag(ss, SRTO_SNDSYN, &s_yes, sizeof(s_yes));
    if (SRT_ERROR == srt_setsockflag(ss, SRTO_SNDSYN, &s_yes, sizeof s_yes))
    {
      fprintf(stderr, "srt_setsockflag SRTO_SNDSYN: %s\n", srt_getlasterror_str());
      return 1;
    }

    printf("srt setsockflag encryption\n");
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

    printf("srt connect\n");
    st = srt_connect(ss, (struct sockaddr*)&sa, sizeof sa);
    if (st == SRT_ERROR)
    {
        fprintf(stderr, "srt_connect: %s\n", srt_getlasterror_str());
        return 1;
    }

    int i;
    for (i = 0; i < 100; i++)
    {
        printf("srt sendmsg2 #%d >> %s\n",i,message);
        st = srt_sendmsg2(ss, message, sizeof message, NULL);
        if (st == SRT_ERROR)
        {
            fprintf(stderr, "srt_sendmsg: %s\n", srt_getlasterror_str());
            return 1;
        }

        usleep(10000);  // 10 ms
    }


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
