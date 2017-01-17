
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 *
 * A portable "echo" program that supports "-n" option:
 *     echo Hello world!
 *     echo "Hello world!"
 *     echo -n Hello world!
 *     echo
 *
 * It also passes "\c" characters as is.
 */


#include <stdio.h>
#include <string.h>


int
main(int argc, char *const *argv)
{
    int  i = 1;
    int  nl = 1;

    if (argc > 1) {
        if (strcmp(argv[1], "-n") == 0) {
            nl = 0;
            i++;
        }

        while (i < argc) {
            printf("%s%s", argv[i], (i == argc - 1) ? "" : " ");
            i++;
        }
    }

    if (nl) {
        printf("\n");
    }

    return 0;
}
