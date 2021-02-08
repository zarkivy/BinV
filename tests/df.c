#include <stdio.h>
#include <stdlib.h>

char bss[0x10]={0};
int main(int argc, char const *argv[])
{
    char buf[0x10]={0};
    int times=3;
    unsigned long *ptr=&bss;
    while(times--)
    {
        puts("input:");
        read(0,buf,8);
        switch(atoi(buf))
        {
            case 1: 
                puts("malloc!");
                *ptr=malloc(0x30);
                // printf("%p,%p,%p\n", &ptr,ptr,*ptr);
                break;
            case 2:
                if (*ptr)
                {
                    puts("free!");
                    free(*ptr);

                }
                else
                {
                    puts("fail to free");
                    return;
                }

                break;
            case 3:
                if (*ptr)
                {
                    puts("edit!");
                    read(0,*ptr,8);

                }
                else
                {
                    puts("fail to edit");
                    return;
                }
                break;

            case 4:
                if (*ptr)
                {
                    puts("show!");
                    write(1,*ptr,8);

                }
                else
                {
                    puts("fail to show");
                    return;
                }
                break;

        }

    }

    return 0;
}
