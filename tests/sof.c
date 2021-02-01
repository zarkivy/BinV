#include <stdio.h>

void func()
{
    char pwd[0x10]={0}; 
    puts("input admin password:");
    read(0,pwd,0x20);
}
void over()
{
    puts("over!");
    char c[0x10]={0};   
    read(0,c,0x20);
}
int main(int argc, char const *argv[])
{
    char name[0x10]={0};
    puts("input your name:");
    read(0,name,0x10);
    over();
    if (strstr(name,"admin"))
    {
        func();
        puts("welcome admin~");
    }
    else
    {
        printf("welcome, %s\n", name);
    }
    return 0;
}