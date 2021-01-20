#include<unistd.h>
#include<stdio.h>

void bof() {
    int c[0x10];
    read(0, &c, 0x200);
}

int main() {
    char buffer[10];
    gets(buffer);
    bof();
    puts("Na Ni?!");
    return 0;
}
