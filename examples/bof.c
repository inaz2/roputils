#include <unistd.h>

int main()
{
    char buf[100];
    int size;
    read(0, &size, 4);
    read(0, buf, size);
    write(1, buf, size);
    return 0;
}
