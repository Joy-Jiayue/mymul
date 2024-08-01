#include <stdio.h>

int main() {
    int a = 3;
    int b = 4;
    int result;

    // 使用内联汇编调用c_mymul指令
    asm volatile (
        "c_mymul %0, %1, %2"
        : "=r"(result)
        : "r"(a), "r"(b)
    );

    printf("Result of c_mymul(%d, %d) = %d\n", a, b, result);
    return 0;
}
