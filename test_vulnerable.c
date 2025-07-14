#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Test program with various buffer overflow vulnerabilities
// This is for educational purposes only

// Function 1: Classic gets() vulnerability (CVE-2012-3489 pattern)
void vulnerable_gets() {
    char buffer[100];
    printf("Enter some text: ");
    gets(buffer);  // Dangerous! No bounds checking
    printf("You entered: %s\n", buffer);
}

// Function 2: strcpy vulnerability (CVE-2019-9169 pattern)
void vulnerable_strcpy(char *input) {
    char buffer[50];
    strcpy(buffer, input);  // Dangerous! No size checking
    printf("Copied: %s\n", buffer);
}

// Function 3: sprintf vulnerability (CVE-2017-9047 pattern)
void vulnerable_sprintf(char *input) {
    char buffer[100];
    sprintf(buffer, "Hello %s", input);  // Dangerous if input is too long
    printf("Formatted: %s\n", buffer);
}

// Function 4: scanf vulnerability
void vulnerable_scanf() {
    char buffer[50];
    printf("Enter your name: ");
    scanf("%s", buffer);  // Dangerous! No width specifier
    printf("Hello %s\n", buffer);
}

// Function 5: strcat vulnerability (CVE-2018-16529 pattern)
void vulnerable_strcat(char *input) {
    char buffer[50] = "Prefix: ";
    strcat(buffer, input);  // Dangerous! No size checking
    printf("Result: %s\n", buffer);
}

// Function 6: memcpy vulnerability
void vulnerable_memcpy(char *input, int size) {
    char buffer[100];
    memcpy(buffer, input, size);  // Dangerous if size > 100
    printf("Copied %d bytes\n", size);
}

// Function 7: Format string vulnerability (CVE-2000-0573 pattern)
void vulnerable_printf(char *input) {
    printf(input);  // Dangerous! User input as format string
    printf("\n");
}

// Function 8: alloca vulnerability (CVE-2016-3706 pattern)
void vulnerable_alloca(int size) {
    char *buffer = alloca(size);  // Dangerous with user-controlled size
    memset(buffer, 'A', size);
    printf("Allocated %d bytes on stack\n", size);
}

// Main function to demonstrate vulnerabilities
int main(int argc, char *argv[]) {
    printf("=== Buffer Overflow Vulnerability Test Program ===\n");
    printf("This program contains intentional vulnerabilities for testing.\n");
    printf("DO NOT USE IN PRODUCTION!\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <test_number>\n", argv[0]);
        printf("Tests available:\n");
        printf("  1 - gets() vulnerability\n");
        printf("  2 - strcpy() vulnerability\n");
        printf("  3 - sprintf() vulnerability\n");
        printf("  4 - scanf() vulnerability\n");
        printf("  5 - strcat() vulnerability\n");
        printf("  6 - memcpy() vulnerability\n");
        printf("  7 - printf() format string vulnerability\n");
        printf("  8 - alloca() vulnerability\n");
        return 1;
    }
    
    int test_num = atoi(argv[1]);
    
    switch(test_num) {
        case 1:
            vulnerable_gets();
            break;
        case 2:
            if (argc > 2) vulnerable_strcpy(argv[2]);
            else printf("Need input for strcpy test\n");
            break;
        case 3:
            if (argc > 2) vulnerable_sprintf(argv[2]);
            else printf("Need input for sprintf test\n");
            break;
        case 4:
            vulnerable_scanf();
            break;
        case 5:
            if (argc > 2) vulnerable_strcat(argv[2]);
            else printf("Need input for strcat test\n");
            break;
        case 6:
            if (argc > 3) vulnerable_memcpy(argv[2], atoi(argv[3]));
            else printf("Need input and size for memcpy test\n");
            break;
        case 7:
            if (argc > 2) vulnerable_printf(argv[2]);
            else printf("Need input for printf test\n");
            break;
        case 8:
            if (argc > 2) vulnerable_alloca(atoi(argv[2]));
            else printf("Need size for alloca test\n");
            break;
        default:
            printf("Invalid test number\n");
            return 1;
    }
    
    return 0;
}
