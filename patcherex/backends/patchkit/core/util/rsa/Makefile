TARGET := test_c test_x86 test_x64 test_arm

all: $(TARGET)

test_c: test.c rsa.c key.c
	gcc -Wno-unused-result -DCONFIG_C_TEST -Os -o $@ test.c

test_x86: test.c rsa_x86.s key.c
	gcc -m32 -Wno-unused-result -Wno-implicit-function-declaration -Os -o $@ test.c rsa_x86.s

test_x64: test.c rsa_x64.s key.c
	gcc -Wno-unused-result -Wno-implicit-function-declaration -Os -o $@ test.c rsa_x64.s

test_arm: test.c key.c
	arm-linux-gnueabi-gcc -Wno-unused-result -DCONFIG_C_TEST -Os -o $@ test.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
