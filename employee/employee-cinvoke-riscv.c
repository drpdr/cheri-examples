#include "../include/common.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>

struct cheri_object
{
	void *__capability codecap;
	void *__capability datacap;
};

void print_salary(uint8_t salary);
void invoke_riscv(struct cheri_object * pair);

int main()
{

	// Request special capability `sealcap` from the operating system
	// in order to use it as key to seal `new_small_salary`
	void *__capability sealcap;
	size_t sealcap_size = sizeof(sealcap);
	if (sysctlbyname("security.cheri.sealcap", &sealcap, &sealcap_size, NULL, 0) < 0)
	{
		error("Fatal error. Cannot get `securiy.cheri.sealcap`.");
		exit(1);
	}
	assert(cheri_perms_get(sealcap) & CHERI_PERM_SEAL);
	uint8_t *new_small_salary;

	// Seal `new_small_salary` using previously requested `sealcap`
	new_small_salary = (uint8_t *) malloc(sizeof(uint8_t));
	new_small_salary = (uint8_t *) cheri_seal(new_small_salary, sealcap);
	assert(cheri_is_sealed(new_small_salary));
	// Seal `print_details` using previously requested `sealcap`
	void (*codecap)(uint8_t) = (void (*)(uint8_t)) cheri_seal(&print_salary, sealcap);
	assert(cheri_is_sealed(codecap));
	struct cheri_object * obj;
	obj->codecap = codecap;
	obj->datacap = new_small_salary;
	
	invoke_riscv(obj);
	return 0;
}

inline void invoke_riscv(struct cheri_object * pair){
	// Function pointer (print_salary) for CS1
	void (*codecap)(void) =  pair->codecap;
	// Data for the function
	uint8_t * datacap = (uint8_t *) pair->datacap;

	// FIXME: mv requires output regs!
	__asm__(
		"mv %%cs1, %0\n"
		"mv %%cs1, %1\n"
		: /* output variable list */
		:"r" (codecap), "r" (datacap)
		: /* clobbered registers */
	);
	__asm__(
		"cinvoke %%cs1, %%cs2 \n"
		:
		:
		:
	);
}

void print_salary(uint8_t salary){
	printf("Salary: %d", salary);
	fflush(stdout);	
}


