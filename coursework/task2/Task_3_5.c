#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <crypt.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

/******************************************************************************
  Demonstrates how to crack an encrypted password using a simple
  "brute force" algorithm. Works on passwords that consist only of 2 uppercase
  letters and a 2 digit integer.

  Compile with:
    cc -o CrackAZ99 CrackAZ99.c -lcrypt

  If you want to analyse the output then use the redirection operator to send
  output to a file that you can view using an editor or the less utility:
    ./CrackAZ99 > output.txt

  Dr Kevan Buckley, University of Wolverhampton, 2018 Modified by Dr. Ali Safaa 2019
******************************************************************************/

int count=0;     // A counter used to track the number of combinations explored so far

/**
 Required by lack of standard function in C.   
*/
int num_pwd = 1;

char *enc_pwd[]={
	"$6$AS$gydxgbfzLZ8qnaasLCaCniV.AK0Ja6yujS7Gn1O4439qlG6tROazbfcPJgkGc8/86CcKyjZcHEa16qvWIPgXF0"
};

void substr(char *dest, char *src, int start, int length){
  memcpy(dest, src + start, length);
  *(dest + length) = '\0';
}



void *kernel_function_1(void *salt_and_encrypted){
  int x, y, z;     // Loop counters
  char salt[7];    // String used in hashing the password. Need space for \0 // incase you have modified the salt value, then should modifiy the number accordingly
  char plain[7];   // The combination of letters currently being checked // Please modifiy the number when you enlarge the encrypted password.
  char *enc;       // Pointer to the encrypted password

  substr(salt, salt_and_encrypted, 0, 6);

  for(x='A'; x<='M'; x++){
    for(y='A'; y<='Z'; y++){
      for(z=0; z<=99; z++){
        sprintf(plain, "%c%c%02d", x, y, z); 
        enc = (char *) crypt(plain, salt);
        count++;
        if(strcmp(salt_and_encrypted, enc) == 0){
	    printf("Password found in #%-8d%s %s\n", count, plain, enc);
		
        }
      }
    }
  }
  pthread_exit(NULL);
}

void *kernel_function_2(void *salt_and_encrypted){
  int x, y, z;     // Loop counters
  char salt[7];    // String used in hashing the password. Need space for \0 // incase you have modified the salt value, then should modifiy the number accordingly
  char plain[7];   // The combination of letters currently being checked // Please modifiy the number when you enlarge the encrypted password.
  char *enc;       // Pointer to the encrypted password

  substr(salt, salt_and_encrypted, 0, 6);

  for(x='N'; x<='Z'; x++){
    for(y='A'; y<='Z'; y++){
      for(z=0; z<=99; z++){
        sprintf(plain, "%c%c%02d", x, y, z); 
        enc = (char *) crypt(plain, salt);
        count++;
        if(strcmp(salt_and_encrypted, enc) == 0){
	    printf("Password found in #%-8d%s %s\n", count, plain, enc);
        }
      }
    }
  }
  pthread_exit(NULL);
}


int time_difference(struct timespec *start, struct timespec *finish, long long int *diff){
	long long int ds = finish->tv_sec - start->tv_sec;
	long long int dn = finish->tv_nsec - start->tv_nsec;
	
	if (dn < 0){
		ds--;
		dn += 1000000000;
	}
	*diff = ds * 1000000000 + dn;
	return !(*diff>0);
}

int main(int argc, char *argv[]){
	int i;
	struct timespec start, finish;
	long long int time_spent;

	pthread_t thread_1, thread_2;
	int th1, th2;
	
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (int i=0; i<num_pwd; i++){
		th1 = pthread_create(&thread_1, NULL, kernel_function_1, (void *)enc_pwd[i]);
		if(th1){
			printf("Failed to create thread1: %d\n", th1);
		} 
	}
	for (int i=0; i<num_pwd; i++){
		th2 = pthread_create(&thread_2, NULL, kernel_function_2, (void *)enc_pwd[i]);
		if(th2){
			printf("Failed to create thread2: %d\n", th2);
		} 
	}
	pthread_join(thread_1, NULL);
	pthread_join(thread_2, NULL);
	
	clock_gettime(CLOCK_MONOTONIC, &finish);
	printf("%d solutions explored\n", count);
	time_difference(&start, &finish, &time_spent);
	printf("Spent time: %lldns\n", time_spent);

	pthread_exit(NULL);
}

