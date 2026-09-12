#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
extern int decompress_kle_bounded(uint8_t *, int, uint8_t *, int, int);
int main(void) {
 uint8_t input[128], output[512];
 for (int i=0;i<2000;i++) {
  for(int j=0;j<128;j++) input[j]=rand();
  int size=i%128;
  int result=decompress_kle_bounded(output,512,input,size,i%2);
  assert(result<=512);
 }
 uint8_t raw[]={0x80,0,0,0,3,'a','b','c'};
 assert(decompress_kle_bounded(output,512,raw,8,1)==3);
 assert(memcmp(output,"abc",3)==0);
 assert(decompress_kle_bounded(output,512,raw,7,1)<0);
 assert(decompress_kle_bounded(output,2,raw,8,1)<0);
}
