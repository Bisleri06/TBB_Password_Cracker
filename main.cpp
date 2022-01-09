#include<tbb/tbb.h>
#include<tbb/blocked_range.h>
#include<tbb/parallel_for.h>
#include<tbb/task.h>
#include<crypt.h>
#include<iostream>
#include<vector>
#include<string>
#include<fstream>
using namespace std;
using namespace tbb;

#define VECTORSIZE 100000                               //PASSWORDS TO LOAD AT ONCE

int main(int argc,char *argv[])
{
  if(argc!=3)                                           //INVALID NO. OF ARGS
  {
    printf("\033[1;31m[+]Usage: %s wordlist hashfile\n",argv[0]);
    return 1;
  }


  vector<string> word_block(VECTORSIZE);                
  ifstream wordlist(argv[1]);
  ifstream hashfile(argv[2]);

  if(!wordlist.is_open() or !hashfile.is_open())
  {
    printf("\033[1;31m[-]Error opening files\n");
    return 1;
  }


  string target;                                        //PARSE THE HASH
  hashfile>>target;
  string salt=target.substr(0,target.rfind('$'));
  printf("\e[0m[*]\033[1;31mCracking hash %s\n",target.c_str());
  hashfile.close();

  wordlist.tie(0);
  ios_base::sync_with_stdio(false);
  bool flag=true;
  bool found_pass=false;
  

  while(flag)                                           //WHILE WORDLIST IS NOT EMPTY
  {
      int loaded_passwords=0;
      flag=false;


      while(wordlist and loaded_passwords<VECTORSIZE)                 //READ PASSWORDS
      {
        wordlist>>word_block[loaded_passwords];
        loaded_passwords++;
      }
      


      if(loaded_passwords==VECTORSIZE)                  //WORDLIST IS LARGER THAN BLOCKSIZE,
        flag=true;                                      //READ REMAINING HASHES IN NEXT ITER
      printf("\e[0m[+]\033[1;31mBlocksize loaded %d strings\n",loaded_passwords);

      
      //ONETBB MULTITHREADING CODE WITH LAMBDA FUNCTION TO ENCRYPT AND COMPARE PASSWORDS
      parallel_for(blocked_range<size_t>(0,loaded_passwords),[&](const blocked_range<size_t> &r){
      for(size_t i=r.begin();i!=r.end();++i)
      {
        
        //CRYPT_R IS THREADSAFE VERSION OF CRYPT
        struct crypt_data data;
        data.initialized=0;
        string crypted_pass=crypt_r(word_block[i].c_str(),salt.c_str(),&data);
        

        //printf(": %s %s\n",word_block[i].c_str(),crypted_pass.c_str());
        if(crypted_pass==target)
        {
          printf("\e[0m[+]\033[1;31mpassword is %s\n",word_block[i].c_str());
          found_pass=true;
          tbb::task::self().cancel_group_execution();     //TERMINATE ALL THREADS
        }


      }
      });    
  }

  if(!found_pass)
    printf("\e[0m[-]\033[1;31mHash not found\n");
  

  return 0;
}