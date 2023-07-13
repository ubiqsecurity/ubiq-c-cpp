#pragma once

#include <string>
#include <list>

#if defined(__cplusplus)
extern "C" {
#endif

class Options {
  public:
      std::string infile;
      std::string credentials;
      std::string profile;
      bool print_errors;
      long max_avg_encrypt;
      long max_avg_decrypt;
      long max_total_encrypt;
      long max_total_decrypt;

  Options() :infile(""), credentials(""), profile(""), print_errors(false), 
    max_avg_encrypt(0L), max_avg_decrypt(0L), max_total_encrypt(0L), max_total_decrypt(0L) {

  }

} ;

class Data_rec {
  public: 
  std::string dataset_name;
  std::string plain_text;
  std::string cipher_text;

  Data_rec(
    std::string dataset_name,
    std::string plain_text,
    std::string cipher_text) :dataset_name(dataset_name), plain_text(plain_text), cipher_text(cipher_text){

    }
};

int
ubiq_getopt(
    const int argc, char * const argv[],
    Options & options);

int ubiq_load_datafile(
  std::string & infile,
  std::list<Data_rec> & data
);

#if defined(__cplusplus)
}
#endif
