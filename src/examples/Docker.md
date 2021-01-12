# Dockerized C/C++ Samples

The Ubiq samples for the C and C++ libraries are provided in a pre-built
Docker container that you can use to test out the software without building
or installing it. You'll need to have docker which is available for all major
Linux distributions installed on your system. Note that root permissions may
be required to run docker on your system. In that case, you'll need to prefix
the commands below with `sudo` or change to the root user prior to using the
commands.

All of the examples below use the `ubiq_sample-c` command, but they can be
replaced with `ubiq_sample-c++`.

## View the C/C++ sample help output

To learn about the options associated with the sample application use the `-h`
command line argument. (Note that the `--rm` flag is passed to docker to
automatically remove the container when it exits.)

```shell
$ docker run -it --rm ubiqsecurity/ubiq-c-cpp-sample ubiq_sample-c -h
Usage: ubiq_sample-c -e|-d -s|-p -i INFILE -o OUTFILE
Encrypt or decrypt files using the Ubiq service

  -h                       Show this help message and exit
  -V                       Show program's version number and exit
  -e                       Encrypt the contents of the input file and write
                             the results to the output file
  -d                       Decrypt the contents of the input file and write
                             the results to the output file
  -s                       Use the simple encryption / decryption interfaces
  -p                       Use the piecewise encryption / decryption interfaces
  -i INFILE                Set input file name
  -o OUTFILE               Set output file name
  -c CREDENTIALS           Set the file name with the API credentials
                             (default: ~/.ubiq/credentials)
  -P PROFILE               Identify the profile within the credentials file
```

## Encrypting and Decrypting Data

There are no credentials or other "scratch" files in the container image to
facilitate encryption or decryption, so you'll need to create an empty
directory on your host system that can be used to store these files and to
mount into the container.

Start by creating an empty directory and changing to it:
```shell
$ mkdir ubiq_sample
$ cd ubiq_sample
```

Next, create a file named `credentials` in this directory and populate it as
described [here][1].

Finally, you'll need a file that can be used to test the encryption. You can
copy a file to your newly created directory for this purpose or you can
create one using the following command:
```shell
$ dd if=/dev/urandom of=plaintext bs=1024 count=1024
```

### Encryption

Assuming our input file is named `plaintext`, we can use the following
command to encrypt it using the Ubiq service:
```shell
$ docker run -it --rm -v $(pwd):$(pwd) ubiqsecurity/ubiq-c-cpp-sample ubiq_sample-c -i $(pwd)/plaintext -o $(pwd)/ciphertext -c $(pwd)/credentials -s -e
$ ls -log
total 2056
-rw-r--r-- 1 1049318 Jan 12 10:19 ciphertext
-rw-r--r-- 1     961 Jan 12 09:49 credentials
-rw-r--r-- 1 1048576 Jan 12 09:14 plaintext
```

### Decryption

Now, decrypt the ciphertext:
```shell
$ docker run -it --rm -v $(pwd):$(pwd) ubiqsecurity/ubiq-c-cpp-sample ubiq_sample-c -i $(pwd)/ciphertext -o $(pwd)/recovered -c $(pwd)/credentials -s -d
$ ls -log
total 3080
-rw-r--r-- 1 1049318 Jan 12 10:19 ciphertext
-rw-r--r-- 1     961 Jan 12 09:49 credentials
-rw-r--r-- 1 1048576 Jan 12 09:14 plaintext
-rw-r--r-- 1 1048576 Jan 12 10:25 recovered
```

[1]: https://dev.ubiqsecurity.com/docs/using-api-key-credentials#credentials-file-format
