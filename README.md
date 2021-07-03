# FairplayKSM

_C Bridging module for Fairplay Server_

## Setup instructions

First, you need the [FairPlay Streaming Server SDK v4.4](https://developer.apple.com/services-account/download?path=/Developer_Tools/FairPlay_Streaming_Server_SDK/FairPlay_Streaming_Server_SDK_4.4.zip) from Apple (Requires Developer Program Membership).

Place the `.h` files of the Reference Server Implementation into `include` and the `.c` files into `source` (ignoring SKDCredentials.h).

Then you have to go to the file `SKDServerUtils.c` and change line 480 to the following (inside method `SKDServerRSADecryptKey`):

```c
    pKeyBio = BIO_new_mem_buf((void *)pKeyPem, pKeyPem_s);
```

As a next step, delete both the functions `SKDServerFetchContentKeyAndIV()` and `SKDServerGetASK()` in the same file.

Then use the following commands:
```
cmake .
cmake --build .
sudo cmake --install .
```

The you can run `test.py` with `python3 test.py`

## Dependencies

You need at least OpenSSL and Python installed (`python3.9-dev libssl-dev` apt-packages)

## Options

### PS_DEBUG
By default, the KSM outputs lots of debug stuff. To disable, change `PS_DEBUG` to `0` in `SKDServerUtils.h`.

### Code-Docs
https://docs.python.org/3/extending/extending.html#compilation-and-linkage

## Usage

Place the following items in test_data:

`dev_private_key.pem`
`spc.bin`