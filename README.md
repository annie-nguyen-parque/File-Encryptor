FileEncryptor.java is a file encrypt/decrypt program. 
On the command line, 
- the first parameter is "E" or "D" for encrypt or decrypt, respectively
- the second and third parameters are the input file and output file
- the fourth parameter is not a key, but a password or passphrase. If a passphrase which includes spaces is used, it must be surrounded by quotes to stop the shell parsing it as multiple parameters, e.g. "My Super Secret Passphrase".