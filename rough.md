The secret key intended for MTP is derived from random numbers that the client and the server exchange in the Login Protocol. 

to do 
1. no need to give server access to public key during key generation 
2. implement key derivation

after implementation and testing is done
a. ensure debug and error messages leak nothing to attackers (remove all MTP error messages)
b. more robust error handling?

