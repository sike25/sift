to do 
1. no need to give server access to public key during key generation = done
2. implement window replay protection in login = done
3. edit readme = done

after implementation and testing is done
a. ensure debug and error messages leak nothing to attackers (remove all MTP error messages) 
>> NO, we should not do this. I just set self.debug to false. That is sufficient
b. more robust error handling in login.py? No need.
c. termination by client and server? without error messages?
d. clean up comments

I actually do not want to touch anything else, because it works
and if I break it, we have no way of testing it without 
the professor's code.

things i changed during debugging
1. pubkey
2. server ip

3. version number = correction, from 10 00 -> 01 00
4. starting sequence number, from 0 -> 1
5. message length, added mac and etk lengths
6. message sizes being expected in mtp should account for mac and etk lengths
7. mac length from 16 -> 12
8. increased the self.acceptance window from 2 to 20_000_000_000? Professor said I should?
