TOKEN BUILD NOTES
====================

1. Create token deployment address
  * Open console
  * Type `getnewaddress MyNewToken`
2. Create token collateral
  * Open console
  * Type `sendtoaddress *address generated in step 1* 1`
  * Wait 6 confirmations
3. Creating token
  * Open console
  * Type `newtoken MyToken MTC 1000000 *address generated in step 1*`
  * If your token deployed without errors result of execution this command - id of your new token
