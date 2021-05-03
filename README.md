# MatchUserPermissionstoFolder

This script was created as the result of needing to constantly check who has access to what folder, and through what groups. This script gets all groups a user is a part of (including nested groups) using a module I found [here](http://blog.tofte-it.dk/powershell-get-all-nested-groups-for-a-user-in-active-directory/) written by Alex Ø. T. Hansen, and loads them into a variable. It then goes through and gets all the groups on the folder you specify, and compares the two lists. If there's a match, it then maps out the nested chain that gives the user permissions.

You'll need to replace the DC=<DOMAIN>,DC=<DOMAIN> on line 140 and 141 with your domain before running the script. 
