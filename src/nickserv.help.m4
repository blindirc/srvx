changequote({,})
"<INDEX>" ("$b$N Help$b",
        "$b$N$b is a nickname and authentication service, intended to serve as a central authentication point for all other network services. $b$C$b, $b$O$b, and $b$G$b all depend on $b$N$b to verify that users are valid. The other component allows for ownership of a nickname, but is not necessarily enabled.",
	"$b$N$b command categories:",
	"  ACCOUNT    Account management.",
ifdef({/services/nickserv/disable_nicks},
{        "  NOT NICKSERV   A note on what this service does and does not do.",},
{        "  NICK       Nick management.",})
ifdef({/services/nickserv/email_enabled},
{        "  EMAIL      Email maintenance commands",})
	"  OTHERS     Other functions.",
        "  COMMANDS   A list of all available commands.");

"HANDLE" ("The term $uhandle$u from earlier versions was confusing to many new users.  Therefore, it has been changed to $uaccount$u.");

"ACCOUNT" ("Accounts are the way that $b$C$b identifies you for access to channels.  They are slightly similar to IRC nicks, but only have meaning to the services bots.  Until you authenticate to $b$N$b on an account, you can only use the $bREGISTER$b and $bAUTH$b commands.",
        "Account management commands are:",
        "  REGISTER   Register a new account.",
        "  AUTH       Authenticate yourself to $b$N$b using an existing account.",
        "  PASS       Change your account's password.",
        "  ADDMASK    Add a hostmask to your account.",
        "  DELMASK    Remove a hostmask from your account.",
        "  SET        Set per-account options.",
        "  UNREGISTER Unregister an account.",
        "  RENAME     Renames an account",
ifdef({/services/nickserv/enable_ghost},
{        "  GHOST      Disconnects your old clients",})
        "  ACCOUNT FLAGS Definition for each account flag");

ifdef({/services/nickserv/disable_nicks},
{"NOT NICKSERV" ("$bNOT NICKSERV$b",
        "This $b$N$b is not a standard NickServ.",
        "Most NickServs provide \"nick ownership\", and will either issue a /KILL or a forced nick change if you try to use a registered nick without providing the password.",
        "This $b$N$b will not do this.  It only allows you to register an $baccount$b, which identifies users to $b$C$b.  In a way, it is a virtual nick.  When you authenticate to $b$N$b, it does not care what your IRC nick is -- only account you are logged in as.",
        "$b$N$b can tell you what account a user is authenticated to using the $bUSERINFO$b command.  Any problems with account registration or $b$N$b should be directed to the normal support channel.");

"OUNREGISTER" ("/msg $N OUNREGISTER <nick|*account>",
        "Un-registers the specified account.",
        "You may use *Account instead of Nick as the name argument; the * makes $N use the name of an account directly (useful if the user is not online).",
        "$uSee Also:$u oregister");

"UNREGISTER" ("/msg $N@$s UNREGISTER <password>",
        "Un-registers the account you are authenticated as.",
        "$uSee Also:$u register");},
{"NICK" ("You may register IRC nicknames to be associated with your accounts, and will be able to request a KILL for anyone using a nickname registered to you.",
	"Nick management commands are:",
        "  NICKINFO   Find out who has registered a nick.",
        "  REGNICK    Register a nickname.",
        "  UNREGNICK  Unregister a nickname.",
        "  RECLAIM    Reclaim a nick registered to you.");

"NICKINFO" ("/msg $N NICKINFO <nick>",
        "Displays information on the nick specified.",
        "$uSee Also:$u accountinfo, userinfo");

"REGNICK" ("/msg $N REGNICK ",
        "Registers your current nick to the account you are authenticated to.",
        "$uSee Also:$u register, unregister, unregnick");

"OUNREGISTER" ("/msg $N OUNREGISTER <nick|*account>",
        "Un-registers the specified account, and any nicks that have been registered to that account.",
        "You may use *Account instead of Nick as the name argument; the * makes $N use the name of an account directly (useful if the user is not online).",
        "$uSee Also:$u oregister, oregnick, ounregnick");

"OREGNICK" ("/msg $N OREGNICK [<nick|*account> <nick>]",
        "Registers specified nick to the specified account. If nick and account are not specified, then $boregnick$b registers your current nick to the account you are authenticated to.",
        "You may use *Account instead of Nick as the name argument; the * makes $N use the name of an account directly (useful if the user is not online).",
        "$uSee Also:$u oregister, ounregister, ounregnick");

"OUNREGNICK" ("/msg $N OUNREGNICK <nick>",
        "Un-registers a nick that was previously registered to an account.",
        "$uSee Also:$u oregister, oregnick, ounregister");

"UNREGISTER" ("/msg $N@$s UNREGISTER <password>",
        "Un-registers the account you are authenticated with, and any nicks that have been registered to that account.",
        "$uSee Also:$u register, regnick, unregnick");

"UNREGNICK" ("/msg $N UNREGNICK [nick]",
        "Un-registers a nick that was previously registered to your account.  If you do not specify a nick, your current nick will be un-registered.",
        "$uSee Also:$u register, regnick, unregister");

"RECLAIM" ("/msg $N RECLAIM <nick>",
        "Reclaims the specified nick. You must be authenticated to the account that registered the nick.",
        "Depending on configuration, this may do nothing, may ask the user nicely, may force a nick change on them, or may /KILL (disconnect) the target user.");})

ifdef({/services/nickserv/email_enabled},
{"EMAIL" ("Email-based maintenance commands and topics are:",
        "  AUTHCOOKIE Email a cookie to allow you to authenticate (auth) without a matching hostmask.",
        "  RESETPASS  Request a password change if you forgot your old password.",
        "  COOKIE     Complete an email-based maintenance action.",
        "  DELCOOKIE  For AUTHCOOKIE or RESETPASS, cancel the requested cookie.",
        "  EMAIL POLICY  This network's policy on account email addresses.");

"AUTHCOOKIE" ("/msg $N AUTHCOOKIE <account>",
        "Requests that $N send you email with a cookie that allows you to auth to your account if you do not have a matching hostmask.  (For example, if your ISP changed your IP or hostname.)",
        "Once you receive the cookie in email, you can use the $bcookie$b command to log in.",
        "$uSee Also:$u cookie, delcookie");

"RESETPASS" ("/msg $N@$s RESETPASS <account> <newpassword>",
        "Requests that $N send you email with a cookie that will change your password (in case you have forgotten it).  Once you receive the cookie in email, use the $bcookie$b command to actually change your password.",
        "$bYour password will not be changed, and you will not be able to use it to log in, until you confirm the change using the $ucookie$u command.$b",
        "$uSee Also:$u cookie, delcookie");

"DELCOOKIE" ("/msg $N DELCOOKIE",
        "Requests that $N cancel your authcookie or resetpass cookie.",
        "(Since set-email cookies and registration cookies send email to unverified addresses, to prevent mail flooding, they cannot be cancelled.)",
        "$uSee Also:$u authcookie, resetpass, cookie");

"COOKIE" ("/msg $N@$s COOKIE <account> <cookie>",
        "Completes the maintenance action (for example, activating an account or changing your password) for which a cookie was issued.  The cookie will then be forgotten.",
        "$uSee Also:$u authcookie, resetpass, set, delcookie");

"EMAIL POLICY" ("$bEMAIL POLICY",
        "FooNET has utmost respect for the privacy of its users.  We will submit your email address to as many spam databases as we can find, and we will even post it on our web site.",
        "(No, not really.  It looks like somebody forgot to edit nickserv.help or nickserv.help.m4 to remove this entry.  Make sure they edit the mail section of srvx.conf while they are at it.)");})

"OTHERS" ("Other commands are:",
        "  USERINFO    Displays the account a user is authenticated to.",
        "  ACCOUNTINFO Displays information about an account.",
        "  VERSION     $b$N$b version information.",
        "  STATUS      $b$N$b status.",
        "  SEARCH      Search for accounts by various criteria.",
        "  MERGE       Merge one account into another.",
        "  MERGEDB     Load a database into memory.",
        "  HELP        Get help on $b$N$b.");

"ADDMASK" ("/msg $N ADDMASK [user@host]",
        "Adds the specified user@host to the account you are authenticated to with $b$N$b.  If no mask is given, it uses your current mask.",
        "$uSee Also:$u auth, delmask");
"ALLOWAUTH" ("/msg $N ALLOWAUTH <nick> [account] [STAFF]",
        "Allows the specified nick to $bauth$b to the specified account. $bAllowauth$b does NOT add the hostmask of that nick to the specified account.",
        "If no account is given, it will cancel the allowauth for the user (assuming the user has an allowauth).",
        "If the account is marked as a helper or oper, the STAFF qualifier must be given afterwards.  This reduces social engineering attacks.",
        "$uSee Also:$u addmask, auth");
"AUTH" ("/msg $N@$s AUTH [account] <password>",
        "Authenticates yourself with $b$N$b to the specified account. You must use $bauth$b before you have any access to network services, including channels that are registered with $b$C$b.",
        "If you omit the account, it uses your current nick as your account name.",
ifdef({/services/nickserv/email_enabled},
{        "$uSee Also:$u pass, resetpass, authcookie"},
{        "$uSee Also:$u pass"})
);
"DELMASK" ("/msg $N DELMASK <user@host>",
        "Removes a hostmask from the account you are authenticated on.",
        "An account must have at least one hostmask; you cannot remove the last mask for an account.",
        "$uSee Also:$u addmask");
"ACCOUNTINFO" ("/msg $N ACCOUNTINFO <nick|*account>",
        "Displays infomation on the specified account, including the date the account was registered, the last time that person was seen, the account's $b$N$b info, its flags, its hostmask(s), its channels, and the account's current nickname.",
        "You may use *Account instead of Nick as the name argument; the * makes $N use the name of an account directly (useful if the user is not online).",
ifdef({/services/nickserv/disable_nicks},
{        "$uSee Also:$u userinfo, account flags"},
{        "$uSee Also:$u nickinfo, userinfo, account flags"}));
"ACCOUNT FLAGS" ("$bACCOUNT FLAGS$b",
        "The following flags on accounts are defined:",
        "$bS$b  $O access suspended",
        "$bp$b  Use PRIVMSG for messages rather than NOTICE",
        "$bh$b  User is a support helper (must be in support channel to override security)",
        "$bH$b  User is a network helper (can toggle security override)",
        "$bg$b  God mode (security override for IRC staff)",
        "$bs$b  Account suspended",
        "$bc$b  Use mIRC color codes in responses",
        "$bf$b  Account frozen/on vacation (will not be unregistered for inactivity; cleared when account is authenticated against)",
        "$bn$b  No-delete (will never be unregistered for inactivity)",
        "$uSee Also:$u accountinfo, set");
"OADDMASK" ("/msg $N OADDMASK <nick|*account> <user@host>",
        "Adds a hostmask to the specified account.",
        "You may use *Account instead of Nick as the name argument; the * makes $N use the name of an account directly (useful if the user is not online).",
        "$uSee Also:$u odelmask");
"ODELMASK" ("/msg $N ODELMASK <nick|*account> <user@host>",
        "Removes a hostmask from the specified account.",
        "An account must have at least one hostmask; you cannot remove the last mask for an account.",
        "You may use *Account instead of Nick as the name argument; the * makes $N use the name of an account directly (useful if the user is not online).",
        "$uSee Also:$u oaddmask");
"OREGISTER" ("/msg $N@$s OREGISTER <account> <password> <user@host|nick>",
        "Registers an account with $b$N$b using the specified account, password, and user@host. If then nick of an online user is specified, then that user's user@host is used.",
ifdef({/services/nickserv/disable_nicks},
{        "$uSee Also:$u ounregister"},
{        "$uSee Also:$u oregnick, ounregister, ounregnick"}));
"OSET" ("/msg $N OSET <nick|*account> [<setting> <value>]",
        "Changes an account's settings for srvx. In addition to the normal $bset$b settings, you may set:",
        "$bPASSWORD$b: Sets user's password.",
        "$bFLAGS$b: Changes account flags for user.",
        "$bLEVEL$b: Sets $O access level.",
        "$bEPITHET$b: The description $C shows for the user's access.",
        "You may use *Account instead of Nick as the name argument; the * makes $N use the name of an account directly (useful if the user is not online).",
ifdef({/services/nickserv/disable_nicks},
{        "$uSee Also:$u accountinfo, account flags, set, userinfo"},
{        "$uSee Also:$u accountinfo, account flags, nickinfo, set, userinfo"}));
"PASS" ("/msg $N@$s PASS <oldpass> <newpass>",
        "Changes your $b$N$b password.",
        "$uSee Also:$u auth");
"REGISTER" (
ifdef({/services/nickserv/email_enabled},
{ifdef({/services/nickserv/email_required},
{        "/msg $N@$s REGISTER <account> <password> <email>",},
{        "/msg $N@$s REGISTER <account> <password> [email]",})},
{        "/msg $N@$s REGISTER <account> <password>",})
        "Registers a specified account with $b$N$b, adding your current user@host to your new account. You will be required to know the password you specify with $bregister$b in order to be able to use $bauth$b to authenticate to your account.",
ifdef({/services/nickserv/email_enabled},
{ifdef({/services/nickserv/email_required},
{        "An email will be sent to the email address you give containing a cookie that will let you activate your account.  Once you have that cookie, you must use the $bcookie$b command to be able to use your account.",},
{        "If you specify an email address, an email will be sent to it containing a cookie that will let you activate your account.  Once you have that cookie, you must use the $bcookie$b command to be able to use your account.",})})
        "NOTE: It is strongly recommended that you use the long form ($N@$s) rather than just nick ($N) for this command, to protect against impersonators on other networks.",
ifdef({/services/nickserv/disable_nicks},
{        "$uSee Also:$u auth, unregister"},
{        "$uSee Also:$u auth, regnick, unregister, unregnick"}));
"SET" ("/msg $N SET [<setting> [value]]",
        "Changes your account settings for srvx. Settings are:",
        "$bANNOUNCEMENTS$b: Indicates whether you wish to receive community announcements via the $G service.",
        "$bCOLOR$b: If set, $b$N$b and $b$C$b will use $bbold$b and $uunderlines$u in text they send you.",
ifdef({/services/nickserv/email_enabled},
{        "$bEMAIL$b: Sets (or changes) your email address.",})
        "$bINFO$b:  Your infoline for $b$N$b (which can be viewed with the $baccountinfo$b command).",
        "$bLANGUAGE$b: Your preferred language for private messages from the services.",
        "$bPRIVMSG$b: If set, $b$N$b and $b$C$b will send text to you using PRIVMSGs rather than NOTICEs.",
        "$bSTYLE$b: The style you want srvx to use for channel userlists it sends you. $bSTYLE$b can be either $bDef$b (default) or $bZoot$b.",
        "$bTABLEWIDTH$b: Sets the width for wrapping table-formatted text. (Use 0 for the default.)",
        "$bWIDTH$b: The width you want srvx to wrap text it sends you.  (Use 0 for the default.)",
        "$bMAXLOGINS$b: The number of users that can log into your account at once.  (Use 0 for the default.)",
        "$bset$b with no arguments returns your current settings.",
ifdef({/services/nickserv/disable_nicks},
{        "$uSee Also:$u accountinfo, userinfo"},
{        "$uSee Also:$u accountinfo, nickinfo, userinfo"}));
"STATUS" ("/msg $N STATUS",
ifdef({/services/nickserv/disable_nicks},
{        "Displays information about the status of $b$N$b, including the total number of accounts in its database."},
{        "Displays information about the status of $b$N$b, including the total number of accounts and nicks that are registered in its database, and how many nicks are registered to your account (if you are authenticated to one)."}));
"USERINFO" ("/msg $N USERINFO <nick>",
        "Shows what account the nick specified is authenticated to.",
        "$uSee Also:$u auth, accountinfo");
"VERSION" ("/msg $N VERSION",
        "Sends you the srvx version and some additional version information that is specific to $b$N$b.");
"GHOST" ("/msg $N GHOST <nick>",
        "This disconnects an old client that is authed to your account.  This is $bnot$b the same thing as nick ownership; the user $bmust$b be authenticated to the same account you are.",
        "$uSee Also:$u auth");
"RENAME" ("/msg $N RENAME <nick|*old-account> <new-account>",
        "Renames an account.",
        "This command is only accessible to helpers and IRC operators.",
        "$uSee Also:$u merge");
"VACATION" ("/msg $N VACATION",
        "Marks your account as \"on vacation\" until the next time you authenticate to $N.",
        "While you are \"on vacation\", your account will not be deleted for inactivity.");
"SEARCH" ("/msg $N SEARCH <action> <criteria> <value> [<criteria> <value>]...",
        "Searches for accounts matching the critera, and then does something to them.",
        "$uSee Also:$u search action, search criteria");
"SEARCH ACTION" ("$bSEARCH ACTION$b",
        "The following actions are valid:",
        "  PRINT      - Print matching accounts",
        "  COUNT      - Count matching accounts",
        "  UNREGISTER - Unregister matching accounts",
        "$uSee Also:$u search, search criteria");
"SEARCH CRITERIA" ("$bSEARCH CRITERIA$b",
        "The following account search criteria are valid.  Each takes an additional argument, giving the actual criteria:",
        "  LIMIT      - Limits the number of matches",
        "  FLAGS      - Bits that must be turned on (e.g. +h) and/or off (e.g. -S) in an account",
        "  REGISTERED - Registered time constraint (<Nu, <=Nu, =Nu, >=Nu or >Nu)",
        "  SEEN       - Accounts not seen for at least this long",
        "  ACCOUNTMASK - A glob that must match the account name",
        "  EMAIL      - A glob that must match the account's email address",
ifdef({/services/nickserv/disable_nicks},,
{        "  NICKMASK   - A glob that must match a nick registered to the account",})
        "  HOSTMASK SUPERSET - Account matches if someone with this hostmask can auth to the account",
        "  HOSTMASK EXACT - Account matches if this exact hostmask is in list",
        "  HOSTMASK SUBSET - Account matches if this mask \"covers\" one in their userlist",
        "  HOSTMASK   - A glob that must match a hostmask for the account (equivalent to HOSTMASK SUPERSET)",
        "  ACCESS     - An $O access constraint (<nnn, <=nnn, =nnn, >=nnn or >nnn)",
        "$uSee Also:$u search, search action");
"MERGE" ("/msg $N MERGE <from-nick|*from-account> <to-nick|*to-account>",
        "Merge access from $bfrom-account$b into $bto-account$b.  This includes hostmasks, registered nicks, authed users, access in channels, and OpServ access (if any).  If $bto-account$b has equal  or greater access than $bfrom-account$b (or more a general hostmask, etc), $bto-account$b keeps that information.",
        "This command is only accessible to helpers and IRC operators.",
        "$uSee Also:$u rename");
"MERGEDB" ("/msg $N MERGE <dbfilename>",
        "Merge contents of $bdbfilename$b into in-memory database.  Any accounts in both will be $bOVERWRITTEN$b with the information from $bdbfilename$b, although authed users will be authed to the new account.",
        "This command is only accessible to IRC operators.",
        "$uSee Also:$u write");
