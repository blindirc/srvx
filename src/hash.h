/* hash.h - IRC network state database
 * Copyright 2000-2006 srvx Development Team
 *
 * This file is part of srvx.
 *
 * srvx is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with srvx; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#ifndef HASH_H
#define HASH_H

#include "common.h"
#include "dict.h"
#include "policer.h"

#define MODE_CHANOP         (1<<0) /* +o USER */
#define MODE_VOICE          (1<<1) /* +v USER */
#define MODE_PRIVATE        (1<<2) /* +p */
#define MODE_SECRET         (1<<3) /* +s */
#define MODE_MODERATED      (1<<4) /* +m */
#define MODE_TOPICLIMIT     (1<<5) /* +t */
#define MODE_INVITEONLY     (1<<6) /* +i */
#define MODE_NOPRIVMSGS     (1<<7) /* +n */
#define MODE_KEY            (1<<8) /* +k KEY */
#define MODE_BAN            (1<<9) /* +b BAN */
#define MODE_LIMIT          (1<<10) /* +l LIMIT */
#define MODE_DELAYJOINS     (1<<11) /* +D */
#define MODE_REGONLY        (1<<12) /* ircu +r, Bahamut +R */
#define MODE_NOCOLORS       (1<<13) /* +c */
#define MODE_NOCTCPS        (1<<14) /* +C */
#define MODE_REGISTERED     (1<<15) /* Bahamut +r */
#define MODE_APASS          (1<<16) /* +A adminpass */
#define MODE_UPASS          (1<<17) /* +U userpass */
#define MODE_FREEINVITE     (1<<18) /* +g (charybdis) free to invite */
#define MODE_OPMODERATED    (1<<19) /* +z (charybdis) op moderated */
#define MODE_LARGEBANLIST   (1<<20) /* +L (charybdis) large ban list */
#define MODE_PERMINANT      (1<<21) /* +P (charybdis) perminant */
#define MODE_FREETARGET     (1<<22) /* +F (charybdis) free target */
#define MODE_DISABLEFORWARD (1<<23) /* +Q (charybdis) disable forwarding */
#define MODE_FORWARDCHAN    (1<<24) /* +f (charybdis) forward with channel */
#define MODE_JOINTRHOTTLE   (1<<25) /* +j (charybdis) join throttle count:time */
#define MODE_QUIET          (1<<26) /* +q (charybdis) quiet */
#define MODE_EXEMPT         (1<<27) /* +e (charybdis) exempt even if under +b or +q */
#define MODE_INVEX          (1<<28) /* +I (charybdis) Invite exempt; join +i without /invite via masking */
#define MODE_REMOVE         (1<<31)

#define FLAGS_OPER          (1<<0) /* global operator +o */
#define FLAGS_INVISIBLE     (1<<2) /* invisible +i */
#define FLAGS_WALLOP        (1<<3) /* receives wallops +w */
#define FLAGS_DEAF          (1<<5) /* deaf +d */
#define FLAGS_SERVICE       (1<<6) /* cannot be kicked, killed or deoped +k */
#define FLAGS_GLOBAL        (1<<7) /* receives global messages +g */
#define FLAGS_NOCHAN        (1<<8) /* hide channels in whois +n */
#define FLAGS_PERSISTENT    (1<<9) /* for reserved nicks, this isn't just one-shot */
#define FLAGS_GAGGED        (1<<10) /* for gagged users */
#define FLAGS_AWAY          (1<<11) /* for away users */
#define FLAGS_STAMPED       (1<<12) /* for users who have been stamped */
#define FLAGS_HIDDEN_HOST   (1<<13) /* user's host is masked by their account */
#define FLAGS_REGNICK       (1<<14) /* user owns their current nick */
#define FLAGS_REGISTERING   (1<<15) /* user has issued account register command, is waiting for email cookie */
#define FLAGS_DUMMY         (1<<16) /* user is not announced to other servers */
#define FLAGS_NOIDLE        (1<<17) /* hide idle time in whois +I */
#define FLAGS_CALLERID      (1<<18) /* caller ID mode */
#define FLAGS_HCLOACK       (1<<19) /* host cloak (charybdis module) */
#define FLAGS_ADMIN         (1<<20) /* server admin +a, maybe do some fancy stuff with this in the future? */
#define FLAGS_LOCOP         (1<<21) /* locops (local wallops) */
#define FLAGS_SNOTICE       (1<<22) /* can see server notices (snomask) */
#define FLAGS_OPERWALL      (1<<23) /* can see operwalls */
#define FLAGS_NOFOWARD      (1<<24) /* is not afffected by channel forwarding */
#define FLAGS_NOUNAUTHMSG   (1<<25) /* prevents unidentified users from messaging target */
#define FLAGS_ISSSL         (1<<26) /* user is connected via SSL */

#define IsOper(x)               ((x)->modes & FLAGS_OPER)
#define IsService(x)            ((x)->modes & FLAGS_SERVICE)
#define IsDeaf(x)               ((x)->modes & FLAGS_DEAF)
#define IsInvisible(x)          ((x)->modes & FLAGS_INVISIBLE)
#define IsGlobal(x)             ((x)->modes & FLAGS_GLOBAL)
#define IsNoChan(x)             ((x)->modes & FLAGS_NOCHAN)
#define IsWallOp(x)             ((x)->modes & FLAGS_WALLOP)
#define IsGagged(x)             ((x)->modes & FLAGS_GAGGED)
#define IsPersistent(x)         ((x)->modes & FLAGS_PERSISTENT)
#define IsAway(x)               ((x)->modes & FLAGS_AWAY)
#define IsStamped(x)            ((x)->modes & FLAGS_STAMPED)
#define IsHiddenHost(x)         ((x)->modes & FLAGS_HIDDEN_HOST)
#define IsReggedNick(x)         ((x)->modes & FLAGS_REGNICK)
#define IsRegistering(x)        ((x)->modes & FLAGS_REGISTERING)
#define IsDummy(x)              ((x)->modes & FLAGS_DUMMY)
#define IsNoIdle(x)             ((x)->modes & FLAGS_NOIDLE)
#define IsCallerID(x)           ((x)->modes & FLAGS_CALLERID)
#define IsCloaked(x)            ((x)->modes & FLAGS_HCLOACK)
#define IsAdmin(x)              ((x)->modes & FLAGS_ADMIN)
#define IsLocOp(x)              ((x)->modes & FLAGS_LOCOP)
#define IsSnotice(x)            ((x)->modes & FLAGS_SNOTICE)
#define IsOperwall(x)           ((x)->modes & FLAGS_OPERWALL)
#define IsNoForward(x)          ((x)->modes & FLAGS_NOFOWARD)
#define IsNoUnauth(x)           ((x)->modes & FLAGS_NOUNAUTHMSG)
#define IsSSL(x)                ((x)->modes & FLAGS_ISSSL)
#define IsFakeHost(x)           ((x)->fakehost[0] != '\0')
#define IsFakeIdent(x)          ((x)->fakeident[0] != '\0')
#define IsLocal(x)              ((x)->uplink == self)

#define NICKLEN         30
#define USERLEN         10
#define HOSTLEN         63
#define REALLEN         50
#define TOPICLEN        250
#define CHANNELLEN      200
#define MAXOPLEVEL      999

#define MAXMODEPARAMS   6
#define MAXBANS         45

/* IDLEN is 6 because it takes 5.33 Base64 digits to store 32 bytes. */
#define IDLEN           6

DECLARE_LIST(userList, struct userNode*);
DECLARE_LIST(modeList, struct modeNode*);
DECLARE_LIST(banList, struct banNode*);
DECLARE_LIST(quietList, struct quietNode*);
DECLARE_LIST(exemptList, struct exemptNode*);
DECLARE_LIST(invexList, struct invexNode*);
DECLARE_LIST(channelList, struct chanNode*);
DECLARE_LIST(serverList, struct server*);

struct userNode {
    char *nick;                   /* Unique name of the client, nick or host */
    char ident[USERLEN + 1];      /* Per-host identification for user */
    char info[REALLEN + 1];       /* Free form additional client information */
    char hostname[HOSTLEN + 1];   /* DNS name or IP address */
    char fakehost[HOSTLEN + 1];   /* Assigned fake host */
    char fakeident[USERLEN + 1];  /* Assigned fake ident */
#ifdef WITH_PROTOCOL_P10
    char *numeric[COMBO_NUMERIC_LEN+1];
    unsigned int num_local : 18;
#endif
#ifdef WITH_PROTOCOL_TS6
    char *numeric[UID_NUMERIC_LEN+1];
    unsigned int num_local : 18;
#endif
    unsigned int dead : 1;        /* Is user waiting to be recycled? */
    irc_in_addr_t ip;             /* User's IP address */
    long modes;                   /* user flags +isw etc... */

    unsigned long   timestamp;    /* Time of last nick change */
    unsigned long   idle_since;   /* Last time user did something on or to a channel */
    struct server   *uplink;      /* Server that user is connected to */
    struct modeList channels;     /* Vector of channels user is in */

    /* from nickserv */
    struct handle_info *handle_info;
    struct userNode *next_authed;
    struct policer auth_policer;
};

struct chanNode {
    chan_mode_t modes;
    unsigned int limit;
    unsigned int locks;
    char key[KEYLEN + 1];
    char upass[KEYLEN + 1];
    char apass[KEYLEN + 1];
    unsigned long timestamp; /* creation time */

    char topic[TOPICLEN + 1];
    char topic_nick[NICKLEN + 1];
    unsigned long topic_time;

    struct modeList members;
    struct banList banlist;
    struct quietList quietlist;
    struct exemptList exemptlist;
    struct invexList invexlist;
    struct policer join_policer;
    unsigned int join_flooded : 1;
    unsigned int bad_channel : 1;

    struct chanData *channel_info;
    struct channel_help *channel_help;
    char name[1];
};

struct banNode {
    char ban[NICKLEN + USERLEN + HOSTLEN + 3]; /* 1 for '\0', 1 for ! and 1 for @ = 3 */
    char who[NICKLEN + 1]; /* who set the ban */
    unsigned long set; /* time ban was set */
};

struct quietNode {
    char quiet[NICKLEN + USERLEN + HOSTLEN + 3]; /* 1 for '\0', 1 for ! and 1 for @ = 3 */
    char who[NICKLEN + 1]; /* who set the quiet */
    unsigned long set; /* time quiet was set */
};

struct exemptNode {
    char exempt[NICKLEN + USERLEN + HOSTLEN + 3]; /* 1 for '\0', 1 for ! and 1 for @ = 3 */
    char who[NICKLEN + 1]; /* who set the exempt */
    unsigned long set; /* time exempt was set */
};

struct invexNode {
    char invex[NICKLEN + USERLEN + HOSTLEN + 3]; /* 1 for '\0', 1 for ! and 1 for @ = 3 */
    char who[NICKLEN + 1]; /* who set the invex */
    unsigned long set; /* time invex was set */
};

struct modeNode {
    struct chanNode *channel;
    struct userNode *user;
    unsigned short modes;
    short oplevel;
    unsigned long idle_since;
};

#define SERVERNAMEMAX 64
#define SERVERDESCRIPTMAX 128

struct server {
    char name[SERVERNAMEMAX+1];
    unsigned long boot;
    unsigned long link_time;
    char description[SERVERDESCRIPTMAX+1];
#ifdef WITH_PROTOCOL_P10
    char numeric[COMBO_NUMERIC_LEN+1];
    unsigned int num_mask;
#elif WITH_PROTOCOL_TS6
    char numeric[UID_NUMERIC_LEN+1];
    unsigned int num_mask;
#endif
    unsigned int hops, clients, max_clients;
    unsigned int burst : 1, self_burst : 1;
    struct server *uplink;
#if defined(WITH_PROTOCOL_P10) || defined(WITH_PROTOCOL_TS6)
    struct userNode **users; /* flat indexed by numeric */
#else
    dict_t users; /* indexed by nick */
#endif
    struct serverList children;
};

extern struct server *self;
extern dict_t channels;
extern dict_t clients;
extern dict_t cnicks;
extern dict_t servers;
extern unsigned int max_clients, invis_clients;
extern unsigned long max_clients_time;
extern struct userList curr_opers, curr_helpers;

struct server* GetServerID(const char *numeric); /* using SID */
struct server* GetServerH(const char *name); /* using full name */
struct userNode* GetUserH(const char *nick);   /* using nick */
struct userNode* GetUserUID(const char *numeric); /* using UID's (TS6) */
struct chanNode* GetChannel(const char *name);
struct modeNode* GetUserMode(struct chanNode* channel, struct userNode* user);

int userList_contains(struct userList *list, struct userNode *user);

typedef void (*server_link_func_t) (struct server *server);
void reg_server_link_func(server_link_func_t handler);

typedef void (*new_user_func_t) (struct userNode *user);
void reg_new_user_func(new_user_func_t handler);
typedef void (*del_user_func_t) (struct userNode *user, struct userNode *killer, const char *why);
void reg_del_user_func(del_user_func_t handler);
void unreg_del_user_func(del_user_func_t handler);
void ReintroduceUser(struct userNode* user);
typedef void (*nick_change_func_t)(struct userNode *user, const char *old_nick);
void reg_nick_change_func(nick_change_func_t handler);
void NickChange(struct userNode* user, const char *new_nick, int no_announce);

typedef void (*account_func_t) (struct userNode *user, const char *stamp, unsigned long timestamp, unsigned long serial);
void reg_account_func(account_func_t handler);
void call_account_func(struct userNode *user, const char *stamp, unsigned long timestamp, unsigned long serial);
void StampUser(struct userNode *user, const char *stamp, unsigned long timestamp, unsigned long serial);
void assign_fakehost(struct userNode *user, const char *host, const char *ident, int force, int announce);

typedef void (*new_channel_func_t) (struct chanNode *chan);
void reg_new_channel_func(new_channel_func_t handler);
typedef int (*join_func_t) (struct modeNode *mNode);
void reg_join_func(join_func_t handler);
typedef void (*del_channel_func_t) (struct chanNode *chan);
void reg_del_channel_func(del_channel_func_t handler);

struct chanNode* AddChannel(const char *name, unsigned long time_, const char *modes, char *banlist, char *quietlist, char *exemptlist, char *invexlist);
void LockChannel(struct chanNode *channel);
void UnlockChannel(struct chanNode *channel);

struct modeNode* AddChannelUser(struct userNode* user, struct chanNode* channel);

int modeNode_sort(const void *pa, const void *pb);
typedef void (*part_func_t) (struct modeNode *mn, const char *reason);
void reg_part_func(part_func_t handler);
void unreg_part_func(part_func_t handler);
void DelChannelUser(struct userNode* user, struct chanNode* channel, const char *reason, int deleting);
void KickChannelUser(struct userNode* target, struct chanNode* channel, struct userNode *kicker, const char *why);

typedef void (*kick_func_t) (struct userNode *kicker, struct userNode *user, struct chanNode *chan);
void reg_kick_func(kick_func_t handler);
void ChannelUserKicked(struct userNode* kicker, struct userNode* victim, struct chanNode* channel);

int ChannelBanExists(struct chanNode *channel, const char *ban);

typedef int (*topic_func_t)(struct userNode *who, struct chanNode *chan, const char *old_topic);
void reg_topic_func(topic_func_t handler);
void SetChannelTopic(struct chanNode *channel, struct userNode *user, const char *topic, int announce);

void init_structs(void);

#endif
