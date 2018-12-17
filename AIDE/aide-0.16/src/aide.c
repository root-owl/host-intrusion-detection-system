/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2006,2010-2013,2015,2016 Rami Lehti, Pablo Virolainen,
 * Mike Markley, Richard van den Berg, Hannes von Haugwitz
 * $Header$
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "aide.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "md.h"
#include "commandconf.h"
#include "compare_db.h"
#include "db_config.h"
#include "db_file.h"
#include "db_file_json.h"
#include "do_md.h"
#include "report.h"
#include "gen_list.h"
#include "getopt.h"
#include "list.h"
#include "util.h"
#include "base64.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/
db_config* conf;

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

static void usage(int exitvalue)
{
    fprintf(stderr, 
            _("Aide " AIDEVERSION" \n\n"
            "Usage: aide [options] command\n\n"
            "Commands:\n"
            "  -i, --init\t\tInitialize the database\n"
            "  -C, --check\t\tCheck the database\n"
            "  -u, --update\t\tCheck and update the database non-interactively\n"
            "  -E, --compare\t\tCompare two databases\n\n"
            "Miscellaneous:\n"
            "  -D, --config-check\tTest the configuration file\n"
            "  -v, --version\t\tShow version of AIDE and compilation options\n"
            "  -h, --help\t\tShow this help message\n\n"
            "Options:\n"
            "  -c [cfgfile]\t--config=[cfgfile]\tGet config options from [cfgfile]\n"
            "  -l [REGEX]\t--limit=[REGEX]\t\tLimit command to entries matching [REGEX]\n"
            "  -B \"OPTION\"\t--before=\"OPTION\"\tBefore configuration file is read define OPTION\n"
            "  -A \"OPTION\"\t--after=\"OPTION\"\tAfter configuration file is read define OPTION\n"
            "  -r [reporter]\t--report=[reporter]\tWrite report output to [reporter] url\n"
            "  -V[level]\t--verbose=[level]\tSet debug message level to [level]\n"
            "  -R [val]\t--RAM=[val]\tSet RAM DB enable to [val] (only support 0/1)\n"
            "  -J [val]\t--JSON=[val]\tSet JSON DB enable to [val] (only support 0/1)\n"
            "\n")
            );
    exit(exitvalue);
}

static void print_version(void)
{
    fprintf(stderr, 
            "Aide " AIDEVERSION "\n\n" 
            "Compiled with the following options:\n\n" AIDECOMPILEOPTIONS "\n");
    exit(0);
}

static int read_param(int argc,char**argv)
{
    int option = -1;
    char* err=NULL;
    int i=0;

    static struct option options[] =
    {
        { "help", no_argument, NULL, 'h' },
        { "verbose", optional_argument, NULL, 'V'},
        { "RAM", optional_argument, NULL, 'R'},
        { "JSON", optional_argument, NULL, 'J'},
        { "version", no_argument, NULL, 'v'},
        { "config", required_argument, NULL, 'c'},
        { "before", required_argument, NULL, 'B'},
        { "after", required_argument, NULL, 'A'},
        { "report", required_argument, NULL, 'r'},
        { "init", no_argument, NULL, 'i'},
        { "check", no_argument, NULL, 'C'},
        { "update", no_argument, NULL, 'u'},
        { "config-check", no_argument, NULL, 'D'},
        { "limit", required_argument, NULL, 'l'},
        { "compare", no_argument, NULL, 'E'},
        { NULL,0,NULL,0 }
    };

    while(1)
    {
        option = getopt_long(argc, argv, "hV::vcRJ:B:A:r:iCuDE", options, &i);
        if(option==-1)
            break;
        switch(option)
        {
            case 'h':
            {
                usage(0);
                break;
            }
            case 'v':
            {
                print_version();
                break;
            }
            case 'V':
            {
                if(optarg!=NULL)
                {
                    conf->verbose_level=strtol(optarg,&err,10);
                    if(*err!='\0' || conf->verbose_level>255 || conf->verbose_level<0 || errno==ERANGE)
                    {
                        error(0, _("Illegal verbosity level:%s\n"),optarg);
                        exit(INVALID_ARGUMENT_ERROR);
                    }
                    error(230,_("Setting verbosity to %s\n"),optarg);
                }
                else
                {
                    conf->verbose_level=20;
                }
                break;
            }
            case 'R':
            {
                if(optarg!=NULL)
                {
                    conf->enable_RAM_DB=strtol(optarg,&err,10);
                    if(*err!='\0' || (conf->enable_RAM_DB != 0 && conf->enable_RAM_DB != 1) || errno==ERANGE)
                    {
                        error(0, _("Illegal RAM DB enable value:%s\n Only support:0/1 \n"),optarg);
                        exit(INVALID_ARGUMENT_ERROR);
                    }
                    error(230,_("Setting RAM DB to %s\n"),optarg);
                }
                else
                {
                    conf->enable_RAM_DB=1;
                }
                break;
            }
            case 'J':
            {
                if(optarg!=NULL)
                {
                    conf->enable_JSON_DB=strtol(optarg,&err,10);
                    if(*err!='\0' || (conf->enable_JSON_DB != 0 && conf->enable_JSON_DB != 1) || errno==ERANGE)
                    {
                        error(0, _("Illegal JSON DB enable value:%s\n Only support:0/1 \n"),optarg);
                        exit(INVALID_ARGUMENT_ERROR);
                    }
                    error(230,_("Setting JSON DB to %s\n"),optarg);
                    }
                else
                {
                    conf->enable_JSON_DB=1;
                }
                break;
            }
            case 'c':
            {
                if(optarg!=NULL)
                {
                    conf->config_file=optarg;
                }
                else
                {
                    error(0,_("No config-file name given!\n"));
                    exit(INVALID_ARGUMENT_ERROR);
                }
                break;
            }
            case 'B':
            {
                if (optarg!=NULL)
                {
                    int errorno=commandconf('B',optarg);
                    if (errorno!=0)
                    {
                        error(0,_("Configuration error in before statement:%s\n"),optarg);
                        exit(INVALID_CONFIGURELINE_ERROR);
                    }
                }
                else
                {
                    error(0,_("-B must have a parameter\n"));
                    exit(INVALID_ARGUMENT_ERROR);
                }
                break;
            }
            case 'A':
            {
                if (optarg!=NULL)
                {
                    int errorno=commandconf('A',optarg);
                    if (errorno!=0)
                    {
                        error(0,_("Configuration error in after statement:%s\n"),optarg);
                        exit(INVALID_CONFIGURELINE_ERROR);
                    }
                }
                else
                {
                    error(0,_("-A must have a parameter\n"));
                    exit(INVALID_ARGUMENT_ERROR);
                }
                break;
            }
            case 'l':
            {
                if (optarg!=NULL)
                {
                    const char* pcre_error;
                    int pcre_erroffset;
                    conf->limit=malloc(strlen(optarg)+1);
                    strcpy(conf->limit,optarg);
                    if((conf->limit_crx=pcre_compile(conf->limit, PCRE_ANCHORED, &pcre_error, &pcre_erroffset, NULL)) == NULL)
                    {
                        error(0,_("Error in limit regexp '%s' at %i: %s\n"), conf->limit, pcre_erroffset, pcre_error);
                        exit(INVALID_ARGUMENT_ERROR);
                    }
                    error(200,_("Limit set to '%s'\n"), conf->limit);
                }
                else
                {
                    error(0,_("-l must have an argument\n"));
                    exit(INVALID_ARGUMENT_ERROR);
                }
                break;
            }
            case 'r':
            {
                if(optarg!=NULL)
                {
                    do_repurldef(optarg);
                }
                else
                {
                    error(0,_("-r must have an argument\n"));
                }
                break;
            }
            case 'i':
            {
                if(conf->action==0)
                {
                    conf->action=DO_INIT;
                }
                else
                {
                    error(0,
                    _("Cannot have multiple commands on a single commandline.\n"));
                    exit(INVALID_ARGUMENT_ERROR);
                };
                break;
            }
            case 'C':
            {
                if(conf->action==0)
                {
                    conf->action=DO_COMPARE;
                }
                else
                {
                    error(0,
                    _("Cannot have multiple commands on a single commandline.\n"));
                    exit(INVALID_ARGUMENT_ERROR);
                };
                break;
            }
            case 'u':
            {
                if(conf->action==0)
                {
                    conf->action=DO_INIT|DO_COMPARE;
                }
                else
                {
                    error(0,
                    _("Cannot have multiple commands on a single commandline.\n"));
                    exit(INVALID_ARGUMENT_ERROR);
                };
                break;
            }
            case 'E':
            {
                if(conf->action==0)
                {
                    conf->action=DO_DIFF;
                }
                else
                {
                    error(0,
                    _("Cannot have multiple commands on a single commandline.\n"));
                    exit(INVALID_ARGUMENT_ERROR);
                };
                break;
            }
            case 'D':
            {
                conf->config_check=1;
                break;
            }
            default:
            error(0,_("Unknown option given. Exiting\n"));
            exit(INVALID_ARGUMENT_ERROR);
        }
    }

    if(optind<argc)
    {
        error(0,_("Extra parameters given\n"));
        exit(INVALID_ARGUMENT_ERROR);
    }
    return RETOK;
}

static void setdefaults_before_config()
{
    char* urlstr=INITIALERRORSTO;
    url_t* u=NULL;
    char* s=(char*)malloc(sizeof(char)*MAXHOSTNAMELEN+1);
    DB_ATTR_TYPE X;

    /*
    Set up the hostname
    */
    conf=(db_config*)malloc(sizeof(db_config));
    conf->defsyms=NULL;

    if (gethostname(s,MAXHOSTNAMELEN)==-1)
    {
        error(0,_("Couldn't get hostname"));
        free(s);
    }
    else
    {
        s=(char*)realloc((void*)s,strlen(s)+1);
        do_define("HOSTNAME",s);
    }

    /* Setting some defaults */
    conf->report_db=0;
    conf->tree=NULL;
    conf->config_check=0;
    conf->verbose_level=-1;
    conf->database_add_metadata=1;
    conf->report_detailed_init=0;
    conf->report_base16=0;
    conf->report_quiet=0;
    conf->use_initial_errorsto=1;
    conf->report_url=NULL;
    conf->report_fd=NULL;
    conf->report_syslog=0;
    conf->report_db=0;
#ifdef WITH_E2FSATTRS
    conf->report_ignore_e2fsattrs = 0UL;
#endif

    u=parse_url(urlstr);
    error_init(u,1);

    conf->config_file=CONFIG_FILE;
    conf->config_version=NULL;

#ifdef WITH_ACL
    conf->no_acl_on_symlinks=0; /* zero means don't do ACLs on symlinks */
#endif

#ifdef WITH_MHASH
    conf->do_configmd=0;
    conf->confmd=NULL;
    conf->confhmactype=CONFIGHMACTYPE;
    conf->old_confmdstr=NULL;
    conf->dbhmactype=DBHMACTYPE;
    conf->dbnewmd=NULL;
    conf->dboldmd=NULL;
#endif

    conf->do_dbnewmd=0;
    conf->do_dboldmd=0;
    conf->old_dbnewmdstr=NULL;
    conf->old_dboldmdstr=NULL;

    conf->db_out_order=(DB_FIELD*)malloc(sizeof(DB_FIELD)*db_unknown);
    conf->db_out_size=1;
    conf->db_out_order[0]=db_filename;
    conf->symlinks_found=0;
    conf->db_in_size=0;
    conf->db_in_order=NULL;
    //conf->db_in_url=NULL;
    //conf->db_in=NULL;
    conf->dbc_in.db_url=NULL;
    conf->dbc_in.dbP=NULL;
    conf->db_new_size=0;
    conf->db_new_order=NULL;
    //conf->db_new_url=NULL;
    //conf->db_new=NULL;
    conf->dbc_new.db_url=NULL;
    conf->dbc_new.dbP=NULL;
    //conf->db_out_url=NULL;
    //conf->db_out=NULL;
    conf->dbc_out.db_url=NULL;
    conf->dbc_out.dbP=NULL;

    conf->enable_JSON_DB = 0;
    conf->jDB = NULL;

    conf->mdc_in=NULL;
    conf->mdc_out=NULL;

    conf->line_db_in=NULL;
    conf->line_db_out=NULL;

    conf->db_attrs = 0;
#if defined(WITH_MHASH) || defined(WITH_GCRYPT)
    conf->db_attrs |= DB_MD5|DB_TIGER|DB_HAVAL|DB_CRC32|DB_SHA1|DB_RMD160|DB_SHA256|DB_SHA512;
#ifdef WITH_MHASH
    conf->db_attrs |= DB_GOST;
#ifdef HAVE_MHASH_WHIRLPOOL
    conf->db_attrs |= DB_WHIRLPOOL;
#endif
#endif
#endif

#ifdef WITH_ZLIB
    conf->db_gzin=0;
    conf->db_gznew=0;
    conf->gzip_dbout=0;
    conf->db_gzout=0;
#endif

    conf->action=0;
    conf->catch_mmap=0;

    conf->warn_dead_symlinks=0;

    conf->grouped=1;

    conf->summarize_changes=1;

    conf->root_prefix="";
    conf->root_prefix_length=0;

    conf->limit=NULL;
    conf->limit_crx=NULL;

    conf->selrxlst=NULL;
    conf->equrxlst=NULL;
    conf->negrxlst=NULL;

    conf->groupsyms=NULL;

    conf->start_time=time(&(conf->start_time));

    do_groupdef("ANF",DB_NEWFILE);
    do_groupdef("ARF",DB_RMFILE);
    do_groupdef("p",DB_PERM);
    do_groupdef("i",DB_INODE);
    do_groupdef("I",DB_CHECKINODE);
    do_groupdef("n",DB_LNKCOUNT);
    do_groupdef("u",DB_UID);
    do_groupdef("g",DB_GID);
    do_groupdef("l",DB_LINKNAME);
    do_groupdef("s",DB_SIZE);
    do_groupdef("S",DB_SIZEG);
    do_groupdef("b",DB_BCOUNT);
    do_groupdef("m",DB_MTIME);
    do_groupdef("c",DB_CTIME);
    do_groupdef("a",DB_ATIME);
#if defined(WITH_MHASH) || defined(WITH_GCRYPT)
    do_groupdef("md5",DB_MD5);
    do_groupdef("tiger",DB_TIGER);
    do_groupdef("haval",DB_HAVAL);
    do_groupdef("crc32",DB_CRC32);
    do_groupdef("sha1",DB_SHA1);
    do_groupdef("rmd160",DB_RMD160);
    do_groupdef("sha256",DB_SHA256);
    do_groupdef("sha512",DB_SHA512);
#endif
#ifdef WITH_ACL
    do_groupdef("acl",DB_ACL);
#endif
#ifdef WITH_XATTR
    do_groupdef("xattrs",DB_XATTRS);
#endif
#ifdef WITH_SELINUX
    do_groupdef("selinux",DB_SELINUX);
#endif

#ifdef WITH_MHASH
    do_groupdef("gost",DB_GOST);
#ifdef HAVE_MHASH_WHIRLPOOL
    do_groupdef("whirlpool",DB_WHIRLPOOL);
#endif
#endif
    do_groupdef("ftype",DB_FTYPE);
#ifdef WITH_E2FSATTRS
    do_groupdef("e2fsattrs",DB_E2FSATTRS);
#endif

    X=0LLU;
#ifdef WITH_ACL
    X|=DB_ACL;
#endif
#ifdef WITH_SELINUX
    X|=DB_SELINUX;
#endif
#ifdef WITH_XATTR
    X|=DB_XATTRS;
#endif
#ifdef WITH_E2FSATTRS
    X|=DB_E2FSATTRS;
#endif


    do_groupdef("R",DB_PERM|DB_FTYPE|DB_INODE|DB_LNKCOUNT|DB_UID|DB_GID|DB_SIZE| 
            DB_LINKNAME|DB_MTIME|DB_CTIME
#if defined(WITH_MHASH) || defined(WITH_GCRYPT)
            |DB_MD5
#endif
            |X);

    do_groupdef("L",DB_PERM|DB_FTYPE|DB_INODE|DB_LNKCOUNT|DB_UID|DB_GID|DB_LINKNAME|X);

    do_groupdef(">",DB_PERM|DB_FTYPE|DB_INODE|DB_LNKCOUNT|DB_UID|DB_GID|DB_SIZEG|
    DB_LINKNAME|X);
    do_groupdef("X",X);
    do_groupdef("E",0);

}

static void setdefaults_after_config()
{
    if(conf->dbc_in.db_url==NULL)
    {
        url_t* u=NULL;
        u=(url_t*)malloc(sizeof(url_t));
        u->type=url_file;
        u->value=DEFAULT_DB;
        conf->dbc_in.db_url=u;
    }
    if(conf->dbc_out.db_url==NULL)
    {
        url_t* u=NULL;
        u=(url_t*)malloc(sizeof(url_t));
        u->type=url_file;
        u->value=DEFAULT_DB_OUT;
        conf->dbc_out.db_url=u;
    }
    if(conf->report_url==NULL)
    {
        url_t* u=NULL;

        /* Don't free this one because conf->report_url needs it */
        u=(url_t*)malloc(sizeof(url_t));
        u->type=url_stdout;
        u->value="";
        error_init(u,0);
    }
    if(conf->action==0)
    {
        conf->action=DO_COMPARE;
    }
    if(conf->verbose_level==-1)
    {
        conf->verbose_level=5;
    }
}


int main(int argc,char**argv)
{
    int idx = 0;
    int errorno=0;
    byte* dig=NULL;
    char* digstr=NULL;

#ifdef USE_LOCALE
    setlocale(LC_ALL,"");
    bindtextdomain(PACKAGE,LOCALEDIR);
    textdomain(PACKAGE);
#endif
    umask(0177);
    init_sighandler();

    setdefaults_before_config();

    if(read_param(argc,argv)==RETFAIL)
    {
        error(0, _("Invalid argument\n") );
        exit(INVALID_ARGUMENT_ERROR);
    }

    //fprintf(stdout, "+++ RAM:%d +++\n", conf->enable_RAM_DB);
    //fprintf(stdout, "+++ JSON:%d +++\n", conf->enable_JSON_DB);


    errorno=commandconf('C',conf->config_file);

    errorno=commandconf('D',"");
    if (errorno==RETFAIL)
    {
        error(0,_("Configuration error\n"));
        exit(INVALID_CONFIGURELINE_ERROR);
    }

    setdefaults_after_config();

    /*
    This won't actualy work, because conf->tree is not constructed.
    Now we construct it. And we have THE tree.
    */

    /*
    fprintf(stdout, "+++ out cnt:%d out items:", conf->db_out_size);
    for (idx = 0; idx < conf->db_out_size; idx++)
    {
        fprintf(stdout," %d", conf->db_out_order[idx]);
    }
    fprintf(stdout,"\n");
    */

    //fprintf(stdout, "+++ gen_tree() begin +++\n");
    conf->tree = gen_tree(conf->selrxlst,conf->negrxlst,conf->equrxlst);
    //fprintf(stdout, "+++ gen_tree() end +++\n");

    /* Let's do some sanity checks for the config */
    if(cmpurl(conf->dbc_in.db_url,conf->dbc_out.db_url) == RETOK)
    {
        error(4,_("WARNING:Input and output database urls are the same.\n"));
        if((conf->action & DO_INIT) && (conf->action & DO_COMPARE))
        {
            error(0,_("Input and output database urls cannot be the same "
                        "when doing database update\n"));
            exit(INVALID_ARGUMENT_ERROR);
        }
        if(conf->action & DO_DIFF)
        {
            error(0,_("Both input databases cannot be the same "
                        "when doing database compare\n"));
            exit(INVALID_ARGUMENT_ERROR);
        }
    }

    if((conf->action & DO_DIFF) && (!(conf->dbc_new.db_url) || !(conf->dbc_in.db_url)))
    {
        error(0,_("Must have both input databases defined for "
                    "database compare.\n"));
        exit(INVALID_ARGUMENT_ERROR);
    }

    if (conf->action & (DO_INIT | DO_COMPARE) && conf->root_prefix_length > 0)
    {
        DIR *dir;
        if((dir = opendir(conf->root_prefix)) != NULL)
        {
            closedir(dir);
        }
        else
        {
            char* er = strerror(errno);
            if (er!=NULL)
            {
                error(0,"opendir() for root prefix %s failed: %s\n", conf->root_prefix,er);
            }
            else
            {
                error(0,"opendir() for root prefix %s failed: %i\n", conf->root_prefix,errno);
            }
            exit(INVALID_ARGUMENT_ERROR);
        }
    }

#ifdef WITH_MHASH
    if(conf->config_check && FORCECONFIGMD)
    {
        error(0,"Can't give config checksum when compiled with --enable-forced_configmd\n");
        exit(INVALID_ARGUMENT_ERROR);
    }

    if((conf->do_configmd || conf->config_check) && conf->confmd!=0)
    {
        /* The patch automatically adds a newline so will also have to add it. */
        if(newlinelastinconfig == 0)
        {
            mhash(conf->confmd,"\n",1);
        }

        mhash(conf->confmd, NULL,0);
        dig=(byte*)malloc(sizeof(byte) * mhash_get_block_size(conf->confhmactype));
        mhash_deinit(conf->confmd,(void*)dig);
        digstr=encode_base64(dig,mhash_get_block_size(conf->confhmactype));

        if(!conf->config_check||FORCECONFIGMD)
        {
            if(strncmp(digstr,conf->old_confmdstr,strlen(digstr))!=0)
            {
                /* FIXME Don't use error and add configurability */
                error(0,_("Config checksum mismatch\n"));
                exit(INVALID_ARGUMENT_ERROR);
            }
        }
    }
    else
    {
        if(FORCECONFIGMD)
        {
            error(0,_("Config checksum not found. Exiting..\n"));
            exit(INVALID_ARGUMENT_ERROR);
        }
    }
#endif

    conf->use_initial_errorsto = 0;
    if (!conf->config_check)
    {
        char * jDBStr = NULL;
        /*
        fprintf(stdout, "\n[%s:%d:%s] +++ Confs 1 +++ check:%d limit:%p Action:%x rbase16:%d rQuiet:%d rDetailInit:%d \n",
                __FILE__, __LINE__, __func__, conf->config_check, conf->limit, conf->action,
                conf->report_base16, conf->report_quiet, conf->report_detailed_init );
        fprintf(stdout, "\n[%s:%d:%s] +++ Confs 2 +++ Grouped:%d summarize_changes:%d verbose_level:%d \n",
                __FILE__, __LINE__, __func__, conf->grouped, conf->summarize_changes, conf->verbose_level);
                */

        if(conf->action & DO_INIT)
        {
            if(db_init(DB_WRITE) == RETFAIL)
            {
                exit(IO_ERROR);
            }

            /* FIXME db_out_order info should be taken from tree/config */
            /* update_db_out_order(-1); OOPS. It was allready done by append_rxlist
            :) */
            if(db_writespec(conf) == RETFAIL)
            {
                error(0,_("Error while writing database. Exiting..\n"));
                exit(IO_ERROR);
            }

            /*Do JSON dumpping init*/
            if(conf->enable_JSON_DB)
            {
                int len = strlen(conf->dbc_out.db_url->value);
                len += strlen(".json");
                char * jPath = (char *)calloc(len + 1, 1);
                strcpy(jPath, conf->dbc_out.db_url->value);
                strcat(jPath,".json");

                conf->jDB = dbJSON_New(1, jPath);
                free(jPath);

                if(dbJSON_writespec(conf->jDB, conf) != 0)
                {
                    fprintf(stdout, "--- dbJSON_writespec() fail!\n");
                }

                dbJSON_WriteRxList(conf->jDB, conf);
            }
        }
        if((conf->action & DO_INIT) || (conf->action & DO_COMPARE))
        {
            if(db_init(DB_DISK) == RETFAIL)
                exit(IO_ERROR);
        }
        if((conf->action & DO_COMPARE) || (conf->action & DO_DIFF))
        {
            if(db_init(DB_OLD) == RETFAIL)
                exit(IO_ERROR);
        }
        if(conf->action & DO_DIFF)
        {
            if(db_init(DB_NEW) == RETFAIL)
                exit(IO_ERROR);
        }

        populate_tree(conf->tree);

        /*
        fprintf(stdout, "\n[%s:%d:%s] +++ Confs 1 +++ check:%d limit:%p Action:%x rbase16:%d rQuiet:%d rDetailInit:%d \n",
                __FILE__, __LINE__, __func__, conf->config_check, conf->limit, conf->action,
                conf->report_base16, conf->report_quiet, conf->report_detailed_init );
        fprintf(stdout, "\n[%s:%d:%s] +++ Confs 2 +++ Grouped:%d summarize_changes:%d verbose_level:%d \n",
                __FILE__, __LINE__, __func__, conf->grouped, conf->summarize_changes, conf->verbose_level);

        fprintf(stdout, "\n+++ Print tree after populate_tree() begin +++\n");
        print_tree(conf->tree);
        fprintf(stdout, "\n+++ Print tree after populate_tree() end +++\n");
                */

        db_close();

        /*
        jDBStr = cJSON_Print(conf->jDB->db);
        fprintf(stdout, "\n=== jDB:\n%s\n\n", jDBStr);
        free(jDBStr);

         */
        if(conf->enable_JSON_DB)
        {
            dbJSON_close(conf->jDB);
        }

        exit(gen_report(conf->tree));

    }
    else
    {
#ifdef WITH_MHASH
        if(conf->confmd)
        {
            error(0,"Config checked. Use the following to patch your config file.\n");
            error(0,"0a1\n");
            if(newlinelastinconfig == 1)
            {
                error(0,"> @@begin_config %s\n%lia%li\n> @@end_config\n", digstr ,conf_lineno - 1, conf_lineno + 1);
            }
            else
            {
                error(0,"> @@begin_config %s\n%lia%li\n> @@end_config\n", digstr, conf_lineno, conf_lineno + 2);
            }
            free(dig);
            free(digstr);
        }
#endif
    }
    return RETOK;
}

const char* aide_key_3=CONFHMACKEY_03;
const char* db_key_3=DBHMACKEY_03;

