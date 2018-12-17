/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2007,2010-2013,2016 Rami Lehti, Pablo Virolainen, Mike
 * Markley, Richard van den Berg, Hannes von Haugwitz
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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include <errno.h>

#include "types.h"
#include "base64.h"
#include "db_file_json.h"
#include "gen_list.h"
#include "conf_yacc.h"
#include "util.h"
#include "commandconf.h"
/*for locale support*/
#include "locale-aide.h"
/*for locale support*/

#ifdef WITH_MHASH
#include <mhash.h>
#endif

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

#define BUFSIZE 16384


#include "md.h"

#ifdef WITH_ZLIB
#define ZBUFSIZE 16384

/*
static int dofprintf_ram( const char* s,...)
#ifdef __GNUC__
        __attribute__ ((format (printf, 1, 2)));
#else
        ;
#endif
*/

RamLine* NewRamLine()
{
        RamLine * line = (RamLine*)malloc(sizeof(RamLine));
        line->size = RAMLINE_BLOCK_SIZE;
        line->data = (unsigned char *)calloc(RAMLINE_BLOCK_SIZE, 1);
        line->rwPos = line->data;

        return line;
}

int resizeRamLine(RamLine *out, unsigned int newAppendLen)
{
        unsigned int oldDataLen = RAMLINE_LEN(out);
        unsigned int newAddLen = ((newAppendLen + RAMLINE_BLOCK_SIZE) % RAMLINE_BLOCK_SIZE) * RAMLINE_BLOCK_SIZE;

        unsigned char* newData = (unsigned char*)calloc(oldDataLen + newAddLen, 1);
        memcpy(newData, out->data, oldDataLen);
        free(out->data);
        out->data = newData;
        out->rwPos = out->data + newAddLen;
        out->size = out->size + newAddLen;

        return 0;
}

int ramLineWrite(RamLine *out, unsigned char * buf, unsigned int len)
{
        if(out == NULL)
        {
                return -1;
        }

        if(len > RAMLINE_BUF_LEN(out))
        {
                resizeRamLine(out, len);
        }

        memcpy(out->rwPos, buf, len);
        out->rwPos = out->rwPos + len;

        return 0;
}

#endif

int dofprintf_ram(char ** dst, const char* s,...)
{
    char buf[3];
    int retval;
    char* temp=NULL;
    va_list ap;

    va_start(ap,s);
    retval=vsnprintf(buf,3,s,ap);
    va_end(ap);

    temp=(char*)calloc(retval+2, 1);
    if(temp==NULL)
    {
        error(0,"Unable to alloc %i bytes\n",retval+2);
        return -1;
    }

    va_start(ap,s);
    retval=vsnprintf(temp,retval+1,s,ap);
    va_end(ap);


    *dst = temp;
    return retval;
}

int db_writeint_ram(char ** dst, long i)
{
    return dofprintf_ram(dst, "%li",i);
}

int db_writelong_ram(char ** dst, AIDE_OFF_TYPE i)
{
#if defined HAVE_OFF64_TYPE && SIZEOF_OFF64_T == SIZEOF_LONG_LONG || !defined HAVE_OFF64_TYPE && SIZEOF_OFF_T == SIZEOF_LONG_LONG
    return dofprintf_ram(dst, "%lli",(long long)i);
#else
    return dofprintf_ram(dst, "%li",i);
#endif
}

int db_write_byte_base64_ram(char **dst, byte*data,size_t len, DB_ATTR_TYPE th, DB_ATTR_TYPE attr )
{
    char* tmpstr=NULL;
    int retval=0;

    if (data && !len)
        len = strlen((const char *)data);

    if (data!=NULL&&th&attr)
    {
        tmpstr=encode_base64(data,len);
    }
    else
    {
        tmpstr=NULL;
    }

    if(tmpstr)
    {
        retval=dofprintf_ram(dst, "%s", tmpstr);
        free(tmpstr);
        return retval;
    }
    else
    {
        return dofprintf_ram(dst, "0");
    }
    return 0;
}

int db_write_time_base64_ram(char **dst, time_t i)
{
    static char* ptr=NULL;
    char* tmpstr=NULL;
    int retval=0;

    if(i==0)
    {
        retval=dofprintf_ram(dst, "0");
        return retval;
    }


    ptr=(char*)malloc(sizeof(char)*TIMEBUFSIZE);
    if (ptr==NULL)
    {
        error(0,"\nCannot allocate memory.\n");
        abort();
    }
    memset((void*)ptr,0,sizeof(char)*TIMEBUFSIZE);

    sprintf(ptr,"%li",i);


    tmpstr=encode_base64((byte *)ptr,strlen(ptr));
    retval=dofprintf_ram(dst, "%s", tmpstr);
    free(tmpstr);
    free(ptr);

    return retval;
}

int db_writeoct_ram(char **dst, long i)
{
    return dofprintf_ram(dst, "%lo",i);
}

// JSON DB

JsonDB* dbJSON_New(int isDump2File, unsigned char *filePath)
{
    JsonDB * jDB = (JsonDB*)calloc(sizeof(JsonDB), 1);
    jDB->isDump2File = isDump2File == 0 ? 0 : 1;
    jDB->filePath = NULL;

    if(jDB->isDump2File)
    {
        int len;
        if(filePath == NULL)
            goto end;

        len = strlen(filePath);
        jDB->filePath = (unsigned char *)calloc(len, 1);
        strcpy(jDB->filePath, filePath);
    }

    jDB->db = cJSON_CreateObject();
    if(jDB->db == NULL)
    {
        return NULL;
    }

    jDB->fileList = cJSON_AddArrayToObject(jDB->db, "filesDB");

    return jDB;

end:
    free(jDB);
    return NULL;
}

int dbJSON_writespec(JsonDB *jDB, db_config* conf)
{
    char * jDBStr = NULL;
    int ret = 0;
    int idx = 0;
    cJSON * spec = cJSON_CreateObject();
    cJSON * specItems = NULL;

    if(cJSON_AddNumberToObject(spec, "itemsCount", conf->db_out_size) == NULL)
    {
        goto end;
    }

    specItems = cJSON_AddArrayToObject(spec, "items");
    if(specItems == NULL)
    {
        goto end;
    }

    /*
    fprintf(stdout, "\n+++ dbJSON_writespe() cout cnt:%d out items:", conf->db_out_size);
    for (idx = 0; idx < conf->db_out_size; idx++)
    {
        fprintf(stdout," %d", conf->db_out_order[idx]);
    }
    fprintf(stdout,"\n");
    */

    for(idx = 0; idx < conf->db_out_size; idx++)
    {
        int fieldIdx = conf->db_out_order[idx];
        cJSON *item = cJSON_CreateString(db_field_names[fieldIdx]);
        if(item == NULL)
        {
            goto end;
        }

        cJSON_AddItemToArray(specItems, item);
    }

    cJSON_AddItemToObject(jDB->db, "spec", spec);

    /*
    jDBStr = cJSON_Print(jDB->db);
    fprintf(stdout, "\n=== dbJSON_writespe() obj:\n%s\n\n", jDBStr);
    free(jDBStr);
    */


    return 0;

end:
    cJSON_Delete(spec);
    return -1;
}

cJSON * dbJSON_line2FileObject(db_line* line, db_config* dbconf)
{

    const char time_format[] = "%Y-%m-%d %H:%M:%S %z";
    const int time_string_len = 26;

    int i;
    cJSON * item = NULL;
    cJSON * fileObj = cJSON_CreateObject();

    for(i=0;i<dbconf->db_out_size;i++)
    //for(i=0;i<6;i++)
    {
        switch (dbconf->db_out_order[i])
        {
            case db_filename :
            {
                //db_writechar(line->filename,(FILE*)dbconf->dbc_out.dbP,i);
                if(cJSON_AddStringToObject(fileObj, db_field_names[db_filename], line->filename) == NULL)
                    goto  end;
                break;
            }
            case db_linkname :
            {
                //db_writechar(line->linkname,(FILE*)dbconf->dbc_out.dbP,i);
                char * lname = line->linkname == NULL ? "0" : line->linkname;
                if(cJSON_AddStringToObject(fileObj, db_field_names[db_linkname], lname) == NULL)
                    goto  end;
                break;
            }
            case db_bcount :
            {
                //db_writeint(line->bcount,(FILE*)dbconf->dbc_out.dbP,i);
                //if(cJSON_AddNumberToObject(fileObj, db_field_names[db_bcount], line->bcount) == NULL)
                //    goto  end;
                char * dst = NULL;
                int ret = db_writelong_ram(&dst, line->bcount);
                if(ret <= 0 || cJSON_AddStringToObject(fileObj, db_field_names[db_bcount], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);
               break;
            }
            case db_mtime :
            {
                /*
                //db_write_time_base64(line->mtime,(FILE*)dbconf->dbc_out.dbP,i);
                char * dst = NULL;
                int ret = db_write_time_base64_ram(&dst, line->mtime);
                if(ret <= 0 || cJSON_AddStringToObject(fileObj, db_field_names[db_mtime ], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);
                */
                char *dst = NULL;
                dst = calloc(time_string_len * sizeof(char), 1);
                strftime(dst, time_string_len, time_format, localtime(&line->mtime));
                if(cJSON_AddStringToObject(fileObj, db_field_names[db_mtime ], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);

                break;
            }
            case db_atime :
            {
                //db_write_time_base64(line->atime,(FILE*)dbconf->dbc_out.dbP,i);
                /*
                char * dst = NULL;
                int ret = db_write_time_base64_ram(&dst, line->atime);
                if(ret <= 0 || cJSON_AddStringToObject(fileObj, db_field_names[db_atime ], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);
                    */
                char *dst = NULL;
                dst = calloc(time_string_len * sizeof(char), 1);
                strftime(dst, time_string_len, time_format, localtime(&line->atime));
                if(cJSON_AddStringToObject(fileObj, db_field_names[db_atime ], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);
                break;
            }
            case db_ctime :
            {
                //db_write_time_base64(line->ctime,(FILE*)dbconf->dbc_out.dbP,i);
                /*
                char * dst = NULL;
                int ret = db_write_time_base64_ram(&dst, line->ctime);
                if(ret <= 0 || cJSON_AddStringToObject(fileObj, db_field_names[db_ctime ], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);
                    */
                char *dst = NULL;
                dst = calloc(time_string_len * sizeof(char), 1);
                strftime(dst, time_string_len, time_format, localtime(&line->ctime));
                if(cJSON_AddStringToObject(fileObj, db_field_names[db_ctime ], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);
                break;
            }
            case db_inode :
            {
                //db_writeint(line->inode,(FILE*)dbconf->dbc_out.dbP,i);
                //if(cJSON_AddNumberToObject(fileObj, db_field_names[db_inode], line->inode) == NULL)
                //    goto  end;
                char * dst = NULL;
                int ret = db_writelong_ram(&dst, line->inode);
                if(ret <= 0 || cJSON_AddStringToObject(fileObj, db_field_names[db_inode], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);

                break;
            }
            case db_lnkcount :
            {
                //db_writeint(line->nlink,(FILE*)dbconf->dbc_out.dbP,i);
                //if(cJSON_AddNumberToObject(fileObj, db_field_names[db_lnkcount], line->nlink) == NULL)
                //    goto  end;
                char * dst = NULL;
                int ret = db_writelong_ram(&dst, line->nlink);
                if(ret <= 0 || cJSON_AddStringToObject(fileObj, db_field_names[db_lnkcount], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);

                break;
            }
            case db_uid :
            {
                //db_writeint(line->uid,(FILE*)dbconf->dbc_out.dbP,i);
                if(cJSON_AddNumberToObject(fileObj, db_field_names[db_uid], line->uid) == NULL)
                    goto  end;
                break;
            }
            case db_gid :
            {
                //db_writeint(line->gid,(FILE*)dbconf->dbc_out.dbP,i);
                if(cJSON_AddNumberToObject(fileObj, db_field_names[db_gid], line->gid) == NULL)
                    goto  end;
                break;
            }
            case db_size :
            {
                //db_writelong(line->size,(FILE*)dbconf->dbc_out.dbP,i);
                //if(cJSON_AddNumberToObject(fileObj, db_field_names[db_size], line->size) == NULL)
                //    goto  end;
                char * dst = NULL;
                int ret = db_writelong_ram(&dst, line->size);
                if(ret <= 0 || cJSON_AddStringToObject(fileObj, db_field_names[db_size], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);

                break;
            }
            case db_md5 :
            {
                //db_write_byte_base64(line->md5, HASH_MD5_LEN, (FILE*)dbconf->dbc_out.dbP,i, DB_MD5,line->attr);
                char * str = db_write_byte_base64_str(line->md5, HASH_MD5_LEN, i, DB_MD5,line->attr);
                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_md5], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
            case db_sha1 :
            {
                //db_write_byte_base64(line->sha1, HASH_SHA1_LEN, (FILE*)dbconf->dbc_out.dbP,i, DB_SHA1,line->attr);
                char * str = db_write_byte_base64_str(line->sha1, HASH_SHA1_LEN, i, DB_SHA1,line->attr);
                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_sha1], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
            case db_rmd160 :
            {
                //db_write_byte_base64(line->rmd160, HASH_RMD160_LEN, (FILE*)dbconf->dbc_out.dbP,i, DB_RMD160,line->attr);
                char * str = db_write_byte_base64_str(line->rmd160, HASH_RMD160_LEN, i, DB_RMD160,line->attr);
                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_rmd160], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
            case db_tiger :
            {
                //db_write_byte_base64(line->tiger, HASH_TIGER_LEN, (FILE*)dbconf->dbc_out.dbP,i, DB_TIGER,line->attr);
                char * str = db_write_byte_base64_str(line->tiger, HASH_TIGER_LEN, i, DB_TIGER,line->attr);
                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_tiger], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
            case db_perm :
            {
                //fprintf(stdout,"++++++++++++++++++++++++++++++++++++++++++++++++++++++ db_perm\n");
                //break;
                //db_writeoct(line->perm,(FILE*)dbconf->dbc_out.dbP,i);
                char * dst = NULL;
                int ret = db_writeoct_ram(&dst, line->perm);
                //fprintf(stdout,"+++ ret:%d dst:%s\n", ret, dst);
                if(ret <= 0 || cJSON_AddStringToObject(fileObj, db_field_names[db_perm], dst) == NULL)
                {
                    //fprintf(stdout,"+++ ret:%d dst:%s\n", ret, dst);
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                //fprintf(stdout,"+++ ret:%d dst:%s\n", ret, dst);
                if(dst != NULL)
                    free(dst);
                break;
            }
            case db_crc32 :
            {
                //db_write_byte_base64(line->crc32, HASH_CRC32_LEN, (FILE*)dbconf->dbc_out.dbP,i, DB_CRC32,line->attr);
                char * str = db_write_byte_base64_str(line->crc32, HASH_CRC32_LEN, i, DB_CRC32,line->attr);
                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_crc32], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
            case db_crc32b :
            {
                //db_write_byte_base64(line->crc32b, HASH_CRC32B_LEN, (FILE*)dbconf->dbc_out.dbP,i, DB_CRC32B,line->attr);
                char * str = db_write_byte_base64_str(line->crc32b, HASH_CRC32B_LEN, i, DB_CRC32B,line->attr);
                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_crc32b], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
            case db_haval :
            {
                //db_write_byte_base64(line->haval, HASH_HAVAL256_LEN, (FILE*)dbconf->dbc_out.dbP,i, DB_HAVAL,line->attr);
                char * str = db_write_byte_base64_str(line->haval, HASH_HAVAL256_LEN, i, DB_HAVAL,line->attr);
                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_haval], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
            case db_gost :
            {
                //db_write_byte_base64(line->gost , HASH_GOST_LEN, (FILE*)dbconf->dbc_out.dbP,i, DB_GOST,line->attr);
                char * str = db_write_byte_base64_str(line->gost , HASH_GOST_LEN, i, DB_GOST,line->attr);
                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_gost], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
            case db_sha256 :
            {
                //db_write_byte_base64(line->sha256, HASH_SHA256_LEN, (FILE*)dbconf->dbc_out.dbP,i, DB_SHA256,line->attr);
                char * str = db_write_byte_base64_str(line->sha256, HASH_SHA256_LEN, i, DB_SHA256,line->attr);
                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_sha256], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
            case db_sha512 :
            {
                //db_write_byte_base64(line->sha512, HASH_SHA512_LEN, (FILE*)dbconf->dbc_out.dbP,i, DB_SHA512,line->attr);
                char * str = db_write_byte_base64_str(line->sha512, HASH_SHA512_LEN, i, DB_SHA512,line->attr);

                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_sha512], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
            case db_whirlpool :
            {
                //db_write_byte_base64(line->whirlpool, HASH_WHIRLPOOL_LEN, (FILE*)dbconf->dbc_out.dbP,i, DB_WHIRLPOOL,line->attr);
                char * str = db_write_byte_base64_str(line->whirlpool, HASH_WHIRLPOOL_LEN, i, DB_WHIRLPOOL,line->attr);
                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_whirlpool], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
            case db_attr :
            {
                //db_writelong(line->attr, (FILE*)dbconf->dbc_out.dbP,i);
                char * dst = NULL;
                int ret = db_writelong_ram(&dst, line->attr);
                if(ret <= 0 || cJSON_AddStringToObject(fileObj, db_field_names[db_attr], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);
                break;
            }
#ifdef WITH_ACL
            case db_acl :
            {
                //Does not support now
                /*
                db_writeacl(line->acl,(FILE*)dbconf->dbc_out.dbP,i);
                */
                break;
            }
#endif
            case db_xattrs :
            {
                // Does not support now
                /*
                xattr_node *xattr = NULL;
                size_t num = 0;

                if (!line->xattrs)
                {
                    db_writelong(0, (FILE*)dbconf->dbc_out.dbP, i);
                    break;
                }

                db_writelong(line->xattrs->num, (FILE*)dbconf->dbc_out.dbP, i);

                xattr = line->xattrs->ents;
                while (num < line->xattrs->num)
                {
                    dofprintf(",");
                    db_writechar(xattr->key, (FILE*)dbconf->dbc_out.dbP, 0);
                    dofprintf(",");
                    db_write_byte_base64(xattr->val, xattr->vsz, (FILE*)dbconf->dbc_out.dbP, 0, 1, 1);

                    ++xattr;
                    ++num;
                }
                */
                break;
            }
            case db_selinux :
            {
                //db_write_byte_base64((byte*)line->cntx, 0, (FILE*)dbconf->dbc_out.dbP, i, 1, 1);
                char * str = db_write_byte_base64_str((byte*)line->cntx, 0, (FILE*)dbconf->dbc_out.dbP, i, 1, 1);
                if(str == NULL)
                    goto end;

                if(cJSON_AddStringToObject(fileObj, db_field_names[db_selinux], str) == NULL)
                {
                    free(str);
                    goto end;
                }
                break;
            }
#ifdef WITH_E2FSATTRS
            case db_e2fsattrs :
            {
                //db_writelong(line->e2fsattrs,(FILE*)dbconf->dbc_out.dbP,i);
                if(cJSON_AddNumberToObject(fileObj, db_field_names[db_e2fsattrs], line->e2fsattrs) == NULL)
                    goto  end;
                break;
            }
#endif
            case db_checkmask :
            {
                //db_writeoct(line->attr,(FILE*)dbconf->dbc_out.dbP,i);
                char *dst = NULL;
                int ret = db_writeoct(&dst, line->attr);
                if(ret <= 0 || cJSON_AddStringToObject(fileObj, db_field_names[db_checkmask], dst) == NULL)
                {
                    if(dst != NULL)
                        free(dst);
                    goto  end;
                }
                if(dst != NULL)
                    free(dst);
                break;
            }
            default :
            {
                error(0,"Not implemented in db_writeline_file %i\n", dbconf->db_out_order[i]);
                //return RETFAIL;
                return NULL;
            }
        }
    }

    return fileObj;

end:
    fprintf(stdout,"+++++++ dbJSON_line2FileObject() fail at i:%d name:%s\n", i, db_field_names[i]);
    cJSON_Delete(fileObj);
    return NULL;
}

void dbJSON_addNodeInfo2FileObj(cJSON* fileObj, seltree* node)
{
    char * dst = NULL;
    int ret = db_writelong_ram(&dst, node->attr);
    if(ret <= 0 || cJSON_AddStringToObject(fileObj, "attrStr_node", dst) == NULL)
    {
        if(dst != NULL)
        {
            free(dst);
        }
    }
    if(dst != NULL)
    {
        free(dst);
    }

    // changed_attrs
    dst = NULL;
    ret = db_writelong_ram(&dst, node->changed_attrs);
    if(ret <= 0 || cJSON_AddStringToObject(fileObj, "changed_attrs_node", dst) == NULL)
    {
        if(dst != NULL)
        {
            free(dst);
        }
    }
    if(dst != NULL)
    {
        free(dst);
    }

    // checked
    dst = NULL;
    ret = db_writeint_ram(&dst, node->checked);
    if(ret <= 0 || cJSON_AddStringToObject(fileObj, "checked_node", dst) == NULL)
    {
        if(dst != NULL)
        {
            free(dst);
        }
    }
    if(dst != NULL)
    {
        free(dst);
    }

}

int dbJSON_writeFileObject(JsonDB *jDB, seltree* node, db_config* dbconf)
{
    db_line * line = node->new_data;

    cJSON * fileObj = dbJSON_line2FileObject(line, dbconf);
    if(fileObj != NULL)
    {
        if(++jDB->itemCount % 2000 == 0)
            fprintf(stdout,"+++ got JSON file obj %d +++\n", jDB->itemCount);

        //dbJSON_addNodeInfo2FileObj(fileObj, node);
        cJSON_AddItemToArray(jDB->fileList, fileObj);
    }
    return 0;
}

cJSON * dbJSON_RxRule2RxObject(rx_rule *rxRule)
{
    cJSON * item = NULL;
    cJSON * rxRuleObj = NULL;

    if(rxRule == NULL)
    {
        fprintf(stdout, "[%s:%d:%s] return NULL\n", __FILE__, __LINE__, __func__);
        return NULL;
    }

    rxRuleObj = cJSON_CreateObject();
    if(rxRule == NULL)
    {
        fprintf(stdout, "[%s:%d:%s] goto end\n", __FILE__, __LINE__, __func__);
        goto end;
    }

    item = cJSON_AddStringToObject(rxRuleObj, "rx", rxRule->rx);
    if(item == NULL)
    {
        fprintf(stdout, "[%s:%d:%s] goto end, rx:%s\n", __FILE__, __LINE__, __func__, rxRule->rx);
        goto end;
    }

    item = cJSON_AddNumberToObject(rxRuleObj, "cfgNo", rxRule->conf_lineno);
    if(item == NULL)
    {
        fprintf(stdout, "[%s:%d:%s] goto end\n", __FILE__, __LINE__, __func__);
        goto end;
    }

    item = cJSON_AddNumberToObject(rxRuleObj, "attr", rxRule->attr);
    if(item == NULL)
    {
        fprintf(stdout, "[%s:%d:%s] goto end\n", __FILE__, __LINE__, __func__);
        goto end;
    }

    item = cJSON_AddNumberToObject(rxRuleObj, "restriction", rxRule->restriction);
    if(item == NULL)
    {
        fprintf(stdout, "[%s:%d:%s] goto end\n", __FILE__, __LINE__, __func__);
        goto end;
    }

    return rxRuleObj;

end:
    cJSON_Delete(rxRuleObj);
    return NULL;
}

cJSON * dbJSON_RxList2Array(list *rxList)
{
    list * item = NULL;

    cJSON * rxArray = NULL;

    rxArray = cJSON_CreateArray();
    if(rxArray == NULL)
    {
        fprintf(stdout, "[%s:%d:%s] return NULL\n", __FILE__, __LINE__, __func__);
        return NULL;
    }

    if(rxList == NULL)
    {
        return rxArray;
    }

    for(item = rxList; item != NULL; item = item->next)
    {
        rx_rule *rxRule = (rx_rule*)item->data;
        //fprintf(stdout, "[%s:%d:%s] rx:%s \n", __FILE__, __LINE__, __func__, rxRule->rx);
        cJSON * rxJ = dbJSON_RxRule2RxObject(rxRule);
        if(rxJ == NULL)
        {
            fprintf(stdout, "[%s:%d:%s] goto end\n", __FILE__, __LINE__, __func__);
            goto end;
        }

        cJSON_AddItemToArray(rxArray, rxJ);
    }

    return rxArray;

end:
    cJSON_Delete(rxArray);
    return NULL;
}

int dbJSON_WriteRxList(JsonDB *jDB, db_config* conf)
{
    cJSON * rx = cJSON_CreateObject();

    cJSON * sArray = dbJSON_RxList2Array(conf->selrxlst);
    cJSON * nArray = dbJSON_RxList2Array(conf->negrxlst);
    cJSON * eArray = dbJSON_RxList2Array(conf->equrxlst);

    cJSON_AddItemToObject(rx, "sRx", sArray);
    cJSON_AddItemToObject(rx, "nRx", nArray);
    cJSON_AddItemToObject(rx, "eRx", eArray);

    cJSON_AddItemToObject(jDB->db, "rxLists", rx);

    return 0;
}

//int dbJSON_WriteRxCfgs(JsonDB *jDB, )

int dbJSON_close(JsonDB * jDB)
{

    if(jDB->isDump2File)
    {
        dbJSON_save2File(jDB);
        if (chmod(jDB->filePath, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) < 0)
        {
            error(0,_("Couldn't enable file %s for all reading.\n"), jDB->filePath);
        }
        else
        {
            error(0,_("Enabled file %s for all reading success.\n"), jDB->filePath);
        }
    }
    cJSON_Delete(jDB->db);
    return 0;
}

int dbJSON_save2File(JsonDB * jDB)
{
    FILE* fh=NULL;
    int fd;
    struct flock fl;
    char *jDBStr = NULL;

    if(jDB->filePath != NULL)
    {
        jDB->filePath = expand_tilde(jDB->filePath);
        //fd=open(jDB->filePath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
        fd=open(jDB->filePath,O_CREAT|O_RDWR|O_TRUNC,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
        //fd=open(jDB->filePath, O_WRONLY | O_CREAT , 0666);
        if(fd==-1)
        {
            error(0,_("Couldn't open file %s for %s"), jDB->filePath, "writing\n");
            return -1;
        }

        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        if (fcntl(fd, F_SETLK, &fl) == -1)
        {
            if (fcntl(fd, F_SETLK, &fl) == -1)
                error(0,_("File %s is locked by another process.\n"),jDB->filePath);
            else
                error(0,_("Cannot get lock for file %s"),jDB->filePath);
            return NULL;
        }
        if(ftruncate(fd,0)==-1)
            error(0,_("Error truncating file %s"),jDB->filePath);

        fh=fdopen(fd,"w+");
        if(fh==NULL)
        {
            error(0,_("Couldn't fopen file %s for %s"),jDB->filePath, "writing\n");
            return -1;
        }

        fprintf(stdout,"+++ Total got JSON file obj %d +++\n", jDB->itemCount);
        jDBStr = cJSON_Print(jDB->db);
        if(jDBStr != NULL)
        {
            //fprintf(stdout, "\n=== jDB:\n%s\n\n", jDBStr);
            fwrite(jDBStr, 1, strlen(jDBStr), fh);
            free(jDBStr);
        }

        fclose(fh);
    }


    return 0;
}




