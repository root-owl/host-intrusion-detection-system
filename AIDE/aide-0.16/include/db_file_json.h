/* aide, Advanced Intrusion Detection Environment
 *
 * Copyright (C) 1999-2002,2006 Rami Lehti, Pablo Virolainen, Richard
 * van den Berg
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

#ifndef _DB_FILE_RAM_H_INCLUDED
#define _DB_FILE_RAM_H_INCLUDED

#include "db.h"
#include "cJSON.h"

extern void db_buff(int, FILE*);
extern int db_scan(void); /* Rumaa.... */
extern char* dbtext; /* Todella rumaa... */
extern long* db_lineno;
extern long db_in_lineno;
extern long db_new_lineno;


typedef struct _RamLine {
    unsigned char *data;
    unsigned int size;
    unsigned char *rwPos;
} RamLine;

#define RAMLINE_BLOCK_SIZE  256
#define RAMLINE_SIZE(lineP) lineP->size
#define RAMLINE_LEN(lineP) lineP->rwPos - lineP->data
#define RAMLINE_BUF_LEN(lineP) lineP->size - (lineP->rwPos - lineP->data)


// JSON DB

JsonDB* dbJSON_New(int isDump2File, unsigned char *filePath);
int dbJSON_writespec(JsonDB *jDB, db_config* conf);
int dbJSON_writeFileObject(JsonDB *jDB, seltree* node, db_config *dbconf);
int dbJSON_close(JsonDB * jDB);
int dbJSON_save2File(JsonDB * jDB);

#ifdef WITH_ZLIB
//void handle_gzipped_input_ram(unsigned char *out,gzFile*);
#endif

#endif
