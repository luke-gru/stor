#ifndef _STOR_LIST_H_
#define _STOR_LIST_H_

#define LIST_FOREACH(list,type,var,next)\
    for (type var = list; var != NULL; var = var->next)

#endif
