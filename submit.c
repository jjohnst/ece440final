#include "rollcall.h"

int main(void)
{
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    char command[COMMAND_SIZE];

    conn = mysql_init (NULL);
    if (conn == NULL){
        fprintf (stderr, "mysql_init() failed (probably out of memory)\n");
        exit (1);
    }

    if (mysql_real_connect (
                conn, //Pointer to connection handler 
                def_host_name, //Host to connect to 
                def_user_name, //User name 
                def_password, //Password 
                def_db_name, //Database to use 
                0, //Port (use default) 
                NULL, //Socket (use default) 
                0) //Flags (none) 
            == NULL)
    {
        fprintf (stderr, "mysql_real_connect() failed:\nError %u (%s)\n", mysql_errno (conn), mysql_error (conn));
        exit (1);
    }
    fp = fopen("absences.log", "r");
    if (fp == NULL)
        exit(2);

    while ((read = getline(&line, &len, fp)) != -1) {
        line[17] = '\0'; //put null at end of string
        snprintf(command, COMMAND_SIZE, "UPDATE student SET absences = absences + 1 WHERE mac='%s'", line);
        if (mysql_query (conn, command) != 0){
            printf("mysql_query() failed\n");
        }else{
            printf("Student marked absent\n");
        }
    }
    fclose(fp);
    mysql_close (conn);

    if (line)
        free(line);
    exit(EXIT_SUCCESS);
}