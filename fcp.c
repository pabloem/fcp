/*
 *  fcp - Fast CoPy ssh utility
 *
 *  www.github.com/pabloem/fcp
 *
 *  Copyright 2012 Pablo Estrada.  All rights reserved.
 *
 *  Use and distribution licensed under the GPL license.
 *
 *  Author:
 *      Pablo Estrada <pabloem@ucla.edu>
 */


#include <sys/time.h>
#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

/* This is the tracing macro. It can be extended to cover wider needs, but it is
 * enough for now. If we have a file open (traceFile != 0), then we go ahead
 * and write logs to the traceFile
 */
#define write_trace(...) if(traceFile) fprintf(traceFile, __VA_ARGS__);

FILE* traceFile = 0;
char *host = "localhost";
char *username = 0;
int port = 22;
int verbosity = SSH_LOG_NOLOG;
float max_bandwidth = 0;
char *tracefile_name = "tracefile.log";
ssh_session my_ssh_session = 0;

int unattended_mode = 0;

#define NO_LOGGING 1
#define STDOUT_LOGGING 2
#define DO_LOGGING 4
int logging = 0;

/* This function parses a hoststring of the form "[username@]hostname[:filename]
 * It sets the @ and : separators to \0 and sets the pointers to the in-place
 * location of the username, host and filename string.
 * If no user and file name are specified, the pointers are not changed.
 *
 * Arguments:
 * *    hostString  - Input argument with the host string with 
 * *                    format [username@]hostname[:file]
 * *    hostPointer - Pointer to a string pointer that will be assigned 
 * *                    to the parsed hostname
 * *    username    - Pointer to a string pointer that will be assigned
 * *                    to the parsed username
 * *    filename    - Pointer to a string pointer that will be assigned
 * *                    to the parsed filename
 * */
/* This is an awesome comment added in Vim
 * */
int parseHost(char *hostString, char **hostPointer, char **username,
                char **filename)
{
    int i = 0;
    char *currentPointer = hostString;

    while(hostString[i])
    {
        /* If we find the :, we know currentPointer is pointing at the hostname*/
        if( hostString[i] == ':' )
        {
            *hostPointer = currentPointer;
            *filename = &hostString[i] + 1;
            hostString[i] = 0;
            break;
        }
        /* If we find the :, we know currentPointer is pointing at the username*/
        if( hostString[i] == '@' )
        {
            *username = currentPointer;
            currentPointer = &hostString[i] + 1;
            hostString[i] = 0;
        }
        i++;
    }
    if(!hostString[i]) *hostPointer = currentPointer;

    if(!*username)
    { /* If a username was not passed in, we get the one from the parent
       * terminal */
        *username = getlogin();
    }

    write_trace( "Host set to \"%s\"\n", *hostPointer);
    if( *filename )
        write_trace( "Destination filename set to \"%s\"\n", *filename);
    write_trace( "User set to \"%s\"\n", *username);
    return 1;
}

/*
int set_verbosity(char *verbString)*/
/* This function parses the string that comes after the -v option, looking
 * for the logging tags shown on the help option. It parses for the fcp
 * specific logging, and the libssh logging that prints out to stdout
 * Arguments:
 * *    verbString - Pointer to the string that comes after the -v in the
 * *                    input arguments.
 */
int set_verbosity(char *verbString)
{
    do {
        if(strstr(verbString, "no_logging"))
        {/*
            If the user passes the -g option with the -v no_logging option
            the logging will be done visually to stdout.
          */
            logging |= NO_LOGGING;
        }
        if(strstr(verbString, "fcp_logging"))
        {
            logging |= DO_LOGGING;
        }
        if(strstr(verbString, "SSH_LOG_RARE"))
        {
            write_trace( "Setting verbosity to SSH_LOG_RARE\n");
            verbosity = SSH_LOG_RARE;
            break;
        }
        if(strstr(verbString, "SSH_LOG_PROTOCOL"))
        {
            write_trace( "Setting verbosity to SSH_LOG_PROTOCOL\n");
            verbosity = SSH_LOG_PROTOCOL;
            break;
        }
        if(strstr(verbString, "SSH_LOG_PACKET"))
        {
            write_trace( "Setting verbosity to SSH_LOG_PACKET\n");
            verbosity = SSH_LOG_PACKET;
            break;
        }
        if(strstr(verbString, "SSH_LOG_FUNCTIONS"))
        {
            write_trace( "Setting verbosity to SSH_LOG_FUNCTIONS\n");
            verbosity = SSH_LOG_FUNCTIONS;
            break;
        }
        if(strstr(verbString, "SSH_LOG_NOLOG"))
        {
            write_trace( "Setting verbosity to SSH_LOG_NOLOG\n");
            verbosity = SSH_LOG_NOLOG;
            break;
        }
    } while (1!=1);

    return 1;
}

/*
int startUp()*/
/* This function only opens the tracefile, but it is the ideal function to put
 * all the startup code that we might need. It just sets the traceFile
 */
int startUp()
{
    if(logging & STDOUT_LOGGING)
    {
        traceFile = stdout;
        return 1;
    }

    if((logging & NO_LOGGING) && !(logging & DO_LOGGING))
        return 1;

    traceFile = fopen(tracefile_name, "w");

    return 1;
}
/*
int shutDown(int outCode)*/
/* This function does all the cleanup code, and then EXITS the program*/
int shutDown(int outCode)
{
    if(traceFile && traceFile != stdout)
        fclose(traceFile);

    if(my_ssh_session)
        ssh_free(my_ssh_session);

    exit(outCode);
}

int verify_host(ssh_session session)
{
    return 1;
}/*
    int state, hlen;
    char *hash = 0;
    char *hexa;
    
    state = ssh_is_server_known(session);

    hlen = ssh_get_pubkey_hash(session, &hash);

    if( hlen < 0 )
        return -1;

    switch(state)
    {
        case SSH_SERVER_KNOWN_OK:
            break;

        case SSH_SERVER_KNOWN_CHANGED:
            break;
        case SSH_SERVER_FOUND OTHER:
        case SSH_SERVER_FILE_NOT_FOUND:
        case SSH_SERVER_NOT_KNOWN:
        case SSH_SERVER_ERROR:
            break;
        default:
            break;

    }
}*/
/*
int connect_and_auth(ssh_session my_ssh_session)*/
/* This function attempts to connect through an already setup ssh_session
 * If it is able to connect, it validates the host, and then it tries to
 * authenticate through password. If any of these fails, the application
 * exits right away.
 * Arguments:
 * *    my_ssh_session - The already setup ssh_session through which we
 * *                        will try to connect.
 */
int connect_and_auth(ssh_session my_ssh_session)
{
    char *pass;
    int rc;
    char buffer[256];

    rc = ssh_connect(my_ssh_session);
    if( rc != SSH_OK )
    {
        fprintf(stderr, "Error connecting to localhost!: %s\n", 
                        ssh_get_error(my_ssh_session));
        shutDown(-1);
    }

    verify_host(my_ssh_session);

    sprintf(buffer, "%s@%s's password: ", username, host);
    pass = getpass(buffer);

    rc = ssh_userauth_password(my_ssh_session, NULL, pass);
    if ( rc != SSH_AUTH_SUCCESS )
    {
        fprintf(stderr, "Error authenticating with password\n");
        write_trace("Error authenticating with password\n");
        ssh_disconnect(my_ssh_session);
        shutDown(-1);
    }
    write_trace( "Succesfully authenticated with password!!!\n");

    free(pass);

    return 1;
}

/*
int setup_session(ssh_session *my_session)*/
/* This function creates a new ssh session, and sets up ssh session 
 * parameters, such as the host, port, verbosity and username (if there is one).
 * Arguments:
 * *    my_session - pointer to a ssh_session pointer. It is changed to
 * *                    point to the newly created ssh_session
 */
int setup_session(ssh_session *my_session)
{
    *my_session = ssh_new();
    if ( *my_session == NULL )
        shutDown(-1);

    ssh_options_set(*my_session, SSH_OPTIONS_HOST, host);
    ssh_options_set(*my_session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(*my_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    if( username ) /* We should always have a username, but let's just keep this */
        ssh_options_set(*my_session, SSH_OPTIONS_USER, username);

    return 1;
}

/*
void display_help_exit()*/
/* This function does what it seems it does. Displays the help and then exits
 */
void display_help_exit()
{ /* TODO Write the help information */
    printf("fcp - Fast CoPy utility for Linux\n"
            "This utility works under ssh. It is similar to scp, and it counts\n"
            "with some extra options to customize its behavior.\n"
            "Usage:\n"
            "\tfcp FROM TO [options]\n"
            "\tFROM := filename in local machine\n"
            "\tTO := [user@]host[:filename]  -- All of these are the destination\n"
            "Options:\n"
            "-p <num>\t: Port number\n"
            "-v <level>\t: Verbosity levels for fcp and libssh, given in a comma_separated list\n\n"
            "\tfcp Logging Levels:\n"
            "\t\tno_logging  - This turns off fcp logging\n"
            "\t\tfcp_logging - This turns on fcp logging (overrides no_logging)\n"
            "\tlibssh logging levels:\n"
            "\t\tSSH_LOG_RARE, SSH_LOG_PROTOCOL, SSH_LOG_FUNCTIONS, SSH_LOG_NOLOG, SSH_LOG_PACKET\n"
            "\t\t -- These are the libssh logging levels. They log to stdout\n\n"
            "-o\t\t: Overwrite. If the file exists on the remote host overwrite it\n"
            "-u\t\t: Unattended mode. Do not block the console and transfer on\n"
            "\t\t  background\n"
            "-h\t\t: Help. Display this help and exit\n"
            "-b <num>\t: Set the bandwidth in kilobytes per second\n"
            "-t <file>\t: Set a custom logfile. [Default: tracefile.log]\n"
            "-g\t\t: Graphic logging. Display logging information to stdout\n"
            "\t\t  This will force normal logging, even if the no_logging flag is passed\n"
            );
    shutDown(1);
}


/*
int parse_options(char *argv[], int argc)*/
/* This function takes the argv and argc passed in to main, and it parses the options
 * according to our rules. 
 * NOTE: NONE OF THE TRACING MADE BY THIS FUNCTION OR ANY OF ITS CALLERS WILL
 *       ACTUALLY MAKE IT INTO THE TRACEFILE, SINCE AT THIS POINT WE HAVE NOT
 *       SET UP THE TRACEFILE
 * Arguments:
 * *    argv - The array of char pointers to the last argc-2 options passed to main
 * *            (It is argc-2 because the first two are necessary, and parsed
 * *             beforehand)
 * *    argc - The count of char pointers in the array passed in
 * Effect:
 * *        It sets all the globals with information about the logfile, port,
 * *        verbosity of logging, maximum bandwidth, etc.
 */
int parse_options(char *argv[], int argc)
{
    int c = 0;

    while(-1 != ( c = getopt(argc, argv,
                    "p:"  // port number
                    "v:"  // verbosity
                    "o"   // overwrite destination file
                    "u"   // unattended mode (might be better to do it through a shell script)
                    "h"   // display help and exit
                    "b:"  // select bandwidth in kbps
                    "t:"  // setting the logfile in a specific location
                    "g"   // 'graphic' logging - log to stdout?
                    )))
    {
        switch (c)
        {
            case 'p':
                port = atoi(optarg);
                break;
            case 'v':
                set_verbosity(optarg);
                break;
            case 'o':
                break;
            case 'u':
                unattended_mode = 1;
                break;
            case 'h':
                display_help_exit();
                break;
            case 'b':
                max_bandwidth = atof(optarg);
                break;
            case 't':
                tracefile_name = optarg;
                break;
            case 'g':
                /* We set no_logging to 1 so that traceFile 
                 * will not be changed by startUp*/
                logging |= STDOUT_LOGGING; 
                break;
            default:
                fprintf(stderr, "Wrong number or types of arguments\n");
                shutDown(-1);
                break;
        }
    }
    return 1;
}

/*
int get_file_mode(FILE *fd, int *mode)*/
/* This function fills the mode of a certain file 
 * Arguments:
 * * fd     - File descriptor to the file we're transfering
 * * mode   - An integer pointer to the variable where we'll store the
 * *            file mode
 */
int get_file_mode(FILE *fd, int *mode)
{
    struct stat finfo;
    
    fstat(fileno(fd), &finfo);

    /* We want to format the st_mode variable to look like any ordinary UNIX 
     * file mode, so we want to do a couple of shiftings in the bits
     */
    *mode = (finfo.st_mode & (S_IXOTH | S_IWOTH | S_IROTH)) +
            ((finfo.st_mode & (S_IXGRP | S_IWGRP | S_IRGRP)) << 1) +
            ((finfo.st_mode & (S_IXUSR | S_IWUSR | S_IRUSR)) << 2) ;

    return 1;
}
/*
int send_file(char *local_filename, char *remote_filename)*/
/* This function is in charge of sending the file we intend to pass
 * through the network. It takes the local and remote filenames,
 * creates a ssh_channel and exchanges information through it.
 * To create a file, we use the 'cat' unix command, and the
 * 'chmod' command to set file permissions
 * Arguments:
 * *    local_filename - String pointer to the file name of the file
 * *                        in the local machine
 * *    remote_filename - String pointer to the file name of the file
 * *                        in the remote machine
 */
int send_file(char *local_filename, char *remote_filename)
{
    ssh_channel my_channel;
    int nbytes;
    int sent_bytes = 0;
    int read_bytes = 0;
    char buffer[1024];
    struct timeval start;
    struct timeval now;
    float bandwidth;
    int cycles = 0;
    int incidences = 0;
    FILE *transfer_me = 0;
    int file_mode = 0;
    int rc;

    transfer_me = fopen(local_filename, "r");
    if( transfer_me == NULL )
    {
        write_trace( "Could not open file to transfer\n");
        shutDown(-1);
    }

    get_file_mode(transfer_me, &file_mode);
    write_trace( "File mode is %x\n", file_mode);

    my_channel = channel_new(my_ssh_session);
    if(my_channel == NULL)
        shutDown(SSH_ERROR);
    write_trace( "Created new channel\n");

    rc = channel_open_session(my_channel);
    if(rc != SSH_OK)
    {
        channel_free(my_channel);
        shutDown(rc);
    }
    write_trace( "Channel session opened\n");

    sprintf(buffer, "cat > %s ; chmod %x %s", 
                remote_filename, file_mode, remote_filename);
    write_trace( "Command: %s\n", buffer);
    rc = channel_request_exec(my_channel, buffer);

    if(rc != SSH_OK)
    {
        channel_close(my_channel);
        channel_free(my_channel);
        shutDown(rc);
    }
    write_trace( "Request executed\n");

    gettimeofday(&start, NULL);
    nbytes = fread(buffer, 1, sizeof(buffer), transfer_me);
    read_bytes += nbytes;
    while( nbytes == sizeof(buffer) )
    {
        rc = channel_write(my_channel, buffer, nbytes);
        if(rc == SSH_ERROR)
        {
            channel_close(my_channel);
            channel_free(my_channel);
            shutDown(rc);
        }
        sent_bytes += rc;

#define BANDWIDTH_MEASURE 3
        cycles++;
        if(cycles % BANDWIDTH_MEASURE == 0)
        {
            gettimeofday(&now, NULL);
            bandwidth = 0.7*bandwidth + 0.3*(sent_bytes/
                        ((now.tv_sec - start.tv_sec)*1000 + (now.tv_usec - start.tv_usec)/1000.0));

            /*
             * The following line prints the weighted bandwidth we use to the trace file,
             * The bandwidth function is weighted to not overcompensate when we use
             * too much speed at the begining of the connection
             */
            /*write_trace( "Weighted bandwidth %5.2f bytes per milisec\n", bandwidth);
             */
            
            if(max_bandwidth && bandwidth > max_bandwidth)
            {
                incidences++;
                usleep(incidences*100);
            }
            else
                incidences = 0;
        }

        nbytes = fread(buffer, 1, sizeof(buffer), transfer_me);
        read_bytes += nbytes;
    }

    rc = channel_write(my_channel, buffer, nbytes);
    sent_bytes += rc;
    bandwidth = (sent_bytes)/
                ((now.tv_sec - start.tv_sec)*1000 + (now.tv_usec - start.tv_usec)/1000.0);
    write_trace( "Bandwidth %5.2f bytes per milisec\n", bandwidth);

    gettimeofday(&now, NULL);
    write_trace( "Sent %d bytes through channel\n", sent_bytes);
    write_trace( "Read %d bytes from file\n", read_bytes);
    write_trace( "Elapsed time: %f miliseconds\n", 
                        (now.tv_sec - start.tv_sec)*1000 + (now.tv_usec - start.tv_usec)/1000.0);
    write_trace( "Total bandwidth %5.2f\n", read_bytes / 
                        ((now.tv_sec - start.tv_sec)*1000 + (now.tv_usec - start.tv_usec)/1000.0));

    channel_send_eof(my_channel);
    write_trace( "Sent EOF through channel\n");

    nbytes = channel_read(my_channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0)
    {
        if (write(1, buffer, nbytes) != nbytes)
        {
            channel_close(my_channel);
            channel_free(my_channel);
            shutDown(SSH_ERROR);
        }
        nbytes = channel_read(my_channel, buffer, sizeof(buffer), 0);
    }

    channel_close(my_channel);
    channel_free(my_channel);

    return 1;
}

/*
int default_destfile(char *from, char **dest_file)*/
/* This function sets the dest_file pointer to the file name for which 
 * from holds the full path, so if:
 * from = mydir/filename, this function sets dest_file = filename
 * Arguments:
 * *    from        - String pointer to the origin file
 * *    dest_file   - Pointer to the string pointer for the destination
 *                      file
 */
int default_destfile(char *from, char **dest_file)
{
    int i = 0;

    *dest_file = from;
    for(i=0 ; from[i] ; i++)
    {
        if( from[i] == '/' )
            *dest_file = &from[i+1];
    }
    write_trace("Destination file set to \"%s\"", *dest_file);

    return 1;
}

int main(int argc, char *argv[])
{
    char *dest_file = 0;
    char *from = 0;
    int pid;

    if(!strcmp(argv[1], "-h"))
        display_help_exit();

    /* First we need to parse the extra input options */
    parse_options(&argv[2], argc - 2);

    startUp();

    if( argc >= 2 )
    {
        from = argv[1];
        write_trace( "From set to \"%s\"\n", from);
    }
    if( argc >= 3 )
    {
        parseHost(argv[2], &host, &username, &dest_file);
    }

    /* If the user did not provide the destination file, then
     * we set it to the default
     */
    if( dest_file == 0 )
    {
        default_destfile(from, &dest_file);
    }
   
    /* If we made it here, then we start the session, and setup the parameters
     */
    setup_session(&my_ssh_session);


    /* After setup has been done, we connect and authenticate with the server.
     * In the following call we request the password from the console.
     */
    connect_and_auth(my_ssh_session);

    /* If we want to run in unattended mode, we fork out and leave */
    if(unattended_mode)
    {
        if((pid = fork()) < 0)
            printf("Could not run unattended, running normally\n");
        else if( pid != 0 )
            shutDown(1);
    }

    /* The following code is code for the whole communication process
     */
    send_file(from, dest_file);


    ssh_disconnect(my_ssh_session);

    shutDown(1);

    return 1;
}
