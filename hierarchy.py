from ldap3 import Server, Connection, ALL
from pwd import getpwnam

import datetime

import json

from pathlib import Path
import os,sys,stat

# ==== Active Directory Functions ====

def get_item_from_AD(ip,user,pwd,dc,ldap_query,attributes=["cn"]):
    """
    Performs a LDAP query on a server

    Requires LDAP3

    Arguments:

    ip: the ip or FQDN of the server

    user: user for the binding

    pwd: password for the binding

    DC: domain controller

    ldap_query: a valid ldap_query

    attributes: what ldap attributes should be exported.

    Returns the raw output of the query.
    """
    server = Server(str(ip),get_info=ALL)

    conn = Connection(server,
            user = user,
            password = pwd,
            auto_bind = True)

    conn.search(dc,
            ldap_query,
            attributes=attributes)
    
    return(conn.entries)

def create_AD_json(ip,user,pwd,dc,ldap_query,json_path,root_group_name):
    """
    Performs a LDAP queries and creates a json containing all the groups
    and user beloging to a "root" group

    Requires LDAP3

    Arguments:

    ip: the ip or FQDN of the server
    user: user for the binding
    pwd: password for the binding
    DC: domain controller
    ldap_query: a valid ldap_query
    attributes: what ldap attributes should be exported.
    json_path: the path of the json to be produced. Either relative o absolute
    root_group_name: the name of the AD groupt that contains any other wanted
    group and user.

    Returns the raw output of the query.
    """
    # to be parametrized
    output_json = check_path_exists_is_file(json_path)

    if not output_json:
        sys.exit("The input json does not exist: Exiting...")

    # gets all groups belonging to hpc.users
    groups=get_item_from_AD(ip,user,pwd,dc,ldap_query,["cn","sAMAccountName"])
    
    groups_dn_list=[ str(element).split()[1] for element in groups ]
    
    # gets all users belonging to those groups
    # To be ensembled in a list comprehension
    # the parameter retrieved is the sAMAccountName
    sAMAccountName_list = []
    
    for group in groups:
        DN = str(group).split()[1] 
        user_list=get_item_from_AD(ip,
                user,
                pwd,
                dc,
                "(&(objectClass=user)(memberOf={}))".format(DN),
                ["sAMAccountName"])
        group_dict = {str(group.sAMAccountName): []}
        for element in user_list:
            uid = getpwnam(str(element.sAMAccountName))[2]
            user_dict = { str(element.sAMAccountName): uid }
            group_dict[str(group.sAMAccountName)].append(user_dict)
    
        sAMAccountName_list.append(group_dict)
    
    sAMAccountName_json = { root_group_name : sAMAccountName_list}

    json_file = open(output_json.as_posix(), "r+") 
   
    # traps cases in which the json file is not properly encoded

    try:
        old_data = json.load(json_file)
    except:
        old_data = ""

    if old_data != sAMAccountName_json:
        now = datetime.datetime.now()
        # data in ad chaged: update json
        old_data_json_name = "{}_{}".format(
                now.strftime("%Y%m%d%H%M%S"),
                output_json.name
                )

        old_data_json = os.path.join(output_json.parent.as_posix(),
                old_data_json_name)

        os.system("cp {} {}".format(output_json.as_posix(),
            old_data_json
            ))


        json_file.write(json.dumps(sAMAccountName_json, 
            indent = 4, 
            sort_keys = True)
            )

    json_file.close()
    
    return(sAMAccountName_json)

# ==== Create Directory functions ====

def create_directory_hierarchy(output_folder,json_data):
    """
    given a json in the form of 

    {
    "root_group": [
        {
            "group_1": [
                {
                    "user1": uid
                }
            }
        ]
    }

    produces a folder hierarchy in "ouptut_folder" in the form:

    group1
        user1 (permissions 750 user1:user1)
        group1 (pemissions 750 group1:group1)
    """
    output_folder = Path(output_folder)
    # get the list of element
    root_group = list(json_data.keys())[0]

    for group in json_data[root_group]:
        group_name = list(group.keys())[0]
        group_folder = Path(os.path.join(output_folder.as_posix(),
                group_name))

        os.makedirs(group_folder,mode=0o750,exist_ok = True)
        os.chmod(group_folder,stat.S_ISGID)
        os.chmod(group_folder,0o4750)


        group_folder = Path(os.path.join(group_folder.as_posix(),
                group_name))

        os.makedirs(group_folder,mode=0o750,exist_ok = True)
        os.chmod(group_folder,0o750)


        for user in group[group_name]:

            user_folder = os.path.join(output_folder,
                group_name,
                list(user.keys())[0]) 

            os.makedirs(user_folder,mode=0o740,exist_ok = True)
            os.chmod(user_folder,0o700)

    return(None)

# ==== Files Functions  ====

def check_path_exists_is_file(file_path):
    """
    Checks if the path given as argument is a file.
    If so, returns the a Path object
    else returns False
    """

    if not isinstance(file_path,Path):
        file_path = Path(file_path)

    if file_path.exists():
        if file_path.is_file():
            return (file_path)
        else:
            return (False)
    else:
        return(False)



