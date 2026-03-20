# ngfw_policy.py

This script creates a NGFW policy and the groups of interest (security_data_prefix_list, security_port_list, security_zone_list) that the NFGW will use. The script is divided in 2 Phases:  

Phase 1: Reads the policy objects (Data Prefixes, Port Lists, Security Zones) from the .xlsx file and uploads them to vManage.  

Phase 2: Reads the NGFW rules from the "NGFW Rules" sheet and creates / updates the profile in the vManage  

Both phases can be ran individually or at the same time.


## Usage

### 1. Create a xlsx file with next information: 

**a) Sheet "Data Prefixes"**

| Col A | Col B | 
|-----|-----|
|Data Prefix Name|Value (s) separated by commas

Example:
| Col A | Col B | 
|-----|-----|
|Prefix_Test_1|10.10.10.10/32,10.10.10.11/32



**b) Sheet "Port Lists"**

| Col A | Col B | 
|-----|-----|
|Port List Name|Value (s) separated by commas

Example:
| Col A | Col B | 
|-----|-----|
|Port_List_1|43,80,1100-1150



**c) Sheet "Security Zones"**

| Col A | Col B | Col C |
|-----|-----|-----|
|Security Zone Name|Type|Value (s) separated by commas

Example: 
| Col A | Col B | Col C |
|-----|-----|-----|
|Security_Zone_1|Interface|GigabitEthernet1,GigabitEthernet2
|Security_Zone_2|VPN|VPN_Service_Test

**Note: the VPN must've been created before using the same in the xlsx file**



**d) Sheet "NGFW Rules"**

| SOURCE ZONE | DST ZONE | TYPE OF DATA PREFIX SOURCE | DATA PREFIX SOURCE | TYPE OF DATA PORT SOURCE | PORT SOURCE | TYPE OF DATA PREFIX DESTINATION | DATA PREFIX DESTINATION | TYPE OF DATA PORT DST | PORT DST | TYPE OF DATA PROTOCOL | DATA PROTOCOL | ACTION | DEFAULT ACTION |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|

Column name | Expected Content |
|-----|-----|
SOURCE ZONE | ZONE NAME
DST ZONE | ZONE NAME
TYPE OF DATA PREFIX SOURCE | object or value
DATA PREFIX SOURCE | object_name or IP value(s)
TYPE OF DATA PORT SOURCE | object or value
PORT SOURCE | object_name or Port value(s)
TYPE OF DATA PREFIX DESTINATION | object or value
DATA PREFIX DESTINATION | object_name or IP value(s)
TYPE OF DATA PORT DST | object or value
PORT DST | object_name or Port value(s)
TYPE OF DATA PROTOCOL | object or value or name
DATA PROTOCOL | object_name or protocol name or value
ACTION | inspect / pass / drop
DEFAULT ACTION | drop / pass

**Note: Refer to the .xlsx file on this repository to see an example**

### 2. Run the script and write the required information  

**a) You can run either Phase 1 or Phase 2, or both:**   
```sh
Enter vManage Host (e.g., 198.168.1.100): 192.168.1.100  
Enter Username: admin  
Enter Password:  
Enter Excel File Name (.xlsx): example.xlsx  

--- Phase Selection ---  
  1 = Run Phase 1 only  (Upload policy objects)  
  2 = Run Phase 2 only  (Create/Update NGFW policies)  
  3 = Run Both Phases   (Phase 1 then Phase 2)  
Select phases to run [3]:  
```

**b) if you choose Phase 2 only or both phases, you will need to specify if the script will create or update the NGFW policy**  
```sh
--- Phase 2: NGFW Policy Configuration ---  
Enter New Policy Name: new_policy  
Enter New Policy Description: Creation of new_policy  
Enter Mode ('create' or 'update') [create]:  create
```
When the script ends, next output will be shown:  
```sh  
  ✅ PHASE 2 CREATE COMPLETE!  

  Profile ID: xxxxxxx-yyyy-zzzz-aaaa-bbbbbbbb 
  Policy ID:  jjjjjjj-kkkk-llll-mmmmmm-oooooooo
  ...  
  ...  
  
  Default Actions Used:  
    Security_Zone_1 -> Security_Zone_2: DROP  
  
  ─── FOR FUTURE UPDATES ───────────────────────────  
  Set these in the script and change MODE to 'update':  
  
  MODE = "update"  
  EXISTING_PROFILE_ID = "xxxxxxx-yyyy-zzzz-aaaa-bbbbbbbb"  
  EXISTING_POLICY_ID  = "jjjjjjj-kkkk-llll-mmmmmm-oooooooo"  
```  
**Note : You will need the "EXISTING_PROFILE_ID" and the "EXISTING_POLICY_ID" if you use the "update" mode of this script to update the NGFW policy**


**c) If mode is "update", next menu will be shown to specify the NGFW policy to be updated**  
```sh   
--- Phase 2: NGFW Policy Configuration ---  
Enter New Policy Name: new_policy  
Enter New Policy Description: new_policy  
Enter Mode ('create' or 'update') [create]: update  
Enter Existing Profile ID: xxxxxxx-yyyy-zzzz-aaaa-bbbbbbbb  
Enter Existing Policy ID: jjjjjjj-kkkk-llll-mmmmmm-oooooooo  
```

## Output

.json files with the json payload for all lists and created policies







