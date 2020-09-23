#!/usr/bin/env python3.6

import botocore
import boto3
from boto3.session import Session
from botocore.exceptions import ClientError
import time
import os
from datetime import date

dt=date.today()
dtstr=dt.strftime("%Y-%m-%d")

dry_run=False
search_tag = "Name" # Tag to search for instances
search_value = "dtest*"  #value in tag to search for instances 
snap_prefix = dtstr+"-pre-termination-snapshot" #snapshot description
arole="AddARoleHere" #role to assume across accounts
accounts = ['0000000000000','1111111111111'] # list of accounts e.g ['0000000000000','1111111111111','2222222222222222','333333333333333333']
total_acc = len(accounts)
print(f"{total_acc} AWS account(s) detected")

def assume_roles(acc,accounts,arole):
    global acc_key
    global sec_key
    global sess_tok
    global client
    #print(f"Initating assume role for account : {acc}")
    print(f"Assuming role")
    sts_conn = boto3.client('sts')
    #print(f"role defined :{arole}")
    #print(f"account defined :{acc}")
    tmp_arn = f"{acc}:role/{arole}"
    #print(tmp_arn)
    response = sts_conn.assume_role(DurationSeconds=900,RoleArn=f"arn:aws:iam::{tmp_arn}",RoleSessionName='Test')
    acc_key = response['Credentials']['AccessKeyId']
    sec_key = response['Credentials']['SecretAccessKey']
    sess_tok = response['Credentials']['SessionToken']
    #print(f"Access key = {acc_key}")

def get_instances(process_acc,filters=[{'Name': 'tag:'+search_tag, 'Values': [search_value]}]):
    reservations = {}
    try:
        reservations = ec2.describe_instances(
            Filters=filters
        )
    except botocore.exceptions.ClientError as e:
        print(e.response['Error']['Message'])
    instances = []
    for reservation in reservations.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            instances.append(instance)
    return instances 

def shutdown_instance(Iid):
    print(f"Instance is running, shutting down prior to creating snapshot(s) of attached volume(s)")
    ec2.stop_instances(InstanceIds=Iid)
    shutdown_instance_wait(Iid)

def shutdown_instance_wait(Iid):
    shutdown_instance_waiter = ec2.get_waiter('instance_stopped')
    try:
        shutdown_instance_waiter.wait(InstanceIds=Iid)
        print(f"Instance {Iid[0]} has shutdown successfully")
    except botocore.exceptions.WaiterError as er:
        if "Max attempts exceeded" in er.message:
            print(f"Instance {Iid[0]} did not shutdown in 600 seconds")
        else:
            print(er.message)
            
def create_snapshots_wait(snap_check):
    try:
        create_snapshot_waiter = ec2.get_waiter('snapshot_completed')
        print(f"Waiting for {snap_check}")
        create_snapshot_waiter.wait(SnapshotIds=snap_check)  
    except botocore.exceptions.WaiterError as er:
        if "Max attempts exceeded" in er.message:
            print(f"Instance {Iid[0]} did not shutdown in 600 seconds")
        else:
            print(er.message)

def check_volumes(Iid,inst):
    terminate_check=[]
    print(f"Checking volumes attached to {Iid} for Termination settings")
    for bdevice in inst.get('BlockDeviceMappings'):
        vol = bdevice.get('Ebs') #type
        volatt = bdevice.get('DeviceName') #attachment, always useful
        delter = vol.get('DeleteOnTermination')
        if delter == False:
            print(f"deleteontermination check : EBS is not set to delete on termination, lets fix that")
            #Build a json file
            #what do we need
            #[{"DeviceName": "/dev/sda1","Ebs": {"DeleteOnTermination": true}}]
            delonterm = ec2.modify_instance_attribute(
                Attribute='blockDeviceMapping',
                BlockDeviceMappings=[
                    {
                        'DeviceName': volatt,
                        'Ebs': {
                            'DeleteOnTermination': True,
                            }}],
                            InstanceId=Iid[0])
            #print(delonterm)
        else:
            print(f"deleteontermination check : EBS will be deleted, no change required")


def snapshot_volumes(Iid,inst):
    snap_check=[]
    print(f"Processing volumes attached to {Iid[0]} for snapshot")
    snap_shot = ec2.create_snapshots(
        Description=snap_prefix,
        InstanceSpecification={
            'InstanceId': Iid[0],
            'ExcludeBootVolume': False
        },
        DryRun=dry_run,
        CopyTagsFromSource='volume'
    )
    #build a list of snapshotids so we can check if they are complete - waiter
    for snapid in snap_shot.get('Snapshots'):
        #print(snapid.get('SnapshotId'))
        snap_check.append(snapid.get('SnapshotId'))
    create_snapshots_wait(snap_check)

def terminate_instances(Iid,FailedIid,SuccessIid):
    print(f"Proceding with termination of {Iid[0]}")
    try:
        terminate_instance = ec2.terminate_instances(
            InstanceIds=Iid,
            DryRun=dry_run
        )
        SuccessIid.append(Iid[0])
    except ClientError as er:
        FailedIid.append(Iid[0])
        print(f"an error occured terminating {Iid[0]} - {err.message}")

def main():
    global ec2
    global instances
    processing_acc = 0
    FailedIid = []
    SuccessIid = []
    #retrieve account context the script is executing so we know whether to assume a role or not
    client = boto3.client("sts")
    account_id = client.get_caller_identity()["Account"]
    #print(f"script is executing in {account_id}")
    for acc in accounts:
        processing_acc += 1
        print(f"Processing account : {processing_acc}")
        if acc != account_id:
            assume_roles(acc,accounts,arole)
            ec2 = boto3.client('ec2',aws_access_key_id=acc_key,aws_secret_access_key=sec_key,aws_session_token=sess_tok,region_name='eu-west-1')
        else:
            print(f"Execution account, no assume required")
            ec2=boto3.client('ec2')
        instances = get_instances(processing_acc)
        #print(instances)
        # print instance names
        for inst in instances:
            #print(inst) # returns all of the instances meta-data
            Iid = []
            Iid.append(inst.get('InstanceId'))
            Istate = inst.get('State')
            IstateCode = Istate.get('Code')
            #The for and first if can be removed, used to retrieve the name tag for verbose output
            for tags in inst.get('Tags'):
                if tags["Key"] == 'Name':
                    Iname = tags["Value"]
                    #print(inst.get('InstanceId'))
                    print(f"Instance Name : {Iname} ; Instance Id : {Iid[0]} ; Instance state : {IstateCode}")
                    #EC2 Instance States = 0 : pending ; 16 : running ; 32 : shutting-down ; 48 : terminated ; 64 : stopping ; 80 : stopped
                    if IstateCode == 16 or IstateCode ==32 or IstateCode == 64 or IstateCode == 80:
                        if IstateCode == 16:
                            #print("Instance is running") # proceed to shut it down
                            shutdown_instance(Iid)
                        elif IstateCode == 32 or IstateCode == 64: 
                            print("Instance is already shutting down, calling waiter")
                            shutdown_instance_wait(Iid)
                        elif IstateCode == 80:
                            print(f"Instance is stopped")
                        check_volumes(Iid,inst)
                        snapshot_volumes(Iid,inst)
                        terminate_instances(Iid,FailedIid,SuccessIid)
                    else:
                        print(f"Warning : Instance {Iid[0]} is not running, stopping or stopped. Please perform a manual check")
                        FailedIid.append(Iid[0])
    print(f"Terminated : {SuccessIid}")
    print(f"Failed to Terminate : {FailedIid}")
            

if __name__ == "__main__":
    main()
