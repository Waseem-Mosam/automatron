from django.shortcuts import render
from django.contrib import messages
from django.http import HttpResponse
from django.template import loader

# Packages necessary for API
import requests, json, pprint

#Issuing the API client an access token
from base64 import b64encode

# Base variables
client_id = 'bcaca1e6-fe48-49da-8484-8853b7497587'
client_secret = 'izk6tia6jtjg7mqjfbdnpxf2miadabojof3xkrpjefrdkvsebeai'
datacenter_url = 'https://eu2-cloud.acronis.com'

#Set base url
base_url = f'{datacenter_url}/api/2'

#Encode the client ID and client secret string using Base64 encoding
encoded_client_creds = b64encode(f'{client_id}:{client_secret}'.encode('ascii'))

#Assign an object with the Authorization key containing authentication data
basic_auth = {'Authorization': 'Basic ' + encoded_client_creds.decode('ascii')}

#Send a POST request to the /idp/token endpoint
response = requests.post(
        f'{base_url}/idp/token',
        headers={'Content-Type': 'application/x-www-form-urlencoded', **basic_auth},
        data={'grant_type': 'client_credentials'},
    )


#Convert the JSON text that the response body contains to an object
token_info = response.json()

#Assign an object, that will be used for constructing an Authorization header in API requests
auth = {'Authorization': 'Bearer ' + token_info['access_token']}

#To be used for scoped JWT tokens
access_token = token_info['access_token']

#Fetching the ID of the clients tenant
response = requests.get(f'{base_url}/clients/{client_id}', headers=auth)


#Assign the ID of the tenant, fetched from the response body
tenant_id = response.json()['tenant_id']

#Application is now set up to access API


# Create your views here.
def home(request):
    return render(request, "index.html")

def register(request):

    #Fetch form data
    if (request.method == "POST"):
        customerName = request.POST['customerName']
        customerAdd = request.POST['customerAdd']
        customerEmail = request.POST['customerEmail']
        customerPhone = request.POST['customerPhone']
        
        #create customer
        createCustomer(customerName,customerAdd, customerEmail, customerPhone, request)

    return render(request, "index.html")

def createCustomer(name, address, email, phone, request):

    #Creating a customer tenant
    tenant = {
        'name': name,
        'kind': 'customer',
        'parent_id': tenant_id,
        'internal_tag': '007',
        'language': 'en',
        'contact': {
            'address1': address,
            'email': email,
            'phone': phone,
        },
    }

    #Convert the tenant object to JSON
    tenant = json.dumps(tenant, indent=4)

    #Send a POST request with the JSON text to the /tenants endpoint:
    response = requests.post(
        f'{base_url}/tenants',
        headers={'Content-Type': 'application/json', **auth},
        data=tenant,
    )

    #Check the response (201 means success)
    if (response.status_code == 201):
        messages.info(request, 'Customer created successfully.')
    else:
        messages.info(request, 'Customer creation failed.')
    
    # print(response.status_code)

    #Convert the JSON text that the response body contains to an object and store the value of the object’s id key
    created_tenant_id = response.json()['id']

    print("Created Tenant ID: ",created_tenant_id)


# Retrieve Customer Information
def retrieveInfo(request):
    if (request.method == "POST"):
        clientID = request.POST['clientID']
    customer_tenant = clientID
    tenant_id = customer_tenant

    #Send a GET request to the /tenants/{tenant_id} endpoint:
    response = requests.get(f'{base_url}/tenants/{tenant_id}', headers=auth)

    #check response status (200 means success)
    # if (response.status_code == "200"):
        #Convert the JSON text that the response body contains to an object
    tenant = response.json()
    name = response.json()['name']
    enabled = response.json()['enabled']
    kind = response.json()['kind']
    address = response.json()['contact']['address1']
    phone = response.json()['contact']['phone']
    email = response.json()['contact']['email']

    pprint.pprint(tenant)
    template = loader.get_template('reports.html')
    context = {
    'name': name,
    'enabled' : enabled,
    'kind' : kind,
    'address': address,
    'phone': phone,
    'email':email,
    }
    return HttpResponse(template.render(context, request))
    #return render(request, "reports.html")




#Creating a user
def registerUser(request):
    if (request.method == "POST"):
        customerID = request.POST['customerID']
        username = request.POST['username']
        firstName = request.POST['firstName']
        lastName = request.POST['lastName']
        email = request.POST['email']
        role = request.POST['role']


    login = username  # username as login
    params = {"username": login}

    #check if login is available
    response = requests.get(f'{base_url}/users/check_login', headers=auth, params=params)

    #check response code
    #print(response.status_code)

    #Assign user account info
    user_data = {
    "tenant_id": customerID,
    "login": login,
    "contact": {
    "email": email,
    "firstname": firstName,
    "lastname": lastName,
    "types": ["billing"]
    }
    }

    #convert user_data object to JSON text
    user_data = json.dumps(user_data, indent=4)

    #Send a POST request with the JSON text to the /users endpoint:
    response = requests.post(
    f'{base_url}/users',
    headers={'Content-Type': 'application/json', **auth},
    data=user_data,
    )

    #check the response (200 means success)
    print("Status Code: ",response.status_code)

    #pprint.pprint(response.json())

    user_id = response.json()['id']
    print(user_id)
    status = response.status_code
    

    personal_tenant_id = response.json()['personal_tenant_id']
    #print(personal_tenant_id)
    #activate a user account through email
    response = requests.post(f'{base_url}/users/{user_id}/send-activation-email', headers={'Content-Type': 'application/json', **auth})

    # Assigning a role to a user
    #assign the items array of the access policy objects with a new role to this variable
    policies_object = {
        "items": [
            {
                "id": "00000000-0000-0000-0000-000000000000",
                "issuer_id": "00000000-0000-0000-0000-000000000000",
                "trustee_id": user_id,
                "trustee_type": "user",
                "tenant_id": customerID,
                "role_id": role,
                "version": 0
            }
        ]
    }

    #Convert the policies_object object to a JSON text
    policies_object = json.dumps(policies_object, indent=4)

    #Send a PUT request with the JSON text to the /users/{user_id}/access_policies endpoint
    response = requests.put(
        f'{base_url}/users/{user_id}/access_policies',
        headers={'Content-Type': 'application/json', **auth},
        data=policies_object,
    )

    #check the status code 
    print("User role status: ",response.status_code)

    # if (status == 200):
    #     messages.info(request, 'User created successfully.')
    # else:
    #     messages.info(request, 'User creation failed.')
    
    # return render(request, "index.html")
    messageDisplay = []
    template = loader.get_template('index.html')
    if(status == 200):
        messageDisplay.append("User created successfully.")
    else:
        messageDisplay.append("User creation failed.")
    context = {
    'messageDisplay': messageDisplay,
    }
    return HttpResponse(template.render(context, request))


# Retrieve User Information
def retrieveUserInfo(request):
    if (request.method == "POST"):
        userID = request.POST['userID']

    user_id = userID

    #Send a GET request to the /tenants/{tenant_id} endpoint:
    response = requests.get(f'{base_url}/users/{user_id}', headers=auth)

    login = response.json()['login']
    firstname = response.json()['contact']['firstname']
    lastname = response.json()['contact']['lastname']
    email = response.json()['contact']['email']

    template = loader.get_template('reportsUser.html')
    context = {
    'firstname': firstname,
    'lastname' : lastname,
    'login' : login,
    'email':email,
    }
    return HttpResponse(template.render(context, request))

#Create a scoped access token
def scopedAccessToken(customer_tenant_id):
    #Body containing necessary parameters
    params = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': f'{access_token}',
        'scope': f'urn:acronis.com:tenant-id:{customer_tenant_id}'
    }


    response = requests.post(
        f'{base_url}/idp/token',
        headers={'Content-Type': 'application/x-www-form-urlencoded', **auth},
        data=params
    )

    token_info2 = response.json()
    auth2 = {'Authorization': 'Bearer ' + token_info2['access_token']}

    return auth2

#Create a protection plan
#Current implementation creates a predfined plan 
def createProtection(request):
    if (request.method == "POST"):
        customer_tenant_id = request.POST['customerID']
    
    auth2 = scopedAccessToken(customer_tenant_id)
    #Import the uuid4 function from the uuid python module:
    from uuid import uuid4

    #assign the UUID generated with the uuid4() function and converted to string
    protection_plan_id = str(uuid4())
    print("protection plan id: ",protection_plan_id)

    #assign an object with the subject key with an object containing the policy key with an array containing a total protection policy
    plan_data = {
        'subject': {
            'policy': [
                {
                    'id': protection_plan_id,
                    'type': 'policy.protection.total',
                    'origin': 'upstream',
                    'enabled': True,
                    'name': 'New Plan'
                }
            ]
        }
    }

    #Define the variable named policies and assign it with the list of protection policy objects.
    policies = [

        {
            "id": str(uuid4()),
            # Machine backup policy type is 'policy.backup.machine'
            'type': 'policy.backup.machine',
            'parent_ids': [
                protection_plan_id
            ],
            'origin': 'upstream',
            'enabled': True,
            'settings_schema': '2.0',
            'settings': {
                # Archive compression level. Available values: ``normal``, ``high``, ``max``. When value is not specified - no compression is applied.
                'compression': 'normal',
                # Format of the Acronis backup archive. Available values: ``11``, ``12``, ``auto``.
                'format': 'auto',
                # If true, snapshots of multiple volumes will be taken simultaneously. Equals to false if value is not specified.
                'multi_volume_snapshotting_enabled': True,
                # If true, the file security settings will be preserved. Equals to false if value is not specified.
                'preserve_file_security_settings': True,
                # Configuration of retries on recoverable errors during the backup operations like reconnection to destination. No attempts to fix recoverable errors will be made if retry configuration is not set.
                'reattempts': {
                    # If true, enables retry on recoverable errors.
                    'enabled': True,
                    # An interval between retry attempts.
                    'interval': {
                        # A type of the interval. Available values are: ``seconds``, ``minutes``, ``hours``, ``days``.
                        'type': 'seconds',
                        # The amount of value specified in ``interval.type``.
                        'count': 30
                    },
                    # Max number of retry attempts. Operation will be considered as failed when max number of retry attempts is reached.
                    'max_attempts': 30
                },
                # If true, a user interaction will be avoided when possible. Equals to false if value is not specified.
                'silent_mode_enabled': True,
                # Determines the size to split backups on. Splitting is not performed if value is not specified.
                'splitting': {
                    # The size of split backup file in bytes.
                    'size': 9223372036854775807
                },
                # Configuration of retries on errors during the creation of the virtual machine snapshot. No attempts to fix recoverable errors will be made if retry configuration is not set.
                'vm_snapshot_reattempts': {
                    # If true, enables retry on errors.
                    'enabled': True,
                    # Configuration of the interval between retry attempts.
                    'interval': {
                        # A type of the interval. Available values are: ``seconds``, ``minutes``, ``hours``, ``days``.
                        'type': 'minutes',
                        # The amount of value specified in ``interval.type``.
                        'count': 5
                    },
                    # Max number of retry attempts. Operation will be considered as failed when max number of retry attempts is reached.
                    'max_attempts': 3
                },
                # Settings for the Volume Shadow Copy Service (VSS) provider. If not set, no VSS provider is used.
                'vss': {
                    # If true, the VSS will be enabled.
                    'enabled': True,
                    # A type of VSS provider to use in backup. Only ``native`` and ``target_system_defined`` options are available.
                    'provider': 'target_system_defined'
                },
                # The archive properties.
                'archive': {
                    # The name of the generated archive. The name may use the following variables: ``[Machine Name]``, ``[Plan ID]``, ``[Plan Name]``, ``[Unique ID]``, ``[Virtualization Server Type]``.
                    'name': '[Machine Name]-[Plan ID]-[Unique ID]A'
                },
                # Time windows for performance limitations of backup and storage maintenance operations.
                "performance_window": {
                    "enabled": True,
                    # A tuple of 3 presets
                    "presets": [
                        {
                            # CPU priority - 'idle', 'low', 'normal', 'high', 'realtime'
                            "cpu_priority": "normal",
                            "disk_limit": {
                                # Value in specified units
                                "value": 50,
                                # Units. 'percent' - percentage, 'speed' - speed in kilobytes
                                "type": "percent"
                            },
                            # ID of preset. 'high' - green, 'low' - blue, 'cancel' - gray.
                            "id": "high",
                            "network_limit": {
                                # Value in specified units
                                "value": 50,
                                # Units. 'percent' - percentage, 'speed' - speed in kilobytes per second
                                "type": "percent"
                            },
                            # List of timetable objects
                            "timetable": [
                                {
                                    # Time from which the preset applies
                                    "time_from": {
                                        "hour": 0,
                                        "minute": 0
                                    },
                                    # Time until the preset applies
                                    "time_to": {
                                        "hour": 23,
                                        "minute": 59,
                                        "second": 59
                                    },
                                    # Days of week in three-letter format
                                    "days_of_week": [
                                        "sun",
                                        "mon",
                                        "tue",
                                        "wed",
                                        "thu",
                                        "fri",
                                        "sat"
                                    ]
                                }
                            ]
                        },
                        {
                            "cpu_priority": "high",
                            "disk_limit": {
                                "value": 25,
                                "type": "percent"
                            },
                            "id": "low", # Blue preset
                            "network_limit": {
                                "value": 25,
                                "type": "percent"
                            },
                            "timetable": [
                                {
                                    "time_from": {
                                        "hour": 8,
                                        "minute": 0
                                    },
                                    "time_to": {
                                        "hour": 8,
                                        "minute": 59,
                                        "second": 59
                                    },
                                    "days_of_week": [
                                        "sun",
                                        "fri"
                                    ]
                                }
                            ]
                        },
                        {
                            "id": "cancel", # Gray (inactive) preset
                            "network_limit": {
                                "value": 100,
                                "type": "percent"
                            },
                            "disk_limit": {
                                "value": 100,
                                "type": "percent"
                            },
                            "timetable": [
                                {
                                    "time_from": {
                                        "hour": 8,
                                        "minute": 0
                                    },
                                    "time_to": {
                                        "hour": 15,
                                        "minute": 59,
                                        "second": 59
                                    },
                                    "days_of_week": [
                                        "mon"
                                    ]
                                }
                            ]
                        }
                    ],
                },
                # Configuration of backup retention rules.
                'retention': {
                    # A list of retention rules.
                    'rules': [
                        {
                            # A list of backup sets where rules are effective.
                            'backup_set': [
                                'daily'
                            ],
                            # Configuration of the duration to keep backups in archive created by the policy.
                            'max_age': {
                                # A type of the duration. Available values are: ``seconds``, ``minutes``, ``hours``, ``days``.
                                'type': 'days',
                                # The amount of value specified in ``max_age.type``.
                                'count': 7
                            }
                        },
                        {
                            'backup_set': [
                                'weekly'
                            ],
                            'max_age': {
                                'type': 'weeks',
                                'count': 4
                            }
                        },
                        {
                            'backup_set': [
                                'monthly'
                            ],
                            'max_age': {
                                'type': 'months',
                                'count': 6
                            }
                        }
                    ],
                    # If true, retention rules will be applied after backup is finished.
                    'after_backup': True
                },
                # Storage location of the archives.
                'vault': {
                    # Type of storage location. Available values: ``local_folder``, ``network_share``, ``ftp``, ``sftp``, ``cd``, ``tape``, ``storage_node``, ``asz``, ``removable``, ``cloud``, ``nfs_share``, ``esx``, ``astorage2``, ``script``.
                    'type': 'cloud',
                    # If true, the vault will be accessed using the policy credentials.
                    'use_policy_credentials': True
                },
                # Configuration of policy-related alerts.
                'alerts': {
                    # If true, the alerts will be enabled.
                    'enabled': False,
                    # Number of days that will trigger the alert about the passed number of days without a backup.
                    'max_days_without_backup': 5
                },
                # Configuration of the backup schedule.
                'scheduling': {
                    # A list of schedules with backup sets that compose the whole scheme.
                    'backup_sets': [
                        {
                            'type': 'auto',
                            'schedule': {
                                'alarms': {
                                    'time': {
                                        'weekdays': [
                                            'mon',
                                            'tue',
                                            'wed',
                                            'thu',
                                            'fri'
                                        ],
                                        'repeat_at': [
                                            {
                                                'hour': 21,
                                                'minute': 0
                                            }
                                        ]
                                    }
                                },
                                'conditions': {},
                                'prevent_sleep': True,
                                'type': 'weekly'
                            }
                        }
                    ],
                    # If true, the backup schedule will be enabled.
                    'enabled': True,
                    # Max number of backup processes allowed to run in parallel. Unlimited if not set.
                    'max_parallel_backups': 2,
                    'rand_max_delay': {  # Configuration of the random delay between the execution of parallel tasks.
                        # A type of the duration. Available values are: ``seconds``, ``minutes``, ``hours``, ``days``.
                        'type': 'minutes',
                        # The amount of value specified in ``rand_max_delay.type``.
                        'count': 30
                    },
                    # A backup scheme. Available values: ``simple``, ``always_full``, ``always_incremental``, ``weekly_incremental``, ``weekly_full_daily_incremental``, ``custom``, ``cdp``.
                    'scheme': 'always_incremental',
                    "task_failure": {
                        "enabled": True,
                        "interval": {
                            "type": "hours", # Time units - hours, minutes, seconds
                            "count": 1 # Number of time units
                        },
                        "max_attempts": 12 # Number of attempts between task restarts
                    },
                    # A day of week to start weekly backups in 3-letter abbreviation format.
                    'weekly_backup_day': 'mon'
                },
                # A configuration of Changed Block Tracking (CBT). Available values: ``use_if_enabled``, ``enable_and_use``, ``do_not_use``.
                'cbt': 'enable_and_use',
                # If true, determines whether a file has changed by the file size and timestamp. Otherwise, the entire file contents are compared to those stored in the backup.
                'fast_backup_enabled': True,
                # If true, a quiesced snapshot of the virtual machine will be taken.
                'quiesce_snapshotting_enabled': True
            }
        },
        # Put other policy objects here.
    ]

    #Merge the list of protection policy objects into the policy key of the plan_data object:
    plan_data['subject']['policy'] += policies

    #Convert the plan_data object to a JSON text:
    plan_data = json.dumps(plan_data, indent=4)

    base_url = f'{datacenter_url}/api'
    #Send a POST request with the JSON text to the /policy_management/v4/policies endpoint:
    response = requests.post(
        f'{base_url}/policy_management/v4/policies',
        headers={'Content-Type': 'application/json', **auth2},
        data=plan_data,
    )

    status = response.status_code
    #check the response code(200 means success)
    print("status code: ",status)
        
    message = []
    template = loader.get_template('index.html')
    if(status == 200):
        message.append("Protection plan created successfully.")
    else:
        message.append("Protection plan creation failed.")
    context = {
    'message': message,
    }
    return HttpResponse(template.render(context, request))

#Retrieve customer alerts
def retrieveAlerts(request):
    if (request.method == "POST"):
        customer_tenant_id = request.POST['customerID']
    
    auth2 = scopedAccessToken(customer_tenant_id)

    #set base url for retrieving alerts
    alerts_url = f'{datacenter_url}/api'

    #send get request to endpoint
    response = requests.get(f'{alerts_url}/alert_manager/v1/alerts', headers=auth2)
    pprint.pprint(response.json())
    #check status of response
    print("Alerts status: ",response.status_code)

    template = loader.get_template('reportsAlerts.html')
    context = {
    
    }
    return HttpResponse(template.render(context, request))
