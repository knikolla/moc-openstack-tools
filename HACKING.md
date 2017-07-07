### Setting up a development environment

Use either DevStack (Ubuntu) or PackStack all-in-one (CentOS) to deploy a
test OpenStack deployment in a virtual machine. 

Except for the [Ubuntu](#ubuntu) section, these instructions assume you are using CentOS, so you might need to modify them if you are using Ubuntu or something else.

The URLs to the parent CCI-MOC repos of both moc-openstack-tools and setpass are given below, but if you are actively developing on either, you will want to substitute the URL of your fork.

#### CentOS
Use a virtual machine with at least 8GB of RAM.  Below, specify the release of OpenStack you wish to test against - the example installs Newton. 

    $ sudo yum install -y centos-release-openstack-newton  
    $ sudo yum install -y openstack-packstack
    $ sudo packstack --allinone

The installation can take a while (20+ minutes), so go do something else and come back in a bit. When it's done you'll see a message like this: 

    **** Installation completed successfully ******
    
    Additional information:
     * A new answerfile was created in: /root/packstack-answers-20170601-190213.txt
     * Time synchronization installation was skipped. Please note that unsynchronized time on server instances might be problem for some OpenStack components.
     * File /root/keystonerc_admin has been created on OpenStack client host 10.11.12.13. To use the command line tools you need to source the file.
     * To access the OpenStack Dashboard browse to http://10.11.12.13/dashboard .
    Please, find your login credentials stored in the keystonerc_admin in your home directory.
     * The installation log file is available at: /var/tmp/packstack/20170601-190212-ESb_Vc/openstack-setup.log
     * The generated manifests are available at: /var/tmp/packstack/20170601-190212-ESb_Vc/manifests
    
Credentials for the admin user and the demo user will be in `/root/keystonerc_admin` and `/root/keystonrc_demo`.

#### Ubuntu
In the git clone command, specify the branch corresponding to the release of OpenStack you want.  In the example, we install Newton.

    $ sudo su -
    $ sudo useradd -s /bin/bash -d /opt/stack -m stack
    $ echo "stack ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers
    $ sudo apt-get install git -y
    $ sudo su - stack
    $ git clone https://git.openstack.org/openstack-dev/devstack --branch stable/newton
    $ cd devstack

Create the following `local.conf` file inside the devstack folder:

    [[local|localrc]]
    FLOATING_RANGE=192.168.1.224/27
    FIXED_RANGE=10.11.12.0/24
    FIXED_NETWORK_SIZE=256
    FLAT_INTERFACE=eth0
    ADMIN_PASSWORD=stacksecret
    DATABASE_PASSWORD=stacksecret
    RABBIT_PASSWORD=stacksecret
    SERVICE_PASSWORD=stacksecret

Make sure the `FLAT_INTERFACE` matches your VM's interface name (check your interfaces names with the command `ip link`)

Run devstack:
    $ ./stack.sh


#### Install required packages

    $ sudo yum install python-virtualenv

#### Set up Setpass

###### Deploy Setpass in a virtual environment
    $ virtulenv .setpass
    $ source .setpass/bin/activate
    (.setpass)$ git clone https://CCI-MOC/setpass 
    (.setpass)$ cd setpass 
    (.setpass)$ pip install -r requirements.txt
    (.setpass)$ python setup.py install 
    (.setpass)$ python -m setpass.api

Note that this test setup will run in the foreground and log to the console.

### Create a development Google API service user

You will need a Google API service user to use for development purposes.  You can use the same one across multiple development environments, but you should NOT use the service user that has access to the production sheet for development, or vice versa. 

Follow the instructions in this repo's README to set up a service user and download the API key.

### Set up a development spreadsheet

For development, create Google Sheets to stand in for both the Access and Quota request sheets.  Give your service account user write access to the sheet.

### Set up the Helpdesk VM

It's best to use a second VM for the helpdesk even in development environments.  This makes it easier to point it at different OpenStack installations if you need to test code against multiple releases, and avoids the potential for version conflicts in required Python packages (notably, oauth2).  

    $ sudo useradd moc-tools -d /usr/local/src/moc-tools
    $ cd ~moc-tools
    $ git clone https://CCI-MOC/moc-openstack-tools helpdesk
    $ cd helpdesk
    $ sudo pip install -r requirements.txt
    $ sudo chown -R moc-tools:moc-tools ~moc-tools/*
    $ sudo su - moc-tools
    $ cd helpdesk
    $ cp example_settings.ini settings.ini

If you do install everything in one VM, use a virtual environment.  There are some bugs in the openstack client installers that make this tricky.  It helps to install the clients outside the virtual environment and comment them out in requirements.txt.  Then run `pip install -U setuptools` inside the virtual environment before `pip install -r requirements.txt`. 

Fill out the settings.ini file with the OpenStack endpoints and spreadsheet keys/IDs as described in the README.

Place the API key for your service user in the ~moc-tools/helpdesk folder.

###### Set up a Postfix mail server

In theory any mail server should work, but this code is only tested against Postfix.  Other mail servers may require additional configuration to work.

    $ sudo yum install postfix -y
    
See the README for instructions on enabling TLS in Postfix.

### Development tips and tricks

##### Turning off emails
During development, you may not want to skip sending emails while testing your changes.  Comment out the line where the message is sent, which should look something like this:
     email_msg.send()
If it's inside a try block, replace it with something like `print "No email."`  Or, if it would be useful to see the message body, use `print msg.body` to print the email body to the screen.
