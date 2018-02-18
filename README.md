# Ruairi's Cheat Sheet Application
A Python Web-Application for displaying and editing items from a catalog.

## Description
This is Project 3 for the Udacity Full Stack Nanodegree. I was required to create a Web-Application that would allow users to view items in a catalog, as well as logging in via OAuth, create and edit new items in the database, and use the applications API to retrieve data.

## Primary Features
- [x] Dynamically generated from a Python data structure.
- [x] Google+ and Facebook oAuth
- [x] CRUD operations once user is logged in
- [x] JSON API Endpoints.
- [x] Code is ready for personal review and neatly formatted.
- [x] Page is error free.
- [x] Comments effectively explain longer code procedures.
- [x] A `README` file includes details of all the steps required to successfully run the application.

## Extras
- [x] CRUD functionality for image handling
- [x] CSRF protection on CRUD operations

## Requirements

### Git
If you don't already have Git installed, download Git from [here](git-scm.com). Install the version for your operating system.


### Installing the Vagrant VM

Here are the tools you'll need to install to get it running:

#### VirtualBox
VirtualBox is the software that actually runs the VM. You can download it from [here](virtualbox.org). Install the platform package for your operating system. You do not need the extension pack or the SDK. You do not need to launch VirtualBox after installing it.

Ubuntu 14.04 Note: If you are running Ubuntu 14.04, install VirtualBox using the Ubuntu Software Center, not the virtualbox.org web site. Due to a reported bug, installing VirtualBox from the site may uninstall other software you need.

#### Vagrant
Vagrant is the software that configures the VM and lets you share files between your host computer and the VM's filesystem. You can download it from [vagrantup.com](vagrantup.com). Install the version for your operating system.

Windows Note: The Installer may ask you to grant network permissions to Vagrant or make a firewall exception. Be sure to allow this.

#### Fetch the Source Code and VM Configuration
Windows: Use the Git Bash program (installed with Git) to get a Unix-style terminal.
Other systems: Use your favorite terminal program.

From the terminal, run:
```
$ git clone https://github.com/grocer-of-despair/UdacityCatalogProject.git UdacityCatalogProject
```

#### Run the virtual machine!
Using the terminal, change directory to CheatSheetCatalog:
```
 $ cd UdacityCatalogProject
 ```
 Then type vagrant up to launch your virtual machine.
 ```
 $ vagrant up
 ```
 Now that you have Vagrant up and running type you need to log into your VM.
 ```
 $ vagrant password_hash
 ```
Change to the /vagrant directory. This will take you to the shared folder between your virtual machine and host machine.
```
$ cd /vagrant
```
#### Install Redis
Redis is used for Rate-Limiting within the application:

```
$ pip install redis
```


## How to run this project
 * Change to the project directory
 ```
 $ cd /CheatSheetApp
 ```
 * Run `application.py` from the project directory:
 ```
 $ python entertainment_centre.py
 ```
 * Enjoy my Cheat Sheet Application

## License
The contents of this repository are covered under the [GNU GENERAL PUBLIC LICENSE](LICENSE.txt).
