# IT Platform Development Assistant

Quickly setup a Development Environment for IT Platforms. You just need to provide the underlying infrastructure.

Major Features Include:
  - CLI tool to bootstrap the Development Envrionemnt
  - Virtualization Platform (Hypervisor)
    - [XCP-ng](https://xcp-ng.org/docs/)
  - WebUI to control the Virt. Platform
    - [Xen Orchestra](https://xen-orchestra.com/docs/)
  - Terraform Configuration Template
  - Default ISO datastore

## Quick Start

In general the following steps will get you to a point where you can start creating VMs.

  - Clone this project to your dev environment
  - Install XCP-ng on a device & setup SSH Access
  - Specify download links to OS ISOs, IMGs, tarballs, etc...
  - Run the `setup.sh` script

### Clone this project

```bash
git clone "${PROJECT_URL}"
```

### Install & Setup SSH Access to XCP-NG

> 🔴 Currently only 1 remote host is supported. Multi-node support is on the roadmap

Please follow the [XCP-ng Installation Documentation](https://xcp-ng.org/docs/install.html) to get XCP-ng setup on your remote device. An Intel NUC is a good option to get started with.

While XCP-ng is installing create a new SSH Key

```bash
ssh-keygen -t ed25519 -f ~/.ssh/xcp-ng -C "user@domain.tld"
chmod 400 ~/.ssh/xcp-ng ~/.ssh/xcp-ng.pub
```

Now add the XCP-ng node to your ssh config. Make sure to match the `Hostname` & `User` values to your specific environment.

```
Host xcp-ng
    Hostname 192.168.0.187
    IdentityFile ~/.ssh/xcp-ng
    User root
```

Once installation of XCP-ng is complete; on the XCP-ng Node:
  - Enable `PubkeyAuthentication` Authentication (on by default)
  - (optionally) disable `PasswordAuthentication`
  - Add the newly generated public key `~/.ssh/xcp-ng.pub` to the `~/.ssh/authorized_keys` file.

Verify SSH connection from your dev station to the XCP-ng Node

```bash
ssh xcp-ng echo hello
```

### Specify OS Images

Create a file named `os-imgs.txt` under the [os-imgs folder](./docker/os-imgs). For every remote image you want to include provide it HTTP Download link on a newline.

For your convenience a default file already exists & includes images for Ubuntu 20.04 LTS & Alpine 3.

### Run `setup.sh`

> 🔵 Currently this part is most error prone since it's dependent on your environment. Enabling debug logging will help with troubleshooting.

Add executable bits to `setup.sh` which is found at the root of this project

```bash
chmod +x ./setup.sh
```

The script uses Docker to build & host the Xen Orhcestra & ISO img repository. It is assumed that your development environment is your local computer & is the x86_64 architecture. If this is not the case then you can specify the ssh config name of a remote host that is x86_64 & runs docker. You can alternatively setup the local Docker Client's Context seperate from this script.

For docker configuration flags & a full list of options run the script with the help command

```bash
./setup.sh --help
```

A few environment variables must be set before running the script.

  - XCP_NODE_USER
    - The Login User of the XCP-ng node. Usually root.
  - XCP_NODE_PASSWORD
    - The Login Users's Password you set during install of XCP-ng.
  - XCP_NODE_ADDR
    - The FQDN or IP address of the XCP-ng Node.
  - XOA_ADMIN_EMAIL
    - Email address you want to set to be the default admin for Xen Orchestra.
  - XOA_ADMIN_PASSWORD
    - The Default Admin's Password for Xen Orchestra.

A few other software dependencies are required as well.

  - jq
  - ssh
  - git
  - docker
  - curl
  - terraform

In the event these two sets of prereqs are not met the script will error out before conducting any work.

Now run the script

```bash
./setup.sh
```

Briefly, the setup script conducts a few tasks:

  - Builds & Runs supporting services (ISO Share & Xen Orchestra) on the Docker Daemon's host
  - Configures Xen Orchestra (XO) to the point you can manually deploy VMs
  - Generates a Terraform Config Template with necessary values injected.

Assuming execution doesn't error out it should run through all the necessary setup steps. It will then prompt for the user to exit the script. You can verify everything deployed as necessary or look at any of the temporary files.

You now have a functional dev environment for IT platform development.

In the event you need to redeploy the services or change your development environment you can run `setup.sh` again. Changes in the XO will be lost (ex. users) but changes pushed to the XCP-ng node (ex. VMs) are not touched.