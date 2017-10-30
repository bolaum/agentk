# agentk

`agentk` implements the [ssh-agent protocol](https://tools.ietf.org/html/draft-miller-ssh-agent-00) and allows access to keys within a kNET-HSM. It uses the `kkmip` library provided by [Kryptus](www.kryptus.com) as a backend for communication with kNET-HSM and supports a subset of the functionalities provided by OpenSSH's `ssh-agent`, as listed below.

## Features

- Suports all clients compatible with `ssh-agent`
- Key management with `ssh-add`
- Straight-forward operation and configuration

## Dependencies

All dependencies are installed during setup with the exception of `kkmip` library, that should be acquired separately (please contact folks at [Kryptus](http://resources.kryptus.com/hsm)).

## Usage

Checkout the repository:

```bash
git clone https://github.com/bolaum/agentk.git
cd agentk
```

And install (virtualenv recommended):

```bash
virtualenv venv
source venv/bin/activate
pip install -e .
```

Create a config file:

```bash
cp etc/config.example.yml ~/.agentk.yml
vim ~/.agentk.yml
```

And edit it with appropriate values.

Run the application (use `-v` for verbose output, `-d` for debug and `-h` for other options):

```bash
agentk 
```

I should output something like this:

```bash
SSH_AUTH_SOCK=/tmp/agentk.sock; export SSH_AUTH_SOCK;
```

Now, in a new terminal, paste the string printed by the app.

#### Adding a private key

```bash
ssh-add /path/to/private_key
```

The private key will be added to kNET-HSM.

#### Listing all public keys

```bash
ssh-add -L
```

#### Removing a key

```bash
ssh-add -d /path/to/public_or_private_key
```

#### Removing all keys

**WARNING**: This will remove all RSA key pairs inside the HSM!

```bash
ssh-add -D
```

#### Using `ssh`

Listed keys can be added to your `~/.ssh/authorized_keys` to allow ssh connection without a password.

```bash
ssh-add -L >> ~/.ssh/authorized_keys
```

Then you should be able to connect to the local ssh server:

```bash
ssh localhost
```

## TODO

- Daemonize application
- Support for DSA and ECDSA keys
- Add key password support
- Add locking and unlocking support
- Add option to disable removal of all keys
- Windows support
- Fix tests
- Test on other unix like systems (FreeBSD, OpenBSD, etc.)

## Why?

Well, mainly for fun and profit. I supposed tens of millions of people use `ssh` everyday, so it's a good thing that kNET-HSM is now integrated with almost every client ever written for unix like systems =D 


