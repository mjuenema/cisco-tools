# cisco-tools
Various scripts for working with Cisco network devices

* **ciscoconfdict** converts a Cisco IOS configuration into nested Python dictionaries.
* **ciscoacldict** parses the output of the ``show access-lists`` command into nested Python dictionaries.
* **ciscoconfexit** inserts ``exit`` statements into a Cisco configuration so one can copy-and-paste it.

## ciscoconfdict

**ciscoconfdict** converts a Cisco IOS configuration into nested Python dictionaries.

>> Description goes here.

## ciscoaclparse

* **ciscoacldict** parses the output of the ``show access-lists`` command into list of Python dictionaries.

>> Description goes here.

## ciscoconfexit

**ciscoconfexit** inserts ``exit`` statements into a Cisco configuration so one can copy-and-paste it.

Example:

```
! input.cfg
interface FastEthernet 1/1
  description Internet
  ip address 192.168.1.1 255.255.255.0
!
interface FastEthernet 1/1
  description LAN
  ip address 172.16.1.1 255.255.255.0
!
```

Running **ciscoconfexit** will insert ``exit`` statements where required.

```
$ ciscoconfexit input.cfg
! output.cfg
interface FastEthernet 1/1
  description Internet
  ip address 192.168.1.1 255.255.255.0
  exit
!
interface FastEthernet 1/1
  description LAN
  ip address 172.16.1.1 255.255.255.0
  exit
!
```
